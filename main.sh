#!/usr/bin/env bash
set -euo pipefail

# Color codes
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
NC="\033[0m"

# Batch size for kxss
BATCH_SIZE=40

# Headers variable
HEADERS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -H|--header)
      HEADERS="$2"
      shift 2
      ;;
    *)
      DOMAIN="$1"
      shift
      ;;
  esac
done

# Check for domain argument
if [[ -z "${DOMAIN:-}" ]]; then
  echo -e "${RED}Usage: $0 [-H 'header'] <domain.com>${NC}"
  echo -e "${CYAN}Example: $0 -H 'Cookie: session=abc123' example.com${NC}"
  exit 1
fi

# Prepare working directories
WORKDIR="./${DOMAIN}_recon"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Now that we're inside WORKDIR, set the scan directory
SCAN_DIR="./kxss_scan"
mkdir -p "$SCAN_DIR"

# Extensions to filter out from passive results
EXTS='(json|js|css|jpg|jpeg|png|svg|gif|exe|mp4|flv|pdf|doc|webm|wmv|webp|mov|mp3|avi|zip)($|\?)'

#
# 1) Passive enumeration: waybackurls, gau ONLY
#
run_nice_passive_in_bash() {
  local domain="$1"
  local tmp_all="all-urls.tmp"
  : > "$tmp_all"

  # root URL
  echo "https://${domain}/" | tee -a "$tmp_all"

  # waybackurls
  echo "$domain" \
    | waybackurls \
    | tee waybackurls.txt >> "$tmp_all"

  # gau with subs
  gau "$domain" --threads 5 --subs \
    | tee gau.txt >> "$tmp_all"

  # finalize unique URLs
  sort -u "$tmp_all" > all-urls.txt
  rm -f "$tmp_all"

  # emit for filtering
  cat all-urls.txt
}

echo -e "${CYAN}[+] Collecting passive URLs (waybackurls + gau)…${NC}"
run_nice_passive_in_bash "$DOMAIN" \
  | grep -iEv "\.${EXTS}" \
  | awk 'NF' \
  | anew "${DOMAIN}.passive"
echo -e "${GREEN}[+] Passive URLs saved in ${DOMAIN}.passive${NC}"

#
# 2) Extract unique parameter keys with unfurl
#
echo -e "${CYAN}[*] Extracting unique parameter keys…${NC}"
if command -v anew &>/dev/null; then
  unfurl --unique keys < "${DOMAIN}.passive" \
    | anew unfurl-params.txt \
    | sort -u > unfurl-params.tmp
  mv unfurl-params.tmp unfurl-params.txt
else
  unfurl --unique keys < "${DOMAIN}.passive" \
    | sort -u > unfurl-params.txt
fi
UNFURLPARAMS_COUNT=$(wc -l < unfurl-params.txt)
echo -e "${GREEN}[+] $UNFURLPARAMS_COUNT unique param(s) extracted${NC}"

#
# 3) Chunk dynamic URLs and run httpx
#
echo -e "${CYAN}[*] Running httpx in chunks…${NC}"
DYNAMIC_PASSIVE=$(mktemp)
grep '?' "${DOMAIN}.passive" | sort -u > "$DYNAMIC_PASSIVE"
split -l 150 "$DYNAMIC_PASSIVE" chunk_
ls chunk_* | xargs -P 8 -I{} bash -c \
  'httpx -silent -threads 100 -timeout 2 -retries 2 < "{}" > "{}.httpx"' || true

for f in chunk_*.httpx; do
  [[ -f "$f" ]] && grep '?' "$f"
done | anew dynamic-httpx.txt

for f in chunk_*.httpx; do
  [[ -f "$f" ]] && cat "$f"
done | anew httpx.txt

rm -f chunk_* chunk_*.httpx "$DYNAMIC_PASSIVE"
echo -e "${GREEN}[+] httpx: $(wc -l < httpx.txt) live, $(wc -l < dynamic-httpx.txt) dynamic live${NC}"

#
# 4) x8 brute-force reflections (parallel) with optional headers
#
echo -e "${CYAN}[*] Running x8…${NC}"
X8_OUT="${SCAN_DIR}/x8-brute.txt"
X8_REFLECTED="${SCAN_DIR}/x8-brute-reflected.txt"
mkdir -p "${SCAN_DIR}/x8_temp"
: > "$X8_OUT"

if command -v x8 &>/dev/null; then
  set +e
  
  # Build x8 command with optional headers
  X8_CMD='x8 -u "{}" -w "'"$PWD/unfurl-params.txt"'" -X GET POST'
  if [[ -n "$HEADERS" ]]; then
    X8_CMD+=' -H "'"$HEADERS"'"'
    echo -e "${CYAN}[*] Using headers: $HEADERS${NC}"
  fi
  
  cat dynamic-httpx.txt \
    | xargs -P 8 -I{} bash -c \
        "$X8_CMD"' > "'"${SCAN_DIR}/x8_temp/$(echo {} | md5sum | cut -d" " -f1).txt"'"' \
        || true
  cat "${SCAN_DIR}/x8_temp"/*.txt > "$X8_OUT" 2>/dev/null
  grep -Ei 'reflects:|change reflect' "$X8_OUT" \
    | sort -u > "$X8_REFLECTED"
  rm -rf "${SCAN_DIR}/x8_temp"
else
  echo -e "${RED}[!] x8 not found, skipping...${NC}"
  touch "$X8_OUT" "$X8_REFLECTED"
fi
echo -e "${GREEN}[+] x8 reflections saved in $X8_REFLECTED${NC}"

#
# 5) Generate URLs for kxss - individual parameters
#
echo -e "${CYAN}[*] Preparing kxss URLs (individual parameters)…${NC}"

# Check if we have parameters and URLs
if [[ ! -f "unfurl-params.txt" ]] || [[ ! -s "unfurl-params.txt" ]]; then
  echo -e "${RED}[!] No parameters found for kxss scanning${NC}"
  touch "${SCAN_DIR}/kxss_urls.txt"
else
  mapfile -t params < <(sort -u unfurl-params.txt)

  if [[ ! -f "dynamic-httpx.txt" ]] || [[ ! -s "dynamic-httpx.txt" ]]; then
    echo -e "${RED}[!] No dynamic URLs found for kxss scanning${NC}"
    touch "${SCAN_DIR}/kxss_urls.txt"
  else
    mapfile -t urls < <(sort -u dynamic-httpx.txt)
    url_param_log="${SCAN_DIR}/urls_with_params.log"
    : > "$url_param_log"

    # Function to generate single parameter URL
    gen_single_param_url() {
      local base="$1"
      local param="$2"

      # Remove existing parameter if it exists
      if [[ "$base" == *"?${param}="* ]]; then
        # Parameter already exists, replace its value
        echo "$base" | sed "s/\([\?&]${param}=\)[^&]*/\1KXSS/"
      elif [[ "$base" == *\?* ]]; then
        # URL has query string, add parameter
        echo "${base}&${param}=KXSS"
      else
        # No query string, add first parameter
        echo "${base}?${param}=KXSS"
      fi
    }

    # Always include healthcheck payload first
    echo "https://1.bigdav.ir/test.php?test=KXSS" >> "$url_param_log"

    # DEBUG: Show what we're working with
    echo -e "${CYAN}[*] DEBUG: Found ${#urls[@]} URLs and ${#params[@]} parameters${NC}"
    echo -e "${CYAN}[*] First 3 URLs:${NC}"
    printf '%s
' "${urls[@]:0:3}"
    echo -e "${CYAN}[*] First 5 parameters:${NC}"
    printf '%s
' "${params[@]:0:5}"

    # Generate each parameter separately for each URL
    count=0
    for u in "${urls[@]}"; do
      for p in "${params[@]}"; do
        gen_single_param_url "$u" "$p" >> "$url_param_log"
        ((count++))
        if (( count % 100 == 0 )); then
          echo -e "${CYAN}[*] Generated $count URLs so far...${NC}"
        fi
      done
    done

    # Remove duplicates and save
    sort -u "$url_param_log" > "${SCAN_DIR}/kxss_urls.txt"

    echo -e "${GREEN}[+] Generated $(wc -l < "${SCAN_DIR}/kxss_urls.txt") unique URLs for kxss scanning${NC}"
    echo -e "${CYAN}[*] URLs: ${#urls[@]}, Params: ${#params[@]}, Total combinations: $((${#urls[@]} * ${#params[@]}))${NC}"

    # Show first and last few URLs for verification
    echo -e "${CYAN}[*] First 5 generated URLs:${NC}"
    head -5 "${SCAN_DIR}/kxss_urls.txt"
    echo -e "${CYAN}[*] Last 5 generated URLs:${NC}"
    tail -5 "${SCAN_DIR}/kxss_urls.txt"
  fi
fi

#
# 6) Run kxss with correct output parsing
#
echo -e "${CYAN}[*] Running kxss in parallel…${NC}"

if command -v kxss &>/dev/null && [[ -s "${SCAN_DIR}/kxss_urls.txt" ]]; then
  # Create temp directory for parallel processing
  mkdir -p "${SCAN_DIR}/kxss_temp"

  # Split URLs into chunks for parallel processing
  CHUNK_SIZE=100
  TOTAL_URLS=$(wc -l < "${SCAN_DIR}/kxss_urls.txt")

  # Split the URLs file into chunks
  split -l "$CHUNK_SIZE" "${SCAN_DIR}/kxss_urls.txt" "${SCAN_DIR}/kxss_temp/chunk_"

  echo -e "${CYAN}[*] Processing $TOTAL_URLS URLs in chunks of $CHUNK_SIZE (parallel)${NC}"

  set +e
  # Process each chunk in parallel
  ls "${SCAN_DIR}/kxss_temp/chunk_"* | xargs -P 6 -I{} bash -c '
    chunk_file="{}"
    chunk_name=$(basename "$chunk_file")
    output_file="'"${SCAN_DIR}/kxss_temp"'/${chunk_name}.out"
    log_file="'"${SCAN_DIR}/kxss_temp"'/${chunk_name}.log"

    echo "[$(date)] Starting kxss on chunk: $chunk_name" >> "'"${SCAN_DIR}/kxss_parallel.log"'"

    # Run kxss on this chunk
    if timeout 300 kxss < "$chunk_file" > "$output_file" 2> "$log_file"; then
      echo "[$(date)] Completed kxss on chunk: $chunk_name ($(wc -l < "$output_file") lines)" >> "'"${SCAN_DIR}/kxss_parallel.log"'"
    else
      echo "[$(date)] Failed/timeout kxss on chunk: $chunk_name" >> "'"${SCAN_DIR}/kxss_parallel.log"'"
    fi
  ' || true
  set -e

  # Wait for all processes to complete
  wait

  # Combine all outputs
  cat "${SCAN_DIR}/kxss_temp/chunk_"*.out > "${SCAN_DIR}/kxss-out.txt" 2>/dev/null || true
  cat "${SCAN_DIR}/kxss_temp/chunk_"*.log > "${SCAN_DIR}/kxss.log" 2>/dev/null || true

  # Parse kxss output correctly (single line format)
  # Format: URL: <url> Param: <param> Unfiltered: [<chars>]
  awk '
  /^URL: .* Param: .* Unfiltered: / {
    # Extract URL (between "URL: " and " Param:")
    url_start = index($0, "URL: ") + 5
    param_pos = index($0, " Param: ")
    url = substr($0, url_start, param_pos - url_start)

    # Extract Parameter (between "Param: " and " Unfiltered:")
    param_start = param_pos + 8
    unfilt_pos = index($0, " Unfiltered: ")
    param = substr($0, param_start, unfilt_pos - param_start)

    # Extract Unfiltered part (everything after "Unfiltered: ")
    unfilt_start = unfilt_pos + 13
    unfiltered = substr($0, unfilt_start)

    # Only print if unfiltered is not empty brackets
    if (unfiltered != "[]" && unfiltered != "" && url != "" && param != "") {
      print url " | " param " | Unfiltered: " unfiltered
    }
  }
  ' "${SCAN_DIR}/kxss-out.txt" > "${SCAN_DIR}/kxss-reflected-pairs.txt"

  # Clean up temp files
  rm -rf "${SCAN_DIR}/kxss_temp"

  REFLECTED_COUNT=$(wc -l < "${SCAN_DIR}/kxss-reflected-pairs.txt" 2>/dev/null || echo 0)
  echo -e "${GREEN}[+] kxss completed - Found $REFLECTED_COUNT reflections${NC}"

else
  echo -e "${RED}[!] kxss not found or no URLs to scan${NC}"
  touch "${SCAN_DIR}/kxss-out.txt" "${SCAN_DIR}/kxss-reflected-pairs.txt"
  echo "[!] kxss not found or no URLs" > "${SCAN_DIR}/kxss.log"
fi
echo -e "${GREEN}[+] kxss done${NC}"

#
# 7) Final summary
#
# helper to count lines or return zero
count_or_zero(){
  [[ -f "$1" ]] && wc -l < "$1" || echo 0
}

WAYBACK_COUNT=$(count_or_zero waybackurls.txt)
GAU_COUNT=$(count_or_zero gau.txt)
ALLURLS_COUNT=$(count_or_zero all-urls.txt)
STATIC_COUNT=$(grep -iv "?" all-urls.txt 2>/dev/null | sort -u | wc -l)
DYNAMIC_COUNT=$(count_or_zero dynamic-httpx.txt)
HTTPX_COUNT=$(count_or_zero httpx.txt)
UNFURLPARAMS_COUNT=$(count_or_zero unfurl-params.txt)
X8_COUNT=$(count_or_zero "${X8_OUT}")
KXSS_COUNT=$(count_or_zero "${SCAN_DIR}/kxss-out.txt")

echo -e "${GREEN}"
echo "============ Recon Summary for $DOMAIN ============"
printf "%-22s: %d
" "waybackurls"         "$WAYBACK_COUNT"
printf "%-22s: %d
" "gau"                  "$GAU_COUNT"
printf "%-22s: %d
" "All unique URLs"      "$ALLURLS_COUNT"
printf "%-22s: %d
" "Static URLs"          "$STATIC_COUNT"
printf "%-22s: %d
" "Dynamic URLs"         "$DYNAMIC_COUNT"
printf "%-22s: %d
" "Unique URL params"    "$UNFURLPARAMS_COUNT"
printf "%-22s: %d
" "httpx (alive URLs)"   "$HTTPX_COUNT"
printf "%-22s: %d
" "x8 reflections lines" "$X8_COUNT"
printf "%-22s: %d
" "kxss scan lines"      "$KXSS_COUNT"
[[ -n "$HEADERS" ]] && printf "%-22s: %s\n" "Headers used" "$HEADERS"
echo "=================================================="
echo -e "${NC}"

# show first 5 reflected pairs if any
if [[ -s "${SCAN_DIR}/kxss-reflected-pairs.txt" ]]; then
  echo -e "${CYAN}[*] First 5 reflected pairs:${NC}"
  head -5 "${SCAN_DIR}/kxss-reflected-pairs.txt"
else
  echo -e "${RED}[!] No reflected pairs found.${NC}"
fi

# health check
if grep -q "1.bigdav.ir" "${SCAN_DIR}/kxss-reflected-pairs.txt"; then
  echo -e "${GREEN}[✓] Health check passed.${NC}"
else
  echo -e "${RED}[✗] Health check failed.${NC}"
fi

echo -e "${CYAN}[*] All logs & artifacts are in: $WORKDIR${NC}"
exit 0
