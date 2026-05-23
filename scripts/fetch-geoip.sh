#!/usr/bin/env bash
#
# Fetch the offline GeoIP/ASN databases pktscope's egress monitor uses.
#
# Sources (no account required, redistributable):
#   - Country: DB-IP IP-to-Country Lite  (CC-BY-4.0)
#   - ASN:     DB-IP IP-to-ASN Lite       (CC-BY-4.0)
#
# Both are MaxMind DB (.mmdb) format, read by the bundled `maxminddb` reader.
# This script is NEVER run at build or test time; pktscope stays fully offline
# at runtime. MaxMind GeoLite2 is intentionally NOT fetched (its EULA forbids
# redistribution and requires an account); point --geoip-*-db at one yourself
# if you have it.
#
# Usage: scripts/fetch-geoip.sh [dest-dir]
set -euo pipefail

month="$(date +%Y-%m)"
base="https://download.db-ip.com/free"

case "$(uname -s)" in
  Darwin) default_dir="$HOME/Library/Application Support/pktscope" ;;
  *)      default_dir="${XDG_DATA_HOME:-$HOME/.local/share}/pktscope" ;;
esac
dest="${1:-$default_dir}"
mkdir -p "$dest"

fetch() {
  local name="$1" out="$2"
  local url="$base/${name}-${month}.mmdb.gz"
  echo "Fetching $url"
  curl -fSL "$url" -o "$out.gz"
  gunzip -f "$out.gz"
  echo "  -> $out"
}

fetch "dbip-country-lite" "$dest/dbip-country.mmdb"
fetch "dbip-asn-lite" "$dest/dbip-asn.mmdb"

cat <<EOF

Done. Point pktscope at them:
  pktscope monitor run -i en0 \\
    --geoip-country-db "$dest/dbip-country.mmdb" \\
    --geoip-asn-db "$dest/dbip-asn.mmdb"

Data © db-ip.com, licensed under CC-BY-4.0.
EOF
