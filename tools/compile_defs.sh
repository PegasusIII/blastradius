#!/bin/sh
# Compile incidents.json -> flat TSV the POSIX checker can read without jq.
# Usage: tools/compile_defs.sh IN.json OUT.tsv   (needs jq; dev-time only)
set -eu
in=$1; out=$2
jq -e '.schema=="blastradius-incidents/1" and (.version|test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and (.incidents|type=="array")' "$in" >/dev/null \
  || { echo "compile: schema check failed for $in" >&2; exit 2; }
jq -r '
  def t: gsub("[\t\n]";" ");
  "META\tversion\t\(.version)",
  "META\tpublished_at\t\(.published_at)",
  (.incidents[] as $i |
    "INC\t\($i.id)\t\($i.kind)\t\($i.severity_rank)\t\($i.published_at)\t\($i.title|t)",
    ($i.references[]? | "REF\t\($i.id)\t\(.)"),
    ($i.rules[] |
      if .type=="version_below" then "VB\t\($i.id)\t\(.component)\t\(.branch)\t\(.fixed_version)"
      elif .type=="eol_branch" then "EOL\t\($i.id)\t\(.component)\t\(.branch_max)"
      elif .type=="package_below" then "PKGMIN\t\($i.id)\t\(.pm)\t\(.package)\t\(.fixed_version)"
      elif .type=="cert_fingerprint_present" then (.stores|join(",")) as $s | (.certs[] | "FP\t\($i.id)\t\(.sha256|ascii_upcase|gsub(":";""))\t\($s)\t\(.label|t)")
      elif .type=="issuer_name_match" then (.issuer_cn[] | "ICN\t\($i.id)\t\(.|t)")
      elif .type=="distro_package_fixed" then (.fixes[] | "PKGFIX\t\($i.id)\t\(.os_id)\t\(.os_release)\t\(.package)\t\(.branch)\t\(.fixed_version)\t\(.advisory|t)")
      elif .type=="node_version_below" then "NODE\t\($i.id)\t\(.branch)\t\(.fixed_version)"
      else error("unknown rule type \(.type) in \($i.id)") end),
    ($i.remediation | to_entries[] | .key as $k | .value[] | "REM\t\($i.id)\t\($k)\t\(.|t)")
  )' "$in" > "$out"
echo "compiled $(grep -c '^INC' "$out") incidents -> $out"
