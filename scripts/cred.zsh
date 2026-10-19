#!/bin/zsh
set -euo pipefail
helper="${PI_CREDENTIALS_HELPER:-${0:A:h:h}/bin/pi-credentials-helper}"
usage="usage: cred env create [--path .env.local] [--name credential]..."
if [[ "${1-}" != "env" || "${2-}" != "create" ]]; then
  print -u2 -r -- "$usage"
  exit 2
fi
shift 2
file=""
names=()
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--path" && $# -ge 2 ]]; then
    file="$2"
  elif [[ "$1" == "--name" && $# -ge 2 ]]; then
    names+=("$2")
  else
    print -u2 -r -- "$usage"
    exit 2
  fi
  shift 2
done
request=$(jq -cn --arg cwd "$PWD" --arg file "$file" '{cwd: $cwd} + (if $file == "" then {} else {path: $file} end) + {names: ($ARGS.positional | if length == 0 then null else . end)} | with_entries(select(.value != null))' --args -- "${names[@]}")
if ! result=$(print -r -- "$request" | "$helper" env); then
  message=$(print -r -- "$result" | jq -r '.error.message // "the helper failed"')
  print -u2 -r -- "cred: ${message:-the helper failed}"
  exit 1
fi
print -r -- "$result" | jq -r '"Wrote \(.path) with \(.variables | join(", "))." + (if (.unavailable | length) > 0 then " Could not read: \(.unavailable | join(", "))." else "" end) + (if (.skipped // [] | length) > 0 then " Skipped (under 8 characters): \(.skipped | join(", "))." else "" end)'
