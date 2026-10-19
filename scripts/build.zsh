#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
swift build -c release -Xswiftc -warnings-as-errors
binary="$(swift build -c release --show-bin-path)/pi-credentials-helper"
identity=${PI_CREDENTIALS_SIGNING_IDENTITY:-}
if [[ -z "$identity" ]]; then
  identity=$(security find-identity -p codesigning -v | awk '/Developer ID Application/ {print $2; exit}')
fi
if [[ -n "$identity" ]]; then
  codesign -f -s "$identity" -i dev.pi-credentials.helper -o runtime "$binary"
else
  print -u2 'No Developer ID identity: using ad-hoc signing. Keychain access resets after each rebuild.'
  codesign -f -s - -i dev.pi-credentials.helper "$binary"
fi
mkdir -p bin
install -m 755 "$binary" bin/pi-credentials-helper
print "Built bin/pi-credentials-helper"
