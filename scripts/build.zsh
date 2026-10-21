#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
if [[ -e .swiftpm ]]; then
  print -u2 'Remove .swiftpm before building: SwiftPM reads its configuration, which Git does not track.'
  exit 1
fi
swift build -c release -Xswiftc -warnings-as-errors
binary="$(swift build -c release --show-bin-path)/pi-credentials-helper"
identity=${PI_CREDENTIALS_SIGNING_IDENTITY:-}
if [[ -z "$identity" ]]; then
  identity=$(/usr/bin/security find-identity -p codesigning -v | /usr/bin/awk '/Developer ID Application/ {print $2; exit}')
fi
if [[ -n "$identity" ]]; then
  /usr/bin/codesign -f -s "$identity" -i dev.pi-credentials.helper -o runtime "$binary"
else
  print -u2 'No Developer ID identity: using ad-hoc signing. Keychain access resets after each rebuild.'
  /usr/bin/codesign -f -s - -i dev.pi-credentials.helper "$binary"
fi
/bin/mkdir -p bin
/usr/bin/install -S -m 755 "$binary" bin/pi-credentials-helper
print "Built bin/pi-credentials-helper"
