#!/usr/bin/env bash
set -euo pipefail
# Downloads firmware only; never flashes or modifies a device.
OUT="${1:-firmware/iphone16,2}"
mkdir -p "$OUT"
fetch() {
 local build="$1" url="$2" sha="$3" file="$OUT/iPhone16,2_27.2_${build}_Restore.ipsw"
 if [[ ! -f "$file" ]]; then
   curl --fail --location --retry 5 --continue-at - --output "$file" "$url"
 fi
 printf '%s  %s\n' "$sha" "$file" | sha256sum --check -
}
fetch 24B5099f 'https://updates.cdn-apple.com/2026FallSeed/f8e317a0-cc63-4333-940f-e7418a409e59/iPhone16,2_27.2_24B5099f_Restore.ipsw' '9e20553ff1fb9eadc59eec6c5fdb9de0bd63f10a55a1e6707fe4579c789827e4'
fetch 24B5110a 'https://updates.cdn-apple.com/2026FallSeed/60788e91-0d08-498b-961b-ea6a8d03b334/iPhone16,2_27.2_24B5110a_Restore.ipsw' '01c7eb92ce296bffb813fec8fa6750ac6409710f51a7566f9424a6ca0f176fea'
printf '\nVerified both device-matched firmware images. Run:\n'
printf 'ipadecrypt firmware-diff "%s/iPhone16,2_27.2_24B5099f_Restore.ipsw" "%s/iPhone16,2_27.2_24B5110a_Restore.ipsw" --device iPhone16,2 --output comparison.txt\n' "$OUT" "$OUT"
