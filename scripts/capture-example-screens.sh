#!/usr/bin/env bash
# Captures the README screenshots of the SecurityLab example app on an iPhone simulator.
#
# The script builds and installs the app, opens each screen with `-screen <case> -demo YES`
# (the demo flag fills in sample input and runs the actions), and takes a simulator screenshot in
# light and dark appearance with a fixed status bar. Nothing is drawn by hand: every image is the
# running app.
#
# Usage: scripts/capture-example-screens.sh [simulator name or UDID]
# Without an argument it uses the first available iPhone simulator. Output: docs/images/
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
device="${1:-}"
if [[ -z "$device" ]]; then
  device="$(xcrun simctl list devices available | grep -m1 -oE 'iPhone [^(]+' | sed 's/ *$//')"
fi
if [[ -z "$device" ]]; then
  echo "No available iPhone simulator found." >&2
  exit 1
fi

bundle_id="io.github.muhittincamdali.SecurityLab"
screens=(integrity vault codes redaction privacy)
output_dir="$repo_root/docs/images"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
mkdir -p "$output_dir"

echo "Building SecurityLab for '$device'"
destination="platform=iOS Simulator,name=$device"
if [[ "$device" =~ ^[0-9A-F-]{36}$ ]]; then
  destination="platform=iOS Simulator,id=$device"
fi
xcodebuild build \
  -project "$repo_root/Examples/SecurityLab/SecurityLab.xcodeproj" \
  -scheme SecurityLab \
  -destination "$destination" \
  -derivedDataPath "$build_dir" \
  -quiet
app="$(find "$build_dir/Build/Products" -maxdepth 2 -name 'SecurityLab.app' -path '*iphonesimulator*' | head -1)"

xcrun simctl boot "$device" 2>/dev/null || true
xcrun simctl bootstatus "$device" -b >/dev/null
xcrun simctl status_bar "$device" override --time 9:41 --batteryState charged --batteryLevel 100 \
  --cellularBars 4 --wifiBars 3 --operatorName ""
xcrun simctl install "$device" "$app"

for appearance in light dark; do
  xcrun simctl ui "$device" appearance "$appearance"
  for screen in "${screens[@]}"; do
    xcrun simctl launch --terminate-running-process "$device" "$bundle_id" -screen "$screen" -demo YES >/dev/null
    sleep 5 # navigation push, demo actions (the PIN hash takes a moment) and first layout
    file="$output_dir/example-$screen-$appearance.png"
    xcrun simctl io "$device" screenshot --type=png "$file" >/dev/null 2>&1
    # Half the width of an iPhone 17 screenshot keeps the README light; the lowest part of the
    # display is empty on these screens, so keep the top 1.9 widths.
    sips --resampleWidth 603 "$file" >/dev/null
    sips --cropToHeightWidth 1145 603 --cropOffset 0 0 "$file" >/dev/null
    echo "$file"
  done
done

xcrun simctl status_bar "$device" clear
xcrun simctl terminate "$device" "$bundle_id" 2>/dev/null || true
