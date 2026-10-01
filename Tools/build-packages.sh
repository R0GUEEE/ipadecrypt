#!/bin/sh
# Build the on-device .deb packages (app + auto-confirm tweak) from source,
# without a device and without SSH.
#
#   Tools/build-packages.sh [--helper PATH] [--refresh-embedded] [--rootless-only]
#
# Produces, under dist/:
#   com.korboy.ipadecrypt_<version>_iphoneos-arm64.deb           rootless app
#   com.korboy.ipadecrypt_<version>_iphoneos-arm64e.deb          RootHide app
#   com.korboy.ipadecryptautoalert_<version>_iphoneos-arm64.deb  rootless tweak
#   com.korboy.ipadecryptautoalert_<version>_iphoneos-arm64e.deb RootHide tweak
#
# Options
#   --helper PATH       ipadecrypt-helper binary to embed/sign (default: the
#                       committed app/Resources/helper.arm64)
#   --refresh-embedded  copy the built tweak packages (and --helper) into
#                       internal/device/, so a released CLI bootstraps the same
#                       versions this build produced
#   --rootless-only     build only the rootless (iphoneos-arm64) packages
#
# Environment
#   THEOS          Theos checkout                 (default: $HOME/theos)
#   THEOS_ROOTHIDE RootHide Theos checkout        (default: $HOME/theos-roothide)
#   GO             go binary                      (default: go)
#
# Requires: an iOS SDK in $THEOS/sdks, ldid, dpkg-deb and either xcrun (macOS)
# or the Theos Linux toolchain.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HELPER=
REFRESH_EMBEDDED=0
ROOTLESS_ONLY=0

while [ $# -gt 0 ]; do
	case "$1" in
		--helper) HELPER=$2; shift 2 ;;
		--refresh-embedded) REFRESH_EMBEDDED=1; shift ;;
		--rootless-only) ROOTLESS_ONLY=1; shift ;;
		-h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

THEOS=${THEOS:-$HOME/theos}
THEOS_ROOTHIDE=${THEOS_ROOTHIDE:-$HOME/theos-roothide}
GO=${GO:-go}

[ -d "$THEOS/makefiles" ] || { echo "no Theos at $THEOS (set THEOS)" >&2; exit 1; }
command -v ldid >/dev/null 2>&1 || { echo "ldid not found in PATH" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb not found in PATH" >&2; exit 1; }
command -v "$GO" >/dev/null 2>&1 || { echo "go not found ($GO)" >&2; exit 1; }

IOS_SDK=$(ls -d "$THEOS"/sdks/iPhoneOS*.sdk 2>/dev/null | sort -V | tail -1)
[ -n "$IOS_SDK" ] || { echo "no iPhoneOS SDK found under $THEOS/sdks" >&2; exit 1; }
IOS_SDK_VERSION=$(basename "$IOS_SDK" | sed 's/iPhoneOS//; s/\.sdk//')

if [ -x "$THEOS/toolchain/linux/host/bin/clang-13" ]; then
	IOS_CLANG="$THEOS/toolchain/linux/host/bin/clang-13"
	IOS_LDFLAGS="-fuse-ld=lld -Wl,-platform_version,ios,15.0,$IOS_SDK_VERSION"
elif command -v xcrun >/dev/null 2>&1; then
	IOS_CLANG=$(xcrun -f clang)
	IOS_LDFLAGS="-Wl,-platform_version,ios,15.0,$IOS_SDK_VERSION"
else
	echo "no iOS-capable clang found (checked the Theos Linux toolchain and xcrun)" >&2
	exit 1
fi
IOS_CC="$IOS_CLANG -target arm64-apple-ios15.0 -isysroot $IOS_SDK -Wno-incompatible-sysroot -Wno-unused-command-line-argument"

echo "== theos:      $THEOS"
echo "== sdk:        $IOS_SDK"

# --- ipadecrypt-helper ------------------------------------------------------
# The commited binary is what ships in both the app bundle and the CLI, so a
# fresh one (--helper) replaces it for the duration of the build and is put
# back afterwards, keeping the working tree clean.
HELPER_BACKUP=
if [ -n "$HELPER" ]; then
	[ -f "$HELPER" ] || { echo "--helper: no such file: $HELPER" >&2; exit 1; }
	HELPER_BACKUP=$(mktemp)
	cp "$ROOT/app/Resources/helper.arm64" "$HELPER_BACKUP"
	cp "$HELPER" "$ROOT/app/Resources/helper.arm64"
fi

cleanup() {
	if [ -n "$HELPER_BACKUP" ] && [ -f "$HELPER_BACKUP" ]; then
		cp "$HELPER_BACKUP" "$ROOT/app/Resources/helper.arm64"
		rm -f "$HELPER_BACKUP"
	fi
}
trap cleanup EXIT INT TERM

# --- Go side: app-store helper and the daemon --------------------------------
echo "== building appstore-helper.arm64"
( cd "$ROOT" && \
	GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
	CC="$IOS_CC" CGO_LDFLAGS="$IOS_LDFLAGS" \
	"$GO" build -trimpath -ldflags="-s -w" \
		-o app/Resources/appstore-helper.arm64 ./cmd/ipadecrypt-appstore-helper )
ldid -S"$ROOT/app/appstore-helper.entitlements.plist" "$ROOT/app/Resources/appstore-helper.arm64"
chmod +x "$ROOT/app/Resources/appstore-helper.arm64"

echo "== building ipadecryptd"
mkdir -p "$ROOT/app/layout/usr/libexec"
( cd "$ROOT" && \
	GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
	CC="$IOS_CC" CGO_LDFLAGS="$IOS_LDFLAGS" \
	"$GO" build -trimpath -ldflags="-s -w" \
		-o app/layout/usr/libexec/ipadecryptd ./cmd/ipadecryptd )
ldid -S"$ROOT/app/daemon.entitlements.plist" "$ROOT/app/layout/usr/libexec/ipadecryptd"
chmod +x "$ROOT/app/layout/usr/libexec/ipadecryptd" "$ROOT/app/layout/DEBIAN/postinst"

echo "== signing helper.arm64"
ldid -S"$ROOT/helper/entitlements.plist" "$ROOT/app/Resources/helper.arm64"
chmod +x "$ROOT/app/Resources/helper.arm64"

# --- packages ----------------------------------------------------------------
VERSION=$(sed -n 's/^Version: *//p' "$ROOT/app/control")
DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

echo "== packaging app (rootless)"
( cd "$ROOT/app" && THEOS="$THEOS" make clean package FINALPACKAGE=1 )
cp "$(ls -t "$ROOT"/app/packages/com.korboy.ipadecrypt_*_iphoneos-arm64.deb | head -1)" "$DIST/"

echo "== packaging tweak (rootless)"
( cd "$ROOT/helper/ipadecryptautoalert" && THEOS="$THEOS" make clean package FINALPACKAGE=1 \
	THEOS_PACKAGE_SCHEME=rootless )
cp "$(ls -t "$ROOT"/helper/ipadecryptautoalert/packages/com.korboy.ipadecryptautoalert_*_iphoneos-arm64.deb | head -1)" "$DIST/"

if [ "$ROOTLESS_ONLY" -eq 0 ]; then
	if [ -d "$THEOS_ROOTHIDE/makefiles" ]; then
		echo "== packaging app (RootHide)"
		# build_roothide.sh does the same: a throwaway HOME keeps a
		# THEOS_DEVICE_* env var from turning `make package` into an install.
		TMP_HOME=$(mktemp -d)
		( cd "$ROOT/app" && env -u THEOS_DEVICE_IP -u THEOS_DEVICE_PORT -u THEOS_DEVICE_USER \
			HOME="$TMP_HOME" XDG_CONFIG_HOME="$TMP_HOME/.config" \
			THEOS="$THEOS_ROOTHIDE" make clean package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=roothide )
		rm -rf "$TMP_HOME"
		cp "$(ls -t "$ROOT"/app/packages/com.korboy.ipadecrypt_*_iphoneos-arm64e.deb | head -1)" "$DIST/"

		echo "== packaging tweak (RootHide)"
		( cd "$ROOT/helper/ipadecryptautoalert" && THEOS="$THEOS_ROOTHIDE" make clean package FINALPACKAGE=1 \
			THEOS_PACKAGE_SCHEME=roothide )
		cp "$(ls -t "$ROOT"/helper/ipadecryptautoalert/packages/com.korboy.ipadecryptautoalert_*_iphoneos-arm64e.deb | head -1)" "$DIST/"
	else
		echo "== skipping RootHide (no Theos at $THEOS_ROOTHIDE)"
	fi
fi

# --- keep the shipped copies in step ----------------------------------------
if [ "$REFRESH_EMBEDDED" -eq 1 ]; then
	echo "== refreshing internal/device"
	cp "$(ls -t "$DIST"/com.korboy.ipadecryptautoalert_*_iphoneos-arm64.deb | head -1)" \
		"$ROOT/internal/device/ipadecryptautoalert.deb"
	if ls "$DIST"/com.korboy.ipadecryptautoalert_*_iphoneos-arm64e.deb >/dev/null 2>&1; then
		cp "$(ls -t "$DIST"/com.korboy.ipadecryptautoalert_*_iphoneos-arm64e.deb | head -1)" \
			"$ROOT/internal/device/ipadecryptautoalert-roothide.deb"
	fi
	if [ -n "$HELPER" ]; then
		cp "$HELPER" "$ROOT/internal/device/ipadecrypt-helper-arm64"
	fi
fi

echo
echo "== $VERSION packages:"
ls -l "$DIST"
