#!/bin/bash
# Builds MdocZk.xcframework for iOS (arm64) and iOS Simulator (arm64, x86_64).
#
# Uses CommonCrypto instead of OpenSSL. Links zstd from the multipaz nativeLibs
# folder.
#
# Prerequisites: cmake, Xcode command line tools
# Usage: ./build_xcframework.sh

set -euo pipefail

# Locate cmake
if command -v cmake &>/dev/null; then
    CMAKE=cmake
elif [[ -x /opt/homebrew/bin/cmake ]]; then
    CMAKE=/opt/homebrew/bin/cmake
elif [[ -x /Applications/CMake.app/Contents/bin/cmake ]]; then
    CMAKE=/Applications/CMake.app/Contents/bin/cmake
else
    echo "Error: cmake not found. Install via 'brew install cmake' or CMake.app."
    exit 1
fi
echo "Using cmake: $CMAKE"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$ROOT_DIR/lib"
OUTPUT_DIR="$ROOT_DIR/build-xcframework"
FRAMEWORK_NAME="MdocZk"
DEPLOYMENT_TARGET_IOS="15.0"
ZSTD_LIBS="/Users/ffeli/Source/other/multipaz/multipaz-longfellow/src/iosMain/nativeLibs"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Helper: configure & build mdoc_static for a given platform / arch
# ---------------------------------------------------------------------------
build_slice() {
    local platform="$1"   # iphoneos | iphonesimulator
    local arch="$2"       # arm64 | x86_64
    local build_dir="$OUTPUT_DIR/build-${platform}-${arch}"
    local install_dir="$OUTPUT_DIR/install-${platform}-${arch}"
    local zstd_dir="$ZSTD_LIBS/${arch}-${platform}/lib"

    echo "==> Building ${platform} / ${arch}"
    mkdir -p "$build_dir" "$install_dir"

    local cmake_args=(
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_SYSTEM_NAME=iOS
        -DCMAKE_OSX_ARCHITECTURES="$arch"
        -DCMAKE_OSX_SYSROOT="$platform"
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET_IOS"
        -DCMAKE_INSTALL_PREFIX="$install_dir"
        -DPROOFS_BUILD_TESTS=OFF
        -DCMAKE_FIND_ROOT_PATH="$zstd_dir/.."
        -DZSTD_LIBRARY="$zstd_dir/libzstd.a"
        -DZSTD_INCLUDE_DIR="$zstd_dir/../include"
        -S "$LIB_DIR"
        -B "$build_dir"
    )

    "$CMAKE" "${cmake_args[@]}" 2>&1 | tail -5
    "$CMAKE" --build "$build_dir" --target mdoc_static -j "$(sysctl -n hw.ncpu)" 2>&1 | tail -3
    "$CMAKE" --install "$build_dir" --component Unspecified 2>&1 | tail -3

    # Merge libzstd.a into libmdoc_static.a so the xcframework is self-contained.
    libtool -static -o "$install_dir/lib/libmdoc_static.a" \
        "$install_dir/lib/libmdoc_static.a" \
        "$zstd_dir/libzstd.a"

    echo "    -> $install_dir/lib/libmdoc_static.a (includes zstd)"
}

# ---------------------------------------------------------------------------
# Build all slices
# ---------------------------------------------------------------------------
build_slice iphoneos        arm64
build_slice iphonesimulator arm64
build_slice iphonesimulator x86_64

# ---------------------------------------------------------------------------
# Create fat (universal) library for simulator
# ---------------------------------------------------------------------------
echo "==> Creating universal simulator library"

FAT_SIM="$OUTPUT_DIR/fat-iphonesimulator/libmdoc_static.a"
mkdir -p "$(dirname "$FAT_SIM")"
lipo -create \
    "$OUTPUT_DIR/install-iphonesimulator-arm64/lib/libmdoc_static.a" \
    "$OUTPUT_DIR/install-iphonesimulator-x86_64/lib/libmdoc_static.a" \
    -output "$FAT_SIM"
echo "    -> $FAT_SIM ($(lipo -info "$FAT_SIM" | awk -F': ' '{print $NF}'))"

# ---------------------------------------------------------------------------
# Prepare headers directory
# ---------------------------------------------------------------------------
HEADERS_DIR="$OUTPUT_DIR/include"
mkdir -p "$HEADERS_DIR"
cp "$LIB_DIR/circuits/mdoc/mdoc_zk.h" "$HEADERS_DIR/"
cat > "$HEADERS_DIR/module.modulemap" <<'EOF'
module MdocZK {
    header "mdoc_zk.h"
    export *
}
EOF

# ---------------------------------------------------------------------------
# Create the xcframework
# ---------------------------------------------------------------------------
echo "==> Creating ${FRAMEWORK_NAME}.xcframework"

XCFW="$OUTPUT_DIR/${FRAMEWORK_NAME}.xcframework"
rm -rf "$XCFW"

xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/install-iphoneos-arm64/lib/libmdoc_static.a" \
    -headers "$HEADERS_DIR" \
    -library "$FAT_SIM" \
    -headers "$HEADERS_DIR" \
    -output "$XCFW"

echo ""
echo "Done! Framework at:"
echo "  $XCFW"
echo ""
echo "The framework is self-contained (zstd is included)."
echo "Consumers only need to link the Security framework."
