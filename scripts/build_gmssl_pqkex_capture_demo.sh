#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 PATCHED_GMSSL_BUILD_DIR [OUTPUT]" >&2
    exit 2
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gmssl_build_dir=$(CDPATH= cd -- "$1" && pwd)
gmssl_source_dir=$(CDPATH= cd -- "$gmssl_build_dir/.." && pwd)
output=${2:-"$project_dir/build-pqkex-capture/pqkex_capture_demo"}
output_dir=$(dirname -- "$output")

if [ ! -f "$gmssl_build_dir/bin/libgmssl.a" ] ||
   [ ! -f "$gmssl_build_dir/CMakeFiles/gmssl.dir/flags.make" ]; then
    echo "patched static GmSSL build artifacts not found in: $gmssl_build_dir" >&2
    echo "configure GmSSL with -DBUILD_SHARED_LIBS=OFF" >&2
    exit 2
fi

mkdir -p "$output_dir"

gmssl_defines=$(sed -n 's/^C_DEFINES = //p' \
    "$gmssl_build_dir/CMakeFiles/gmssl.dir/flags.make")
gmssl_cflags=$(sed -n 's/^C_FLAGS = //p' \
    "$gmssl_build_dir/CMakeFiles/gmssl.dir/flags.make")

# GmSSL public structs depend on build feature macros. Compile the driver with
# the exact definitions used by the patched static library.
# shellcheck disable=SC2086
cc -std=c11 -Wall -Wextra -Wpedantic \
    $gmssl_defines $gmssl_cflags \
    -isystem "$gmssl_source_dir/include" \
    "$project_dir/tools/pqkex_capture_demo.c" \
    "$gmssl_build_dir/bin/libgmssl.a" \
    -ldl -lpthread -o "$output"

echo "$output"
