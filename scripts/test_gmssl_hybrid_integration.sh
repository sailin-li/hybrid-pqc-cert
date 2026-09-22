#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 PATCHED_GMSSL_BUILD_DIR [PROJECT_BUILD_DIR]" >&2
    exit 2
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gmssl_build_dir=$(CDPATH= cd -- "$1" && pwd)
gmssl_source_dir=$(CDPATH= cd -- "$gmssl_build_dir/.." && pwd)
project_build_dir=$(CDPATH= cd -- "${2:-$project_dir/build}" && pwd)
test_binary=$(mktemp /tmp/test_tlcp_hybrid_gmssl.XXXXXX)
trap 'rm -f "$test_binary" "$test_binary.gmssl.o" "$test_binary.fixture.o"' \
    EXIT HUP INT TERM
gmssl_defines=$(sed -n 's/^C_DEFINES = //p' \
    "$gmssl_build_dir/CMakeFiles/gmssl.dir/flags.make")
gmssl_cflags=$(sed -n 's/^C_FLAGS = //p' \
    "$gmssl_build_dir/CMakeFiles/gmssl.dir/flags.make")

# GmSSL exposes feature-dependent structs in public headers, so the integration
# translation unit must use the exact feature defines of the linked library.
# shellcheck disable=SC2086
cc -std=c11 -Wall -Wextra -Wpedantic \
    $gmssl_defines $gmssl_cflags \
    -I"$project_dir/tests" -I"$gmssl_source_dir/include" \
    -c "$project_dir/tests/test_tlcp_hybrid_gmssl.c" \
    -o "$test_binary.gmssl.o"

cc -std=c11 -Wall -Wextra -Wpedantic \
    $gmssl_cflags \
    -I"$project_dir/include" -I"$project_dir/tests" \
    -c "$project_dir/tests/tlcp_hybrid_gmssl_fixture.c" \
    -o "$test_binary.fixture.o"

cc $gmssl_cflags "$test_binary.gmssl.o" "$test_binary.fixture.o" \
    "$project_build_dir/libhybrid_pqc.a" \
    "$project_build_dir/libdilithium_ref.a" \
    "$gmssl_build_dir/bin/libgmssl.a" \
    "$project_dir/third_party/openssl/libcrypto.so" \
    -ldl -lpthread -o "$test_binary"

LD_LIBRARY_PATH="$project_dir/third_party/openssl${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$test_binary"
