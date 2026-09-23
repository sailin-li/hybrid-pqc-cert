cmake_minimum_required(VERSION 3.16)
project(hybrid_pqc_cert VERSION 0.1.0 LANGUAGES C)

option(HYBRID_ENABLE_SANITIZERS
       "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(HYBRID_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(DILITHIUM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dilithium"
    CACHE PATH "CRYSTALS-Dilithium source directory")
set(LIBOQS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/liboqs"
    CACHE PATH "liboqs source directory")
if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl")
endif()

find_package(OpenSSL 3.2.0 EXACT REQUIRED COMPONENTS Crypto)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto: ${OPENSSL_CRYPTO_LIBRARY}")

if(NOT EXISTS "${LIBOQS_SOURCE_DIR}/src/kem/ml_kem/kem_ml_kem_768.c")
    message(FATAL_ERROR
            "LIBOQS_SOURCE_DIR does not provide the ML-KEM-768 implementation")
endif()

# Build only the final FIPS 203 ML-KEM-768 implementation. In particular, the
# legacy Kyber family that is also present in liboqs is disabled and cannot be
# selected as a fallback.
set(OQS_MINIMAL_BUILD "KEM_ml_kem_768" CACHE STRING
    "Algorithms included in the embedded liboqs build" FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only the liboqs library" FORCE)
set(OQS_DIST_BUILD OFF CACHE BOOL "Disable multi-architecture dispatch" FORCE)
set(OQS_OPT_TARGET generic CACHE STRING "Use portable liboqs code" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "Use liboqs internal primitives" FORCE)
set(CMAKE_C_EXTENSIONS ON)
add_subdirectory("${LIBOQS_SOURCE_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/liboqs" EXCLUDE_FROM_ALL)
set(CMAKE_C_EXTENSIONS OFF)
message(STATUS "liboqs source: ${LIBOQS_SOURCE_DIR}")
message(STATUS "liboqs minimal algorithm: ML-KEM-768 (FIPS 203)")

set(DILITHIUM_REF_DIR "${DILITHIUM_SOURCE_DIR}/ref")
if(NOT EXISTS "${DILITHIUM_REF_DIR}/api.h")
    message(FATAL_ERROR "DILITHIUM_SOURCE_DIR does not contain ref/api.h")
endif()

function(enable_project_warnings target)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endfunction()

add_library(dilithium_ref STATIC
    ${DILITHIUM_REF_DIR}/sign.c
    ${DILITHIUM_REF_DIR}/packing.c
    ${DILITHIUM_REF_DIR}/polyvec.c
    ${DILITHIUM_REF_DIR}/poly.c
    ${DILITHIUM_REF_DIR}/ntt.c
    ${DILITHIUM_REF_DIR}/reduce.c
    ${DILITHIUM_REF_DIR}/rounding.c
    ${DILITHIUM_REF_DIR}/fips202.c
    ${DILITHIUM_REF_DIR}/symmetric-shake.c
    ${DILITHIUM_REF_DIR}/randombytes.c)
target_compile_definitions(dilithium_ref PRIVATE DILITHIUM_MODE=2)
set_target_properties(dilithium_ref PROPERTIES C_EXTENSIONS ON)
target_include_directories(dilithium_ref PUBLIC ${DILITHIUM_REF_DIR})
enable_project_warnings(dilithium_ref)

add_library(hybrid_pqc
    src/dilithium_wrapper.c
    src/sm2_wrapper.c
    src/composite_key.c
    src/composite_sig.c
    src/hybrid_key_store.c
    src/hybrid_sign.c
    src/hybrid_x509.c
    src/hybrid_chain.c
    src/tlcp_hybrid_cert_adapter.c)
target_include_directories(hybrid_pqc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hybrid_pqc PUBLIC OpenSSL::Crypto dilithium_ref)
enable_project_warnings(hybrid_pqc)

add_library(mlkem STATIC src/mlkem.c)
target_include_directories(mlkem PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(mlkem PRIVATE oqs)
enable_project_warnings(mlkem)

enable_testing()
foreach(test_name IN ITEMS dilithium sm2 hybrid_sign)
    add_executable(test_${test_name} tests/test_${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE hybrid_pqc)
    enable_project_warnings(test_${test_name})
    add_test(NAME ${test_name} COMMAND test_${test_name})
endforeach()

foreach(test_name IN ITEMS composite_key composite_message hybrid_key_store
                           hybrid_x509 hybrid_chain hybrid_encryption_cert
                           tlcp_hybrid_cert_adapter)
    add_executable(test_${test_name} tests/test_${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE hybrid_pqc)
    enable_project_warnings(test_${test_name})
    add_test(NAME ${test_name} COMMAND test_${test_name})
endforeach()

add_executable(test_mlkem tests/test_mlkem.c)
target_link_libraries(test_mlkem PRIVATE mlkem)
enable_project_warnings(test_mlkem)
add_test(NAME mlkem COMMAND test_mlkem)

add_executable(test_mlkem_kat tests/test_mlkem_kat.c)
target_link_libraries(test_mlkem_kat PRIVATE mlkem oqs)
enable_project_warnings(test_mlkem_kat)
add_test(NAME mlkem_kat COMMAND test_mlkem_kat)

add_executable(generate_demo_chain tools/generate_demo_chain.c)
target_link_libraries(generate_demo_chain PRIVATE hybrid_pqc)
enable_project_warnings(generate_demo_chain)

add_executable(verify_chain tools/verify_chain.c)
target_link_libraries(verify_chain PRIVATE hybrid_pqc)
enable_project_warnings(verify_chain)

add_executable(inspect_hybrid_cert tools/inspect_hybrid_cert.c)
target_link_libraries(inspect_hybrid_cert PRIVATE hybrid_pqc)
enable_project_warnings(inspect_hybrid_cert)

add_executable(mlkem_demo tools/mlkem_demo.c)
target_link_libraries(mlkem_demo PRIVATE mlkem)
enable_project_warnings(mlkem_demo)

add_executable(benchmark_composite_verify tools/benchmark_composite_verify.c)
target_link_libraries(benchmark_composite_verify PRIVATE hybrid_pqc)
if(CMAKE_BUILD_TYPE)
    target_compile_definitions(benchmark_composite_verify PRIVATE
        HYBRID_BENCH_BUILD_TYPE="${CMAKE_BUILD_TYPE}")
else()
    target_compile_definitions(benchmark_composite_verify PRIVATE
        HYBRID_BENCH_BUILD_TYPE="unspecified")
endif()
enable_project_warnings(benchmark_composite_verify)
add_test(NAME benchmark_smoke COMMAND benchmark_composite_verify
         --warmup 1 --iterations 10)
