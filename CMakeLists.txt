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
if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl")
endif()

find_package(OpenSSL 3.2.0 EXACT REQUIRED COMPONENTS Crypto)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto: ${OPENSSL_CRYPTO_LIBRARY}")

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
    src/hybrid_sign.c
    src/hybrid_asn1.c
    src/hybrid_cert.c
    src/hybrid_verify.c)
target_include_directories(hybrid_pqc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hybrid_pqc PUBLIC OpenSSL::Crypto dilithium_ref)
enable_project_warnings(hybrid_pqc)

enable_testing()
foreach(test_name IN ITEMS dilithium sm2 hybrid_sign)
    add_executable(test_${test_name} tests/test_${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE hybrid_pqc)
    enable_project_warnings(test_${test_name})
    add_test(NAME ${test_name} COMMAND test_${test_name})
endforeach()

add_executable(test_hybrid_asn1 tests/test_hybrid_asn1.c)
target_link_libraries(test_hybrid_asn1 PRIVATE hybrid_pqc)
enable_project_warnings(test_hybrid_asn1)
add_test(NAME hybrid_asn1 COMMAND test_hybrid_asn1)

add_executable(test_hybrid_cert tests/test_hybrid_cert.c)
target_link_libraries(test_hybrid_cert PRIVATE hybrid_pqc)
enable_project_warnings(test_hybrid_cert)
add_test(NAME hybrid_cert COMMAND test_hybrid_cert)

add_executable(hybrid_cert_gen tools/hybrid_cert_gen.c)
target_link_libraries(hybrid_cert_gen PRIVATE hybrid_pqc)
enable_project_warnings(hybrid_cert_gen)

add_executable(hybrid_cert_dump tools/hybrid_cert_dump.c)
target_link_libraries(hybrid_cert_dump PRIVATE hybrid_pqc)
enable_project_warnings(hybrid_cert_dump)
