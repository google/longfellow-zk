# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13)
project(proofs)
set(CMAKE_CXX_STANDARD 17)
include(CMake/proofs.cmake)
enable_testing()

# macOS-specific configuration
if (CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
  link_directories("/opt/homebrew/lib")
  include_directories("/opt/homebrew/include")
  
  # Option to enable Apple Secure Enclave RNG
  option(USE_SECURE_ENCLAVE_RNG "Use Apple Secure Enclave for random number generation" OFF)
  
  if(USE_SECURE_ENCLAVE_RNG)
    message(STATUS "Using Apple Secure Enclave for random number generation")
    add_compile_definitions(SECURE_ENCLAVE_RNG)
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    if(NOT SECURITY_FRAMEWORK)
      message(FATAL_ERROR "Security framework not found - required for Secure Enclave RNG")
    endif()
  else()
    message(STATUS "Using OpenSSL for random number generation")
  endif()
endif()

# add compiler flags for all known ISA's
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCHITECTURE)

if(ARCHITECTURE MATCHES "x86_64")
    set(ARCH_FLAGS -mpclmul)
elseif(ARCHITECTURE MATCHES "i386")
    set(ARCH_FLAGS -msse2 -mpclmul)
elseif(ARCHITECTURE MATCHES "aarch64")
    set(ARCH_FLAGS -march=armv8-a -march=armv8-a+crypto)
elseif(ARCHITECTURE MATCHES "armv7l")
    set(ARCH_FLAGS -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard)
elseif(ARCHITECTURE MATCHES "arm64")
    # Mac Arm
    set(ARCH_FLAGS -mcpu=apple-m1 -march=armv8-a+crypto)
else()
    set(ARCH_FLAGS "")
endif()

if(ARCH_FLAGS)
    add_compile_options( "$<$<COMPILE_LANGUAGE:CXX>:${ARCH_FLAGS}>")
    message(STATUS "Compiler flags added for architecture ${ARCHITECTURE}: ${ARCH_FLAGS}")
else()
     message(STATUS "Architecture ${ARCHITECTURE} not recognized, no specific compiler flags added.")
endif()


include_directories(${proofs_SOURCE_DIR})

add_subdirectory(testing)
add_subdirectory(util)
add_subdirectory(algebra)
add_subdirectory(arrays)
add_subdirectory(merkle)
add_subdirectory(ligero)
add_subdirectory(proto)
add_subdirectory(random)
add_subdirectory(sumcheck)
add_subdirectory(gf2k)
add_subdirectory(cbor)
add_subdirectory(ec)
add_subdirectory(zk)
add_subdirectory(circuits/anoncred)
add_subdirectory(circuits/base64)
add_subdirectory(circuits/cbor_parser)
add_subdirectory(circuits/compiler)
add_subdirectory(circuits/ecdsa)
add_subdirectory(circuits/jwt)
add_subdirectory(circuits/logic)
add_subdirectory(circuits/mac)
add_subdirectory(circuits/mdoc)
add_subdirectory(circuits/sha)
add_subdirectory(circuits/sha3)
