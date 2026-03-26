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
if(PROOFS_BUILD_TESTS)
    enable_testing()
endif()
if (CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
  link_directories("/opt/homebrew/lib")
  include_directories("/opt/homebrew/include")
endif()

# add compiler flags for all known ISA's
# CMAKE_SYSTEM_PROCESSOR is empty when cross-compiling for iOS;
# fall back to CMAKE_OSX_ARCHITECTURES in that case.
if(CMAKE_SYSTEM_PROCESSOR)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCHITECTURE)
else()
    string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" ARCHITECTURE)
endif()

if(ARCHITECTURE MATCHES "x86_64")
    set(ARCH_FLAGS -mpclmul)
elseif(ARCHITECTURE MATCHES "i386")
    set(ARCH_FLAGS -msse2 -mpclmul)
elseif(ARCHITECTURE MATCHES "aarch64")
    set(ARCH_FLAGS -march=armv8-a -march=armv8-a+crypto)
elseif(ARCHITECTURE MATCHES "armv7l")
    set(ARCH_FLAGS -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard)
elseif(ARCHITECTURE MATCHES "arm64")
    set(ARCH_FLAGS -march=armv8-a+crypto)
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

# main system used in production
if(PROOFS_BUILD_TESTS)
    add_subdirectory(testing)
endif()
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
add_subdirectory(circuits/cbor_parser)
add_subdirectory(circuits/compiler)
add_subdirectory(circuits/ecdsa)
add_subdirectory(circuits/logic)
add_subdirectory(circuits/mac)
add_subdirectory(circuits/mdoc)
add_subdirectory(circuits/sha)

if(PROOFS_BUILD_TESTS)
    # experiments and tests, not used in production, may be buggy
    add_subdirectory(circuits/tests/anoncred)
    add_subdirectory(circuits/tests/sha3)
    add_subdirectory(circuits/tests/base64)
    add_subdirectory(circuits/tests/jwt)
    add_subdirectory(circuits/tests/ripemd)

    # experimental mdoc stuff, not used in production
    add_subdirectory(circuits/tests/mdoc)
endif()

