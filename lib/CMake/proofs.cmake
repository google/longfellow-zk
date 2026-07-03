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

add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED=1)
include(GoogleTest)
find_package(benchmark REQUIRED)
find_package(GTest REQUIRED)
find_path(ZSTD_INCLUDE_DIR zstd.h)
find_library(ZSTD_LIBRARY zstd)
if (ZSTD_INCLUDE_DIR AND ZSTD_LIBRARY AND NOT TARGET zstd)
  add_library(zstd UNKNOWN IMPORTED)
  set_target_properties(zstd PROPERTIES
    IMPORTED_LOCATION "${ZSTD_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ZSTD_INCLUDE_DIR}")
endif()

macro(proofs_add_testing_libraries PROG)
    # libraries that are common enough to be useful in all tests
    target_link_libraries(${PROG} testing_main)    

#   -static won't work on Debian because libbenchmark-dev is
#   dynamic only.  One could enable -static and comment out
#   benchmark, in which case some tests won't build

#    target_link_libraries(${PROG} -static)

    # on Debian buster, gtest seems to need pthread
    if (CMAKE_SYSTEM_NAME STREQUAL "Android")
        target_link_libraries(${PROG} gtest log)
    else()
        target_link_libraries(${PROG} GTest::gtest pthread)
    endif()

    target_link_libraries(${PROG} benchmark::benchmark)

    # Do not auto-discover tests on ios or android
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "iOS" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
        gtest_discover_tests(${PROG})
    endif()
endmacro()

macro(proofs_add_test PROG)
    if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
        add_executable(${PROG} MACOSX_BUNDLE ${PROG}.cc ${ARGN})
        set_target_properties(${PROG} PROPERTIES
            MACOSX_BUNDLE_GUI_IDENTIFIER "com.example.longfellow"
            MACOSX_BUNDLE_BUNDLE_NAME "${PROG}"
            XCODE_SCHEME_BUILD_CONFIGURATION "Release"
            XCODE_SCHEME_ARGUMENTS "--benchmark_filter=BM*")
    else()
        add_executable(${PROG} ${PROG}.cc ${ARGN})
    endif()

    target_link_libraries(${PROG} ec)    
    target_link_libraries(${PROG} algebra)
    target_link_libraries(${PROG} util)
    proofs_add_testing_libraries(${PROG})
endmacro()

macro(proofs_add_tests)
    foreach (PROG ${ARGN})
        proofs_add_test(${PROG})
    endforeach ()
endmacro()
