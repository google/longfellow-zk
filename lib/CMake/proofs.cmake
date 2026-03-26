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

option(PROOFS_BUILD_TESTS "Build tests and benchmarks" ON)

if(PROOFS_BUILD_TESTS)
    include(GoogleTest)
    find_package(benchmark REQUIRED)
    find_package(GTest REQUIRED)
endif()

if(PROOFS_BUILD_TESTS)
    macro(proofs_add_testing_libraries PROG)
        # libraries that are common enough to be useful in all tests
        target_link_libraries(${PROG} testing_main)

    #   -static won't work on Debian because libbenchmark-dev is
    #   dynamic only.  One could enable -static and comment out
    #   benchmark, in which case some tests won't build

    #    target_link_libraries(${PROG} -static)

        # on Debian buster, gtest seems to need pthread
        target_link_libraries(${PROG} gtest pthread)
        target_link_libraries(${PROG} benchmark::benchmark)

        gtest_discover_tests(${PROG})
    endmacro()

    macro(proofs_add_test PROG)
        add_executable(${PROG} ${PROG}.cc ${ARGN})
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
else()
    # No-op stubs so subdirectory CMakeLists.txt files work unchanged.
    macro(proofs_add_testing_libraries PROG)
    endmacro()
    macro(proofs_add_test PROG)
    endmacro()
    macro(proofs_add_tests)
    endmacro()
endif()

