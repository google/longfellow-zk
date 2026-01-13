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

add_library(mdoc mdoc_zk.cc mdoc_decompress.cc mdoc_generate_circuit.cc
                 mdoc_circuit_id.cc zk_spec.cc)
target_link_libraries(mdoc flatsha ec algebra util zstd)

add_library(mdoc_static STATIC
                        mdoc_zk.cc mdoc_decompress.cc mdoc_generate_circuit.cc
                        mdoc_circuit_id.cc zk_spec.cc
    $<TARGET_OBJECTS:flatsha>
    $<TARGET_OBJECTS:ec>
    $<TARGET_OBJECTS:algebra>
    $<TARGET_OBJECTS:util>
)

proofs_add_test(mdoc_signature_test)
target_link_libraries(mdoc_signature_test mdoc)

#proofs_add_test(zk_spec_test)
#target_link_libraries(zk_spec_test mdoc)

proofs_add_test(mdoc_1f_test)
target_link_libraries(mdoc_1f_test mdoc)

# link mdoc_zk_test explicitly against the static library
# so that we know that the static library works
add_executable(mdoc_zk_test mdoc_zk_test.cc)
target_link_libraries(mdoc_zk_test mdoc_static)
proofs_add_testing_libraries(mdoc_zk_test)
target_link_libraries(mdoc_zk_test crypto zstd)
# Link Security framework if using Secure Enclave RNG
if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin" AND USE_SECURE_ENCLAVE_RNG)
    target_link_libraries(mdoc_zk_test ${SECURITY_FRAMEWORK})
endif()

set(installable_libs mdoc_static)
install(TARGETS ${installable_libs} DESTINATION lib)
install(FILES mdoc_zk.h DESTINATION include)

find_package(absl QUIET)
if (absl_FOUND)
    message(STATUS "ABSL found. Adding circuit_maker.")
    add_executable(circuit_maker circuit_maker.cc)
    target_link_libraries(circuit_maker mdoc_static absl::flags absl::flags_parse absl::cleanup crypto zstd)
else()
    message(STATUS "ABSL not found. circuit_maker will not be built.")
endif()
