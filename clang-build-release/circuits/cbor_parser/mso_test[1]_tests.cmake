add_test([=[MSO.Example]=]  /workspaces/longfellow-zk/clang-build-release/circuits/cbor_parser/mso_test [==[--gtest_filter=MSO.Example]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[MSO.Example]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/circuits/cbor_parser SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  mso_test_TESTS MSO.Example)
