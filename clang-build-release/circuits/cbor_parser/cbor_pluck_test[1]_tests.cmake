add_test([=[CborPluck.Pluck]=]  /workspaces/longfellow-zk/clang-build-release/circuits/cbor_parser/cbor_pluck_test [==[--gtest_filter=CborPluck.Pluck]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CborPluck.Pluck]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/circuits/cbor_parser SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  cbor_pluck_test_TESTS CborPluck.Pluck)
