add_test([=[BitAdder.Fields]=]  /workspaces/longfellow-zk/clang-build-release/circuits/logic/bit_adder_test [==[--gtest_filter=BitAdder.Fields]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[BitAdder.Fields]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/circuits/logic SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  bit_adder_test_TESTS BitAdder.Fields)
