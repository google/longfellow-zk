add_test([=[Fp2.All]=]  /workspaces/longfellow-zk/clang-build-release/algebra/fp2_test [==[--gtest_filter=Fp2.All]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Fp2.All]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/algebra SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  fp2_test_TESTS Fp2.All)
