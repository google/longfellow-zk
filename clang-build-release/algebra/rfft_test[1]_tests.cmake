add_test([=[RFFTTest.Simple]=]  /workspaces/longfellow-zk/clang-build-release/algebra/rfft_test [==[--gtest_filter=RFFTTest.Simple]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[RFFTTest.Simple]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/algebra SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  rfft_test_TESTS RFFTTest.Simple)
