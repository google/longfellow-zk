add_test([=[Poly.All]=]  /workspaces/longfellow-zk/clang-build-release/algebra/poly_test [==[--gtest_filter=Poly.All]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Poly.All]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/algebra SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  poly_test_TESTS Poly.All)
