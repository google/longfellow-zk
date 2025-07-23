add_test([=[ECDSA.VerifyExternalP256]=]  /workspaces/longfellow-zk/clang-build-release/circuits/ecdsa/verify_external_test [==[--gtest_filter=ECDSA.VerifyExternalP256]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ECDSA.VerifyExternalP256]=]  PROPERTIES WORKING_DIRECTORY /workspaces/longfellow-zk/clang-build-release/circuits/ecdsa SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  verify_external_test_TESTS ECDSA.VerifyExternalP256)
