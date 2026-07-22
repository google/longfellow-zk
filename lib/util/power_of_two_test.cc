// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util/power_of_two.h"

#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(PowerOfTwoTest, ReturnsSmallestPowerNotLessThanInput) {
  EXPECT_EQ(next_power_of_two(0), 1u);
  EXPECT_EQ(next_power_of_two(1), 1u);
  EXPECT_EQ(next_power_of_two(7), 8u);
  EXPECT_EQ(next_power_of_two(8), 8u);
  EXPECT_EQ(next_power_of_two(9), 16u);
  EXPECT_EQ(next_power_of_two((1ull << 22) - 1), 1ull << 22);
  EXPECT_EQ(next_power_of_two((1ull << 22) + 1), 1ull << 23);
}

}  // namespace
}  // namespace proofs
