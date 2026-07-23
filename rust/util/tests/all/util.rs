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

use util::ceil_log2;

#[test]
fn test_ceil_log2() {
    assert_eq!(ceil_log2(1), 0);
    assert_eq!(ceil_log2(2), 1);
    assert_eq!(ceil_log2(3), 2);
    assert_eq!(ceil_log2(4), 2);
    assert_eq!(ceil_log2(5), 3);
    assert_eq!(ceil_log2(8), 3);
    assert_eq!(ceil_log2(9), 4);
}

#[test]
#[should_panic(expected = "log2 of zero is undefined")]
fn test_ceil_log2_zero_panic() {
    let _ = ceil_log2(0);
}
