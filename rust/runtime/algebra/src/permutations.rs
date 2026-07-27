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

pub(crate) fn bitrev<T>(a: &mut [T]) {
    let n = a.len();
    let mut revi = 0;
    for i in 0..(n - 1) {
        if i < revi {
            a.swap(i, revi);
        }
        let mut bit = n;
        loop {
            bit >>= 1;
            revi ^= bit;
            if (revi & bit) != 0 {
                break;
            }
        }
    }
}
