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

pub struct Tableau<T> {
    data: Vec<T>,
    width: usize,
    height: usize,
}

impl<T> Tableau<T> {
    pub fn new(height: usize, width: usize, default: T) -> Self
    where
        T: Clone,
    {
        Self {
            data: vec![default; height * width],
            width,
            height,
        }
    }

    #[must_use]
    pub fn row(&self, r: usize) -> &[T] {
        assert!(r < self.height);
        &self.data[r * self.width..(r + 1) * self.width]
    }

    pub fn row_mut(&mut self, r: usize) -> &mut [T] {
        assert!(r < self.height);
        &mut self.data[r * self.width..(r + 1) * self.width]
    }
}

impl<T> std::ops::Index<(usize, usize)> for Tableau<T> {
    type Output = T;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let (r, c) = index;
        assert!(r < self.height && c < self.width);
        &self.data[r * self.width + c]
    }
}

impl<T> std::ops::IndexMut<(usize, usize)> for Tableau<T> {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let (r, c) = index;
        assert!(r < self.height && c < self.width);
        &mut self.data[r * self.width + c]
    }
}
