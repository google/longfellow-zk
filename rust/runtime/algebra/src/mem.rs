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

use std::sync::atomic::{AtomicUsize, Ordering};

pub static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
pub static PEAK: AtomicUsize = AtomicUsize::new(0);

pub fn reset_peak() {
    let current = ALLOCATED.load(Ordering::SeqCst);
    PEAK.store(current, Ordering::SeqCst);
}

pub fn get_peak_allocated() -> usize {
    PEAK.load(Ordering::SeqCst)
}

pub fn get_current_allocated() -> usize {
    ALLOCATED.load(Ordering::SeqCst)
}

pub fn log_mem(step: &str) {
    let curr = ALLOCATED.load(Ordering::SeqCst) as f64 / 1024.0 / 1024.0;
    let peak = PEAK.load(Ordering::SeqCst) as f64 / 1024.0 / 1024.0;
    eprintln!("[MEM] {step:<40} | Curr: {curr:>6.2} MB | Peak: {peak:>6.2} MB");
}
