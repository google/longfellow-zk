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
