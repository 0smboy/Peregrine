use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct ProgressGuard {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProgressGuard {
    pub fn start(label: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let label = label.to_string();
        let handle = thread::spawn(move || {
            let length = 40usize;
            let mut ratio = 0usize;
            while !stop2.load(Ordering::Relaxed) {
                let mark = if label.contains("read") { '<' } else { '>' };
                let mut bar = String::new();
                for i in 0..length {
                    if i < ratio {
                        bar.push(mark);
                    } else {
                        bar.push(' ');
                    }
                }
                eprint!("\x1b[32m {label}: [{bar}] \r\x1b[0m");
                ratio = (ratio + 1) % (length + 1);
                thread::sleep(Duration::from_millis(120));
            }
            eprint!("\r\x1b[K");
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
