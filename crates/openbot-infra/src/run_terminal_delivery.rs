//! One bounded, lossy process-local callback worker, independent of durable Run writers.
use openbot_application::{RunTerminalNotice, RunTerminalSubscriber};
use std::sync::{Arc, Mutex, mpsc};

pub(crate) struct TerminalDelivery {
    sender: Mutex<Option<mpsc::SyncSender<RunTerminalNotice>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}
impl TerminalDelivery {
    pub(crate) fn new(subscriber: Arc<dyn RunTerminalSubscriber>) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<RunTerminalNotice>(128);
        let worker = std::thread::spawn(move || {
            while let Ok(notice) = receiver.recv() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    subscriber.on_run_terminal(notice)
                }));
            }
        });
        Self {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
        }
    }
    pub(crate) fn enqueue(&self, notice: RunTerminalNotice) {
        if let Ok(sender) = self.sender.lock()
            && let Some(sender) = sender.as_ref()
        {
            let _ = sender.try_send(notice);
        }
    }
    pub(crate) fn close_and_join(&self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}
impl Drop for TerminalDelivery {
    fn drop(&mut self) {
        self.close_and_join();
    }
}
