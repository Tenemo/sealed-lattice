//! Helpers simulated by native threads, which let native tests run every
//! job through the path the browser module takes with helpers. The
//! `SEALED_LATTICE_SIMULATED_HELPERS` environment variable names their
//! count; without it native code runs every job itself. Each thread that
//! submits jobs gets its own helpers, as each operation's worker does, and
//! a helper's thread-local state stands for a helper instance's memory. A
//! job pinned to a helper runs there after that helper's earlier jobs, and
//! a helper whose job panicked fails every later job, as a trapped instance
//! does.
use crate::{Job, MAXIMUM_HELPERS};
use std::{
    cell::{Cell, OnceCell},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
};
use zeroize::Zeroizing;

const VARIABLE: &str = "SEALED_LATTICE_SIMULATED_HELPERS";

/// A submitted job's end: its output of the declared length, or a failure.
pub(crate) struct Slot {
    state: Mutex<Option<Option<Zeroizing<Vec<u8>>>>>,
    ended: Condvar,
}
impl Slot {
    fn end(&self, output: Option<Zeroizing<Vec<u8>>>) {
        *self.state.lock().unwrap() = Some(output);
        self.ended.notify_all();
    }
    /// The job's output, once it has ended.
    pub(crate) fn wait(&self) -> Zeroizing<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(output) = state.take() {
                return output.expect("A helper failed");
            }
            state = self.ended.wait(state).unwrap();
        }
    }
}

struct Message {
    job: &'static Job,
    input: Zeroizing<Vec<u8>>,
    streamed: Option<Zeroizing<Vec<u8>>>,
    output_length: usize,
    slot: Arc<Slot>,
}

// Dropping the queues ends each helper after its queued jobs. The helpers
// are not joined: Windows runs a thread's destructors under the loader lock,
// which a helper's own exit needs.
struct Simulator {
    queues: Vec<mpsc::Sender<Message>>,
    next: Cell<usize>,
}

thread_local! {
    static SIMULATOR: OnceCell<Option<Simulator>> = const { OnceCell::new() };
    // A helper has no helpers of its own.
    static IS_HELPER: Cell<bool> = const { Cell::new(false) };
}

fn run(queue: mpsc::Receiver<Message>) {
    IS_HELPER.with(|is_helper| is_helper.set(true));
    let mut trapped = false;
    for message in queue {
        let output = if trapped {
            None
        } else {
            match catch_unwind(AssertUnwindSafe(|| {
                crate::run_streaming(
                    message.job,
                    &message.input,
                    message.streamed.as_deref().map(Vec::as_slice),
                )
            })) {
                Ok(output) => {
                    (output.len() == message.output_length).then(|| Zeroizing::new(output))
                }
                Err(_) => {
                    trapped = true;
                    None
                }
            }
        };
        message.slot.end(output);
    }
}

fn start() -> Option<Simulator> {
    let value = std::env::var_os(VARIABLE)?;
    let count = value
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| (1..=MAXIMUM_HELPERS).contains(count))
        .expect("The simulated helpers number one to eight");
    let queues = (0..count)
        .map(|_| {
            let (sender, receiver) = mpsc::channel();
            thread::spawn(move || run(receiver));
            sender
        })
        .collect();
    Some(Simulator {
        queues,
        next: Cell::new(0),
    })
}

fn with<T>(use_simulator: impl FnOnce(Option<&Simulator>) -> T) -> T {
    if IS_HELPER.with(Cell::get) {
        return use_simulator(None);
    }
    SIMULATOR.with(|simulator| use_simulator(simulator.get_or_init(start).as_ref()))
}

/// The simulated helpers of this thread, zero when there are none.
pub(crate) fn helpers() -> usize {
    with(|simulator| simulator.map_or(0, |simulator| simulator.queues.len()))
}

/// Starts the job on the helper the nonzero pin names, else on the next
/// helper in turn.
pub(crate) fn submit(
    job: &'static Job,
    pin: usize,
    input: Zeroizing<Vec<u8>>,
    streamed: Option<Zeroizing<Vec<u8>>>,
    output_length: usize,
) -> Arc<Slot> {
    with(|simulator| {
        let simulator = simulator.expect("No helpers are simulated");
        let count = simulator.queues.len();
        let helper = if pin == 0 {
            let next = simulator.next.get();
            simulator.next.set((next + 1) % count);
            next
        } else {
            pin - 1
        };
        let slot = Arc::new(Slot {
            state: Mutex::new(None),
            ended: Condvar::new(),
        });
        simulator.queues[helper]
            .send(Message {
                job,
                input,
                streamed,
                output_length,
                slot: Arc::clone(&slot),
            })
            .expect("A simulated helper ended");
        slot
    })
}
