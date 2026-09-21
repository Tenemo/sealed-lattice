use std::collections::VecDeque;
use zeroize::{Zeroize, Zeroizing};

const RECORD_BYTES: usize = crate::CHUNK_LIMIT;
const REQUEST_BYTES: usize = 65_536;
// The queue shares the participant's existing absolute linear-memory ceiling.
// Its actual finite budget comes from the authenticated worker descriptor.
const MAXIMUM_BYTES: usize = 671_088_640;

struct Journal {
    total: usize,
    loaded: usize,
    consumed: usize,
    offset: usize,
    records: VecDeque<Zeroizing<Vec<u8>>>,
}

struct State {
    input: Zeroizing<Vec<u8>>,
    output: Zeroizing<Vec<u8>>,
    journal: Option<Journal>,
}
impl State {
    fn new() -> Self {
        Self {
            input: Zeroizing::new(vec![0; RECORD_BYTES]),
            output: Zeroizing::new(vec![0; REQUEST_BYTES]),
            journal: None,
        }
    }
    fn ready(&self) -> bool {
        self.journal
            .as_ref()
            .is_some_and(|journal| journal.loaded == journal.total && journal.consumed == 0)
    }
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        self.output.as_mut_slice().zeroize();
        let result = self.command_inner(operation, length);
        self.input.as_mut_slice().zeroize();
        result
    }
    fn command_inner(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        match operation {
            0 => {
                if self.journal.is_some() || !(1..=MAXIMUM_BYTES).contains(&length) {
                    return Err(());
                }
                self.journal = Some(Journal {
                    total: length,
                    loaded: 0,
                    consumed: 0,
                    offset: 0,
                    records: VecDeque::new(),
                });
            }
            1 => {
                let journal = self.journal.as_mut().ok_or(())?;
                if length == 0
                    || length != RECORD_BYTES.min(journal.total - journal.loaded)
                    || journal.consumed != 0
                {
                    return Err(());
                }
                journal.records.try_reserve(1).map_err(|_| ())?;
                let mut bytes = Zeroizing::new(Vec::new());
                bytes.try_reserve_exact(length).map_err(|_| ())?;
                bytes.extend_from_slice(&self.input[..length]);
                journal.records.push_back(bytes);
                journal.loaded += length;
            }
            2 => {
                let journal = self.journal.as_mut().ok_or(())?;
                if journal.loaded != journal.total
                    || !(1..=REQUEST_BYTES).contains(&length)
                    || length > journal.total - journal.consumed
                {
                    return Err(());
                }
                let mut written = 0;
                while written < length {
                    let record = journal.records.front_mut().ok_or(())?;
                    let count = (length - written).min(record.len() - journal.offset);
                    let source = &mut record[journal.offset..journal.offset + count];
                    self.output[written..written + count].copy_from_slice(source);
                    source.zeroize();
                    journal.offset += count;
                    journal.consumed += count;
                    written += count;
                    if journal.offset == record.len() {
                        journal.records.pop_front();
                        journal.offset = 0;
                    }
                }
            }
            3 => {
                if length != 0 {
                    return Err(());
                }
                self.journal = None;
            }
            _ => return Err(()),
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::State;
    use std::cell::RefCell;

    thread_local! {static STATE:RefCell<State>=RefCell::new(State::new());}

    pub fn ready() -> bool {
        STATE.with(|state| state.borrow().ready())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn release_entropy_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn release_entropy_output_pointer() -> usize {
        STATE.with(|state| state.borrow().output.as_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn release_entropy_command(operation: u32, length: usize) -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().command(operation, length).is_err()))
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::ready;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumes_exact_bytes_across_records_and_retires_consumed_storage() {
        let expected: Vec<_> = (0..RECORD_BYTES + 37)
            .map(|index| ((index * 37 + 11) % 251) as u8)
            .collect();
        let mut state = State::new();
        state.command(0, expected.len()).unwrap();
        for record in expected.chunks(RECORD_BYTES) {
            state.input[..record.len()].copy_from_slice(record);
            state.command(1, record.len()).unwrap();
            assert!(state.input.iter().all(|value| *value == 0));
        }
        assert!(state.ready());
        let mut consumed = 0;
        for requested in [1, 17, REQUEST_BYTES - 1, REQUEST_BYTES]
            .into_iter()
            .cycle()
        {
            let length = requested.min(expected.len() - consumed);
            if length == 0 {
                break;
            }
            state.command(2, length).unwrap();
            assert_eq!(
                state.output[..length],
                expected[consumed..consumed + length]
            );
            consumed += length;
            let journal = state.journal.as_ref().unwrap();
            assert_eq!(
                journal.records.len(),
                usize::from(consumed < RECORD_BYTES) + usize::from(consumed < expected.len())
            );
            assert!(!state.ready());
        }
        assert_eq!(consumed, expected.len());
        assert!(state.command(2, 1).is_err());
        assert!(state.output.iter().all(|value| *value == 0));
        assert!(state.command(0, 1).is_err());
        state.command(3, 0).unwrap();
        assert!(state.journal.is_none());
    }

    #[test]
    fn refuses_incomplete_oversized_and_reordered_entropy_operations() {
        let mut state = State::new();
        for length in [0, MAXIMUM_BYTES + 1, usize::MAX] {
            assert!(state.command(0, length).is_err());
        }
        for operation in [1, 2, 99] {
            assert!(state.command(operation, 1).is_err());
        }
        state.command(0, RECORD_BYTES + 1).unwrap();
        assert!(state.command(2, 1).is_err());
        assert!(state.command(1, RECORD_BYTES - 1).is_err());
        assert!(state.command(1, RECORD_BYTES + 1).is_err());
        state.input.fill(7);
        state.command(1, RECORD_BYTES).unwrap();
        assert!(!state.ready());
        assert!(state.command(2, 1).is_err());
        state.input[0] = 9;
        state.command(1, 1).unwrap();
        assert!(state.ready());
        for length in [0, REQUEST_BYTES + 1, usize::MAX] {
            assert!(state.command(2, length).is_err());
            assert!(state.ready());
        }
        state.command(2, REQUEST_BYTES).unwrap();
        assert!(state.output.iter().all(|value| *value == 7));
        assert!(state.command(1, 1).is_err());
        assert!(state.command(3, 1).is_err());
        state.command(3, 0).unwrap();
        assert!(state.command(2, 1).is_err());
        state.command(0, 1).unwrap();
        state.input[0] = 31;
        state.command(1, 1).unwrap();
        state.command(2, 1).unwrap();
        assert_eq!(state.output[0], 31);
    }
}
