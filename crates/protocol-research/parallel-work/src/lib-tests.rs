use super::*;
use std::cell::Cell;

fn reverse(input: &[u8]) -> Vec<u8> {
    input.iter().rev().copied().collect()
}
static REVERSE: Job = Job {
    kind: 7,
    run: reverse,
};
thread_local! {static TOTAL: Cell<u8> = const { Cell::new(0) };}
// A shard's job that adds its input to the shard's running total.
fn accumulate(input: &[u8]) -> Vec<u8> {
    TOTAL.with(|total| {
        total.set(
            input
                .iter()
                .fold(total.get(), |sum, value| sum.wrapping_add(*value)),
        );
        vec![total.get()]
    })
}
static ACCUMULATE: Job = Job {
    kind: 8,
    run: accumulate,
};
// Each input byte, then every streamed byte read in pieces of three.
fn stream_back(input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    let length = streamed_length();
    for position in (0..length).step_by(3) {
        let mut piece = vec![0; 3.min(length - position)];
        read(position, &mut piece);
        output.extend(piece);
    }
    output
}
static STREAM_BACK: Job = Job {
    kind: 10,
    run: stream_back,
};
// The streamed part's two-byte records at the indices that the input's
// two-byte words name, read in order through windows over regions of
// three records, then gathered in the indices' reverse order.
fn read_records(input: &[u8]) -> Vec<u8> {
    let indices: Vec<usize> = input
        .chunks_exact(2)
        .map(|pair| usize::from(u16::from_le_bytes([pair[0], pair[1]])))
        .collect();
    let mut records = StreamedRecords::new(2, 3);
    let mut output: Vec<u8> = indices
        .iter()
        .flat_map(|index| records.record(*index).to_vec())
        .collect();
    let mut gathered = vec![[0; 2]; indices.len()];
    gather(
        2,
        indices.len(),
        |position| indices[indices.len() - 1 - position],
        |position, record| gathered[position].copy_from_slice(record),
    );
    output.extend(gathered.into_iter().flatten());
    output
}
static READ_RECORDS: Job = Job {
    kind: 12,
    run: read_records,
};
// Reads one byte beyond the streamed part.
fn read_beyond(_: &[u8]) -> Vec<u8> {
    let mut byte = [0];
    read(streamed_length(), &mut byte);
    byte.to_vec()
}
static READ_BEYOND: Job = Job {
    kind: 11,
    run: read_beyond,
};
fn oversized(_: &[u8]) -> Vec<u8> {
    vec![0; MAXIMUM_JOB_BYTES + 1]
}
static OVERSIZED: Job = Job {
    kind: 9,
    run: oversized,
};

#[test]
fn outputs_join_parts_and_follow_each_shard() {
    let shared = share(Zeroizing::new(vec![4, 5]));
    let first = submit(&REVERSE, None, &[Part::Bytes(&[1, 2, 3])], 3);
    let second = submit(
        &REVERSE,
        None,
        &[
            Part::Shared(&shared),
            Part::Bytes(&[]),
            Part::Shared(&shared),
        ],
        4,
    );
    assert_eq!(second.wait().to_vec(), [5, 4, 5, 4]);
    assert_eq!(first.wait().to_vec(), [3, 2, 1]);
    let totals: Vec<u8> = [[1, 2], [3, 4]]
        .iter()
        .map(|input| submit(&ACCUMULATE, Some(3), &[Part::Bytes(input)], 1).wait()[0])
        .collect();
    assert_eq!(totals, [3, 10]);
}

#[test]
fn streamed_parts_join_no_input_and_are_read_in_pieces_within_their_bound() {
    let streamed = share_words(&[0x0807_0605_0403_0201, 0x0a09]);
    let shared = share(Zeroizing::new(vec![20, 21]));
    let output = submit(
        &STREAM_BACK,
        Some(2),
        &[
            Part::Bytes(&[30]),
            Part::Streamed(&streamed),
            Part::Shared(&shared),
        ],
        19,
    )
    .wait();
    assert_eq!(
        output.to_vec(),
        [30, 20, 21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0]
    );
    // A read beyond the part fails the job, and a job streams at most
    // one part.
    assert!(
        std::panic::catch_unwind(
            || submit(&READ_BEYOND, None, &[Part::Streamed(&shared)], 1).wait()
        )
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| submit(
            &STREAM_BACK,
            None,
            &[Part::Streamed(&shared), Part::Streamed(&shared)],
            4
        ))
        .is_err()
    );
    // A job without a streamed part cannot read one.
    assert!(std::panic::catch_unwind(|| submit(&READ_BEYOND, None, &[], 1).wait()).is_err());
}

#[test]
fn streamed_records_read_through_windows_or_gathered_by_chunk_equal_the_part() {
    // Twenty thousand records, each its index's two bytes, which a
    // gather reads in three chunks.
    let part: Vec<u8> = (0..20_000_u16).flat_map(u16::to_le_bytes).collect();
    let streamed = share(Zeroizing::new(part));
    // Forward and backward within and across regions and chunks.
    let indices = [0_u16, 1, 4, 3, 19_999, 2, 2, 8_200, 16_384, 8_191, 0];
    let input: Vec<u8> = indices
        .iter()
        .flat_map(|index| index.to_le_bytes())
        .collect();
    let mut expected = input.clone();
    expected.extend(indices.iter().rev().flat_map(|index| index.to_le_bytes()));
    let output = submit(
        &READ_RECORDS,
        None,
        &[Part::Bytes(&input), Part::Streamed(&streamed)],
        2 * input.len(),
    )
    .wait();
    assert_eq!(output.to_vec(), expected);
    // A record beyond the part fails the job, and the records' width
    // must divide the part.
    assert!(
        std::panic::catch_unwind(|| submit(
            &READ_RECORDS,
            None,
            &[
                Part::Bytes(&20_000_u16.to_le_bytes()),
                Part::Streamed(&streamed)
            ],
            4
        )
        .wait())
        .is_err()
    );
    let odd = share(Zeroizing::new(vec![1, 2, 3]));
    assert!(
        std::panic::catch_unwind(|| submit(
            &READ_RECORDS,
            None,
            &[Part::Bytes(&[0, 0]), Part::Streamed(&odd)],
            4
        )
        .wait())
        .is_err()
    );
}

#[test]
fn refuses_undeclared_lengths_and_oversized_jobs() {
    // A job with helpers fails when its output is taken.
    for length in [1, 3] {
        assert!(
            std::panic::catch_unwind(
                || submit(&REVERSE, None, &[Part::Bytes(&[1, 2])], length).wait()
            )
            .is_err()
        );
    }
    let large = vec![0; MAXIMUM_JOB_BYTES / 2 + 1];
    assert!(
        std::panic::catch_unwind(|| submit(
            &REVERSE,
            None,
            &[Part::Bytes(&large), Part::Bytes(&large)],
            0
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| submit(&REVERSE, None, &[], MAXIMUM_JOB_BYTES + 1)).is_err()
    );
    let parts: Vec<Part> = (0..=MAXIMUM_JOB_PARTS).map(|_| Part::Bytes(&[])).collect();
    assert!(std::panic::catch_unwind(|| submit(&REVERSE, None, &parts, 0)).is_err());
    assert!(
        std::panic::catch_unwind(|| share(Zeroizing::new(vec![0; MAXIMUM_JOB_BYTES + 1]))).is_err()
    );
}

#[test]
fn pipelines_keep_submission_order() {
    for (count, window) in [(0, 1), (1, 0), (2, 1), (5, 2), (5, 8)] {
        let mut pipeline = Pipeline::new(window);
        let mut seen = Vec::new();
        for index in 0..count {
            let ticket = submit(&REVERSE, None, &[Part::Bytes(&[index as u8, 0])], 2);
            seen.extend(pipeline.push(index, ticket));
        }
        seen.extend(pipeline.finish());
        assert_eq!(
            seen.into_iter()
                .map(|(index, output)| (index, output.to_vec()))
                .collect::<Vec<_>>(),
            (0..count)
                .map(|index| (index, vec![0, index as u8]))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn helpers_run_listed_kinds_within_the_bounds() {
    let jobs: [&'static Job; 2] = [&REVERSE, &OVERSIZED];
    assert_eq!(helper::input(MAXIMUM_JOB_BYTES + 1), 0);
    let pointer = helper::input(3) as *mut u8;
    unsafe { std::slice::from_raw_parts_mut(pointer, 3) }.copy_from_slice(&[4, 5, 6]);
    assert_eq!(helper::run(&[&jobs], 3), 1);
    assert_eq!(helper::run(&[&[], &jobs], 7), 0);
    assert_eq!(
        unsafe {
            std::slice::from_raw_parts(
                helper::output_pointer() as *const u8,
                helper::output_length(),
            )
        },
        [6, 5, 4]
    );
    helper::clear();
    assert_eq!(helper::output_length(), 0);
    helper::input(0);
    assert_eq!(helper::run(&[&jobs], 9), 0);
    // The host refuses this output, which exceeds any declared length.
    assert_eq!(helper::output_length(), MAXIMUM_JOB_BYTES + 1);
}
