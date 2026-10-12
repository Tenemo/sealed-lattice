use super::{
    super::{prime_count_bounds, primes, shared},
    Ciphertext, DEGREE, Engine, Instruction, MEMORY_BYTES, Profile, Progress, Refusal, capacity,
    evictions, helper_memory_bytes, helpers_reserved_bytes, peak_values, stored_bytes, value_bytes,
};
use parallel_work::JOB_MEMORY_BYTES;
use std::collections::BTreeSet;

// The peak counts the values alive at each instruction: those defined
// no later and last used no earlier, where the final value lives to the
// end. Programs of pseudorandom shape, repeated inputs and one hand
// count check it.
#[test]
fn peak_values_are_the_most_overlapping_lifetimes() {
    let check = |inputs: &[Vec<usize>]| {
        let instructions: Vec<Instruction> = inputs
            .iter()
            .map(|inputs| Instruction {
                operation: 1,
                inputs: inputs.clone(),
                parameter: 0,
            })
            .collect();
        let count = inputs.len();
        let mut uses = vec![0; count];
        let mut last = (0..count).collect::<Vec<_>>();
        for (index, inputs) in inputs.iter().enumerate() {
            for input in inputs {
                uses[*input] += 1;
                last[*input] = index;
            }
        }
        uses[count - 1] = 1;
        last[count - 1] = count;
        let overlapping = (0..count)
            .map(|step| (0..=step).filter(|value| last[*value] >= step).count())
            .max()
            .unwrap();
        let peak = peak_values(&instructions, uses);
        assert_eq!(peak, overlapping);
        peak
    };
    // Inputs summed as a chain hold at most three values: a sum's two
    // inputs beside the sum itself.
    assert_eq!(
        check(&[
            vec![],
            vec![],
            vec![0, 1],
            vec![],
            vec![2, 3],
            vec![],
            vec![4, 5]
        ]),
        3
    );
    // A value squared and then used again stays beside its square and
    // the last product.
    assert_eq!(check(&[vec![], vec![0, 0], vec![1, 0]]), 3);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    for _ in 0..200 {
        let count = 2 + next(60);
        let mut inputs = vec![Vec::new()];
        let mut unused: BTreeSet<usize> = BTreeSet::from([0]);
        for index in 1..count {
            let arity = if index == count - 1 { 1 } else { next(3) };
            let mut chosen = Vec::new();
            for _ in 0..arity {
                // Each earlier value is used at least once.
                let input = match unused.iter().next() {
                    Some(first) if next(2) == 0 => *first,
                    _ => next(index),
                };
                unused.remove(&input);
                chosen.push(input);
            }
            inputs.push(chosen);
            unused.insert(index);
        }
        let last = inputs.len() - 1;
        inputs[last].extend(unused.iter().copied().filter(|value| *value != last));
        check(&inputs);
    }
}

// The prime counts the helper bound assumes cover every profile's
// primes, helpers that share the primes need less evaluation memory
// each, and every bound is whole pages, as a helper's memory bound must
// be.
#[test]
fn helper_evaluation_memory_covers_every_profile_in_whole_pages() {
    for profile in Profile::all() {
        let (primes, _, external_primes) = primes(profile, DEGREE);
        let (tensor_bound, external_bound) = prime_count_bounds(profile, DEGREE);
        assert!(primes.len() <= tensor_bound && external_primes <= external_bound);
    }
    let bounds: Vec<usize> = (1..=8).map(helper_memory_bytes).collect();
    assert!(bounds.iter().all(|bytes| bytes.is_multiple_of(65_536)));
    assert!(bounds.windows(2).all(|pair| pair[1] <= pair[0]));
    assert!(bounds[7] < bounds[0]);
}

// With up to eight helpers, each representative profile keeps room for
// an instruction's two inputs and its output at every kind of
// instruction, and each evaluation job a helper runs fits one job's
// memory.
#[test]
fn every_profile_keeps_room_for_an_instruction_with_eight_helpers() {
    for (participants, options) in [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)] {
        let arithmetic = shared(Profile::new(participants, options).unwrap(), DEGREE);
        for helpers in 0..=8 {
            for operation in [1, 2, 4, 6] {
                assert!(capacity(&arithmetic, operation, helpers, usize::MAX).unwrap() >= 3);
            }
            assert!(helpers == 0 || arithmetic.job_bytes(helpers) <= JOB_MEMORY_BYTES);
        }
    }
}

// An instance bound below what the helpers leave of the planning target
// caps the resident values of every kind of instruction: the smallest
// bound that allows three values allows two a byte lower, each further
// value takes one value's bytes more, a bound that holds only the
// reserves allows none and one a byte lower is refused, and a bound at
// what the helpers leave changes nothing.
#[test]
fn the_instance_bound_caps_the_resident_values() {
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let arithmetic = shared(Profile::new(participants, options).unwrap(), DEGREE);
        let value = value_bytes(&arithmetic);
        for helpers in [0, 3, 8] {
            let left = MEMORY_BYTES - helpers_reserved_bytes(&arithmetic, helpers);
            for operation in [1, 2, 4, 6] {
                let at = |bound| capacity(&arithmetic, operation, helpers, bound);
                assert_eq!(at(left), at(usize::MAX));
                let (mut low, mut high) = (0, left);
                while low < high {
                    let middle = (low + high) / 2;
                    if at(middle).is_ok_and(|values| values >= 3) {
                        high = middle;
                    } else {
                        low = middle + 1;
                    }
                }
                assert_eq!(at(low), Ok(3));
                assert_eq!(at(low - 1), Ok(2));
                assert_eq!(at(low + value), Ok(4));
                assert_eq!(at(low + value - 1), Ok(3));
                assert_eq!(at(low - 3 * value), Ok(0));
                assert_eq!(at(low - 3 * value - 1), Err(Refusal::Allocation));
            }
        }
    }
}

// A spilled value's readback must repeat the resident value's words: a
// changed word at either end of either component refuses it and leaves
// the value resident, and the repeated bytes retire it under the
// identity its reload must then have.
#[test]
fn a_readback_repeats_the_resident_value_and_keys_its_reload() {
    let profile = Profile::new(3, 2).unwrap();
    // Three inputs, the sum of the first two, and that sum plus the third.
    let unused = u32::MAX;
    let mut program = [b"BRK1".as_slice(), &(DEGREE as u32).to_le_bytes()].concat();
    program.extend([5_u32, 4].iter().flat_map(|word| word.to_le_bytes()));
    for instruction in [
        [0, unused, unused, 0],
        [0, unused, unused, 1],
        [0, unused, unused, 2],
        [1, 0, 1, 0],
        [1, 3, 2, 0],
    ] {
        program.extend(instruction.iter().flat_map(|word| word.to_le_bytes()));
    }
    let mut engine = Engine::new(profile, &program).unwrap();
    // The smallest instance bound that holds an addition's two inputs
    // and its output.
    let arithmetic = shared(profile, DEGREE);
    let at = |bound| capacity(&arithmetic, 1, parallel_work::helpers(), bound);
    let (mut low, mut high) = (0, usize::MAX);
    while low < high {
        let middle = low + (high - low) / 2;
        if at(middle).is_ok_and(|values| values >= 3) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert_eq!(at(low), Ok(3));
    engine.bound_instance(low);
    let values: Vec<Ciphertext> = (1..=3)
        .map(|position| {
            let mut value = engine.zero_value();
            value[0][0] = position;
            value[1][0] = position + 3;
            value
        })
        .collect();
    for (position, value) in values.iter().enumerate() {
        let required = engine.requirements().unwrap();
        assert!(required.spills.is_empty() && required.reloads.is_empty());
        assert_eq!(required.input_position, Some(position));
        engine.load_input(position, value.clone()).unwrap();
        assert!(matches!(engine.execute(), Ok(Progress::Executed(_))));
    }
    // The addition keeps its inputs and needs room for its output, so the
    // third input, used last, is spilled.
    let required = engine.requirements().unwrap();
    assert_eq!((required.spills, required.reloads), (vec![2], vec![]));
    let stored = stored_bytes(&values[2]);
    let half = stored.len() / 2;
    let read_back = |engine: &mut Engine, bytes: &[u8]| {
        let mut read = engine.begin_readback(2).unwrap();
        // Pieces that split the first component and cross into the
        // second.
        for piece in [&bytes[..8], &bytes[8..half + 8], &bytes[half + 8..]] {
            engine.push_read(&mut read, piece).unwrap();
        }
        engine.finish_read(read)
    };
    for position in [0, half - 8, half, stored.len() - 8] {
        let mut changed = stored.clone();
        changed[position] ^= 1;
        assert_eq!(read_back(&mut engine, &changed), Err(Refusal::Identity));
        assert_eq!(engine.value(2), Ok(&values[2]));
    }
    read_back(&mut engine, &stored).unwrap();
    assert_eq!(engine.value(2), Err(Refusal::Phase));
    // The addition, then the reload the final sum needs.
    assert!(matches!(engine.execute(), Ok(Progress::Executed(_))));
    let required = engine.requirements().unwrap();
    assert_eq!((required.spills, required.reloads), (vec![], vec![2]));
    let reload = |engine: &mut Engine, bytes: &[u8]| {
        let mut read = engine.begin_reload(2).unwrap();
        engine.push_read(&mut read, bytes).unwrap();
        engine.finish_read(read)
    };
    let mut changed = stored.clone();
    changed[half] ^= 1;
    assert_eq!(reload(&mut engine, &changed), Err(Refusal::Identity));
    reload(&mut engine, &stored).unwrap();
    assert_eq!(engine.value(2), Ok(&values[2]));
    assert!(matches!(engine.execute(), Ok(Progress::Executed(_))));
    assert!(engine.finished());
}

#[test]
fn a_reloaded_value_evicted_again_is_dropped_rather_than_written() {
    // Four resident values, room for three and one more needed: the two
    // with the farthest next uses leave. Value 1 still has its stored
    // copy, so only value 2 is written.
    let next_use = |index: usize| [5, 9, 7, 6][index];
    assert_eq!(
        evictions(
            vec![0, 1, 2, 3],
            &BTreeSet::from([0]),
            1,
            3,
            next_use,
            |index| index == 1
        ),
        Ok((vec![2], vec![1]))
    );
    assert_eq!(
        evictions(
            vec![0, 1, 2, 3],
            &BTreeSet::from([0]),
            1,
            3,
            next_use,
            |_| false
        ),
        Ok((vec![1, 2], vec![]))
    );
}

#[test]
fn a_fitting_step_evicts_nothing_and_inputs_are_never_evicted() {
    assert_eq!(
        evictions(vec![0, 1], &BTreeSet::new(), 1, 3, |_| 0, |_| false),
        Ok((vec![], vec![]))
    );
    // Equal next uses evict the larger index first.
    assert_eq!(
        evictions(vec![0, 1, 2], &BTreeSet::new(), 1, 3, |_| 4, |_| false),
        Ok((vec![2], vec![]))
    );
    assert_eq!(
        evictions(
            vec![0, 1, 2],
            &BTreeSet::from([0, 1, 2]),
            1,
            3,
            |_| 0,
            |_| true
        ),
        Err(Refusal::Allocation)
    );
}
