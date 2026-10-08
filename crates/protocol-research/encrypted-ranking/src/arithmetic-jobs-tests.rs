use super::*;

const TEST_DEGREE: usize = 16;

// The polynomials kept for any session where the job runs.
static KEPT_COUNT: Job = Job {
    kind: 0x03ff,
    run: kept_count,
};
fn kept_count(_: &[u8]) -> Vec<u8> {
    KEPT.with(|kept| (kept.borrow().len() as u32).to_le_bytes().to_vec())
}
// The polynomials kept where each helper, or without helpers this
// thread, runs its jobs, after the jobs submitted before.
fn kept_everywhere() -> usize {
    (0..parallel_work::helpers().max(1))
        .map(|helper| {
            let output = submit(&KEPT_COUNT, Some(helper), &[], 4).wait();
            u32::from_le_bytes(output[..].try_into().unwrap()) as usize
        })
        .sum()
}

fn context(ordinal: usize) -> RecordContext {
    RecordContext {
        program: [7; 64],
        cache: 0,
        ordinal,
    }
}
// A keyed product takes exactly the records it requests, in order, and
// refuses records whose identities differ from the held ones: a changed
// record of either group, and a record of another prime or key. Its
// digits and a product's sources are dropped after their last use, and a
// refused product's digits where they are kept.
#[test]
fn keyed_products_take_only_the_held_records_and_keep_nothing() {
    let profile = Profile::new(3, 2).unwrap();
    let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
    let gadget_length = arithmetic.gadget_length;
    let value = arithmetic.uniform(1);
    let keys: Vec<Polynomial> = (0..KEYED_GROUPS * gadget_length)
        .map(|ordinal| arithmetic.uniform(100 + ordinal as u64))
        .collect();
    let held = arithmetic.held_records(&keys.iter().collect::<Vec<_>>(), context(0));
    let run = |held: &HeldRecords| {
        arithmetic.run_keyed(arithmetic.keyed_product(&value, context(0)), held)
    };
    let expected = run(&held).unwrap();
    // The same records in another run give the same sums.
    assert_eq!(run(&held).unwrap(), expected);
    let (identities, records) = &held;
    let mut product = arithmetic.keyed_product(&value, context(0));
    let Keyed::Records(request) = arithmetic.advance_keyed(&mut product, identities).unwrap()
    else {
        panic!("A keyed product needs records first.");
    };
    assert_eq!(
        request,
        RecordRequest {
            first: 0,
            count: gadget_length,
            prime: 0
        }
    );
    // Another key, another prime or a short record is refused.
    assert!(!arithmetic.deliver_record(&mut product, 1, 0, &records[1][0]));
    assert!(!arithmetic.deliver_record(&mut product, 0, 1, &records[0][1]));
    assert!(!arithmetic.deliver_record(&mut product, 0, 0, &records[0][0][8..]));
    // A changed record, another prime's record and swapped keys' records
    // differ from the held identities.
    let mut changed = held.clone();
    changed.1[0][0][5] ^= 1;
    assert!(run(&changed).is_err());
    let mut changed = held.clone();
    changed.1[1][0] = changed.1[1][1].clone();
    assert!(run(&changed).is_err());
    let mut changed = held.clone();
    changed.1.swap(2, 3);
    assert!(run(&changed).is_err());
    let mut changed = held.clone();
    changed.1[gadget_length][1][5] ^= 1;
    assert!(run(&changed).is_err());
    // Records of the largest words, which no transformed residue has,
    // at every digit of one prime still sum without overflow and differ
    // from their identities.
    let mut changed = held.clone();
    for records in changed.1.iter_mut().take(gadget_length) {
        records[0].fill(u8::MAX);
    }
    assert!(run(&changed).is_err());
    assert_eq!(kept_everywhere(), 0);
    assert_eq!(run(&held).unwrap(), expected);
    arithmetic.multiply(&value, &arithmetic.uniform(2), true);
    let square = [value.clone(), arithmetic.uniform(3)];
    arithmetic.tensors(&square, &square);
    arithmetic.tensors(&square, &[arithmetic.uniform(4), arithmetic.uniform(5)]);
    assert_eq!(kept_everywhere(), 0);
}

// A request's records that the host shared itself give the delivered
// records' sums. Only the pending request's whole records are taken,
// never beside a record delivered one at a time, and a changed record
// among them differs from the held identity.
#[test]
fn shared_records_give_the_delivered_records_sums() {
    let profile = Profile::new(3, 2).unwrap();
    let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
    let gadget_length = arithmetic.gadget_length;
    let value = arithmetic.uniform(1);
    let keys: Vec<Polynomial> = (0..KEYED_GROUPS * gadget_length)
        .map(|ordinal| arithmetic.uniform(100 + ordinal as u64))
        .collect();
    let held = arithmetic.held_records(&keys.iter().collect::<Vec<_>>(), context(0));
    let expected = arithmetic
        .run_keyed(arithmetic.keyed_product(&value, context(0)), &held)
        .unwrap();
    let (identities, records) = &held;
    let joined = |request: RecordRequest| -> Vec<u8> {
        records[request.first..request.first + request.count]
            .iter()
            .flat_map(|record| record[request.prime].iter().copied())
            .collect()
    };
    let run = |changed: Option<usize>| -> Result<[Polynomial; KEYED_GROUPS], ()> {
        let mut product = arithmetic.keyed_product(&value, context(0));
        let mut index = 0;
        loop {
            match arithmetic.advance_keyed(&mut product, identities)? {
                Keyed::Done(sums) => {
                    return Ok(sums.map(|sums| arithmetic.lifted(&sums, Lifted::External)));
                }
                Keyed::Waiting(_) => {}
                Keyed::Records(request) => {
                    let mut bytes = joined(request);
                    if changed == Some(index) {
                        bytes[8 * TEST_DEGREE + 3] ^= 1;
                    }
                    assert!(arithmetic.deliver_shared_records(
                        &mut product,
                        request,
                        share(Zeroizing::new(bytes))
                    ));
                    index += 1;
                }
            }
        }
    };
    assert_eq!(run(None).unwrap(), expected);
    assert!(run(Some(3)).is_err());
    let mut product = arithmetic.keyed_product(&value, context(0));
    let Keyed::Records(request) = arithmetic.advance_keyed(&mut product, identities).unwrap()
    else {
        panic!("A keyed product needs records first.");
    };
    let other = RecordRequest {
        prime: request.prime + 1,
        ..request
    };
    assert!(!arithmetic.deliver_shared_records(
        &mut product,
        other,
        share(Zeroizing::new(joined(other)))
    ));
    let mut short = joined(request);
    short.pop();
    assert!(!arithmetic.deliver_shared_records(
        &mut product,
        request,
        share(Zeroizing::new(short))
    ));
    let mut long = joined(request);
    long.push(0);
    assert!(!arithmetic.deliver_shared_records(&mut product, request, share(Zeroizing::new(long))));
    assert!(arithmetic.deliver_record(
        &mut product,
        request.first,
        request.prime,
        &records[request.first][request.prime]
    ));
    assert!(!arithmetic.deliver_shared_records(
        &mut product,
        request,
        share(Zeroizing::new(joined(request)))
    ));
    drop(product);
    assert_eq!(kept_everywhere(), 0);
}

// A product whose every job has requested its records has no request
// left, so it refuses another record.
#[test]
fn a_product_past_its_last_request_refuses_a_record() {
    let profile = Profile::new(3, 2).unwrap();
    let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
    let mut product = arithmetic.keyed_product(&arithmetic.uniform(1), context(0));
    product.requested = KEYED_GROUPS * arithmetic.external_primes;
    assert!(!arithmetic.deliver_record(&mut product, 0, 0, &[0; 8 * TEST_DEGREE]));
}

// A keyed product's jobs name every prime's two groups once, each
// prime's first group before its second, and any run of as many jobs
// as there are helpers within a batch's group runs on that many
// helpers, where each prime's groups in turn would leave most idle.
#[test]
fn keyed_jobs_name_each_group_once_and_occupy_every_helper() {
    for helpers in 0..=parallel_work::MAXIMUM_HELPERS {
        let stride = helpers.max(1);
        for primes in 1..=40 {
            let jobs: Vec<_> = (0..KEYED_GROUPS * primes)
                .map(|index| keyed_job(index, primes, helpers))
                .collect();
            let mut seen = vec![[None; KEYED_GROUPS]; primes];
            for (index, &(prime, group)) in jobs.iter().enumerate() {
                assert!(prime < primes && group < KEYED_GROUPS);
                assert!(seen[prime][group].replace(index).is_none());
            }
            assert!(seen.iter().all(|groups| groups[0] < groups[1]));
            for first in (0..primes).step_by(stride) {
                let held = stride.min(primes - first);
                for group in 0..KEYED_GROUPS {
                    let start = KEYED_GROUPS * first + group * held;
                    let mut helpers_used: Vec<_> = jobs[start..start + held]
                        .iter()
                        .map(|(prime, _)| prime % stride)
                        .collect();
                    helpers_used.sort_unstable();
                    helpers_used.dedup();
                    assert_eq!(helpers_used.len(), held);
                }
            }
            if helpers <= 1 {
                assert!(
                    jobs.iter()
                        .enumerate()
                        .all(|(index, &job)| job == (index / KEYED_GROUPS, index % KEYED_GROUPS))
                );
            }
        }
    }
}

// At the full degree each set job's output stays within the job bound,
// which one more prime in a set would exceed, for every supported
// profile's prime counts and every helper count. Every prime lies in one
// set, on its helper, and a helper's primes split only beyond a set's.
#[test]
fn prime_sets_keep_each_set_job_within_the_job_bound() {
    let degree = supported_profile::DEGREE;
    let held = set_primes(degree);
    let record = IDENTITY_BYTES + 8 * degree;
    assert!(held * record <= MAXIMUM_JOB_BYTES && (held + 1) * record > MAXIMUM_JOB_BYTES);
    let most = Profile::all()
        .map(|profile| {
            let (tensor, external) = super::super::prime_count_bounds(profile, degree);
            tensor.max(external)
        })
        .max()
        .unwrap();
    for helpers in 0..=parallel_work::MAXIMUM_HELPERS {
        let stride = helpers.max(1);
        for count in 1..=most.max(3 * held) {
            let sets = prime_sets(count, degree, helpers);
            let mut seen = vec![false; count];
            for set in &sets {
                assert!((1..=held).contains(&set.len()));
                for prime in set.primes() {
                    assert!(!std::mem::replace(&mut seen[prime], true));
                    assert_eq!(prime % stride, set.first % stride);
                }
            }
            assert!(seen.into_iter().all(|seen| seen));
            let expected: usize = (0..stride.min(count))
                .map(|class| (class..count).step_by(stride).count().div_ceil(held))
                .sum();
            assert_eq!(sets.len(), expected);
        }
    }
}

// At the full degree every supported profile's job inputs stay within
// the job bound: a key's record job, its set's header and the record
// context beside the streamed key polynomial, which is the largest, a
// keyed job beside its streamed group of records, and a lift range's
// residues modulo every tensor prime. The record job of the profile
// with the longest coefficients runs.
#[test]
fn job_inputs_stay_within_the_job_bound_at_the_full_degree() {
    let degree = supported_profile::DEGREE;
    let longest = Profile::all()
        .max_by_key(|profile| profile.ciphertext_modulus().bits())
        .unwrap();
    for profile in Profile::all() {
        let arithmetic = Arithmetic::new(profile, degree);
        let set = prime_sets(arithmetic.external_primes, degree, 0)[0];
        let header = arithmetic.header(0).len();
        let record = arithmetic.set_header(set).len()
            + RecordContext::BYTES
            + 8 * arithmetic.polynomial_words();
        let keyed = header + 12 + RecordContext::BYTES + arithmetic.gadget_length * 8 * degree;
        let lift = header + 4 + 8 * LIFT_POSITIONS * arithmetic.tensor_primes();
        assert!(record.max(keyed).max(lift) <= MAXIMUM_JOB_BYTES);
        if profile == longest {
            let (_, records) = arithmetic.key_records(&arithmetic.uniform(1), context(0));
            assert_eq!(records.len(), arithmetic.external_primes);
            assert!(records.iter().all(|record| record.len() == 8 * degree));
        }
    }
}
