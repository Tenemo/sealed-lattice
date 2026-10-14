use super::{Arithmetic, DEGREE, Profile, Refusal, prime_count_bounds, shared};

/// The planning target for the peak linear memory of the evaluation's
/// instances together, the reserve for the runtime and the module's own
/// state, the reserve for the host's transfer buffers, and the reserve for
/// a helper instance's own state.
pub(super) const MEMORY_BYTES: usize = 402_653_184;
pub(super) const RUNTIME_RESERVE_BYTES: usize = 67_108_864;
pub(super) const TRANSFER_RESERVE_BYTES: usize = 2_097_152;
const HELPER_RESERVE_BYTES: usize = 2_097_152;
/// Each transform owns two tables of a word per coefficient: the forward
/// twiddles and their Shoup companions, from which the backward transform
/// reads its own.
const TRANSFORM_TABLES: usize = 2;
/// The tensor sources a multiplication keeps at once.
const KEPT_SOURCES: usize = 3;

/// The memory a helper keeps for evaluation beside its jobs' own when it
/// holds the given counts of tensor and external-product primes: their
/// transform tables and the transformed polynomials a multiplication keeps
/// there, its tensor sources or one prime's digits, since a helper runs the
/// last keyed job of a prime before the next prime's digits.
pub(super) fn helper_kept_bytes(
    tensor_primes: usize,
    external_primes: usize,
    gadget_length: usize,
) -> usize {
    let residue_bytes = DEGREE * 8;
    tensor_primes * TRANSFORM_TABLES * residue_bytes
        + (KEPT_SOURCES * tensor_primes).max(gadget_length * external_primes.min(1)) * residue_bytes
}

/// The memory a helper instance keeps for evaluation beside its running
/// job's, one of `helpers` helpers that hold the primes in turn, for the
/// profile that needs the most. An instance computes it before its first
/// allocation, so it allocates nothing.
pub fn helper_memory_bytes(helpers: usize) -> usize {
    let held = |count: usize| count.div_ceil(helpers.max(1));
    Profile::all()
        .map(|profile| {
            let (tensor_primes, external_primes) = prime_count_bounds(profile, DEGREE);
            helper_kept_bytes(
                held(tensor_primes),
                held(external_primes),
                profile.gadget_length(),
            )
        })
        .max()
        .unwrap()
}

/// The memory one of the helpers reserves for the evaluation: what it
/// keeps for the primes it holds and one job.
pub(super) fn helper_reserved_bytes(
    arithmetic: &Arithmetic,
    helper: usize,
    helpers: usize,
) -> usize {
    let held = |count: usize| (helper..count).step_by(helpers).count();
    helper_kept_bytes(
        held(arithmetic.tensor_primes()),
        held(arithmetic.external_primes),
        arithmetic.gadget_length,
    ) + arithmetic.job_bytes(helpers)
}

/// What the helpers' instances hold for the evaluation: each one's
/// reservation beside the reserve for its own state.
pub(super) fn helpers_reserved_bytes(arithmetic: &Arithmetic, helpers: usize) -> usize {
    (0..helpers)
        .map(|helper| HELPER_RESERVE_BYTES + helper_reserved_bytes(arithmetic, helper, helpers))
        .sum()
}

/// The fewest resident values that any kind of instruction of the profile's
/// evaluation allows an instance of the bound beside the helpers.
pub fn fewest_resident_values(
    profile: Profile,
    helpers: usize,
    bound: usize,
) -> Result<usize, Refusal> {
    let arithmetic = shared(profile, DEGREE);
    [1, 2, 4, 6]
        .into_iter()
        .try_fold(usize::MAX, |fewest, operation| {
            Ok(fewest.min(capacity(&arithmetic, operation, helpers, bound)?))
        })
}

/// Bytes of one resident working value.
pub(super) fn value_bytes(arithmetic: &Arithmetic) -> usize {
    2 * arithmetic.polynomial_words() * 8
}

/// The memory an instruction of the operation adds in the instance that
/// runs it beside its inputs and output: a multiplication holds three
/// lifted tensors beside one tensor's products, and later two of them
/// beside a keyed product's sums and a delivered group's records; a
/// plaintext product holds the plaintext beside one component's products; a
/// rotation holds its automorphic components, and later one of them beside
/// the same. Each key a keyed instruction loads before it starts holds its
/// polynomial beside its records. With helpers the instance also holds the
/// data it moves for one job beside those. Without them it keeps what they
/// would, since it runs each job as it starts: at most three transformed
/// tensor sources, a plaintext product's copied component and its
/// products' bytes, a keyed product's polynomial and one prime's digits, or
/// a loaded key's copied polynomial.
pub(super) fn scratch_bytes(arithmetic: &Arithmetic, operation: u32, helpers: usize) -> usize {
    let residue_bytes = DEGREE * 8;
    let polynomial_bytes = arithmetic.polynomial_words() * 8;
    let kept = usize::from(helpers == 0);
    let moved = |bytes: usize| usize::from(helpers > 0) * bytes;
    let tensor = 3 * polynomial_bytes
        + (1 + kept * KEPT_SOURCES) * arithmetic.tensor_primes() * residue_bytes
        + moved(arithmetic.transfer_bytes(arithmetic.tensor_primes(), false, helpers));
    let keyed = kept * polynomial_bytes
        + (2 * arithmetic.external_primes + (1 + kept) * arithmetic.gadget_length) * residue_bytes
        + moved(arithmetic.transfer_bytes(arithmetic.external_primes, true, helpers));
    let load = (1 + kept) * polynomial_bytes
        + arithmetic.external_primes * residue_bytes
        + moved(arithmetic.records_transfer_bytes(helpers));
    match operation {
        2 => tensor.max(2 * polynomial_bytes + keyed).max(load),
        4 => {
            (1 + kept) * (polynomial_bytes + arithmetic.key_primes * residue_bytes)
                + moved(arithmetic.transfer_bytes(arithmetic.key_primes, false, helpers))
        }
        6 => (2 * polynomial_bytes)
            .max(polynomial_bytes + keyed)
            .max(load),
        _ => 0,
    }
}

/// The resident values an instruction of the operation allows within the
/// planning target and the bound of the instance that runs it. Without
/// helpers the instance also holds the transform tables and one job; with
/// them each helper holds its reservation at every instruction, since an
/// instance's memory never shrinks, and the instance keeps what they leave
/// of the target.
pub(super) fn capacity(
    arithmetic: &Arithmetic,
    operation: u32,
    helpers: usize,
    bound: usize,
) -> Result<usize, Refusal> {
    let (helpers_hold, instance_holds) = if helpers == 0 {
        (
            0,
            arithmetic.tensor_primes() * TRANSFORM_TABLES * DEGREE * 8 + arithmetic.job_bytes(0),
        )
    } else {
        (helpers_reserved_bytes(arithmetic, helpers), 0)
    };
    let available = MEMORY_BYTES
        .checked_sub(helpers_hold)
        .ok_or(Refusal::Allocation)?
        .min(bound)
        .checked_sub(
            RUNTIME_RESERVE_BYTES
                + TRANSFER_RESERVE_BYTES
                + instance_holds
                + scratch_bytes(arithmetic, operation, helpers),
        )
        .ok_or(Refusal::Allocation)?;
    Ok(available / value_bytes(arithmetic))
}
