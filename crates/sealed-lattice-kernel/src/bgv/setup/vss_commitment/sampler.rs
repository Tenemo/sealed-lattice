use super::message_encoding::*;
use super::*;

#[derive(Clone, Copy)]
pub(in crate::bgv::setup) struct ProjectionTermsInput<'a> {
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) commitment_modulus_index: usize,
    pub(in crate::bgv::setup) output_coordinate_index: usize,
    pub(in crate::bgv::setup) input_column: &'a str,
    pub(in crate::bgv::setup) ring_degree: usize,
    pub(in crate::bgv::setup) modulus: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct ProjectionTermCacheKey {
    public_matrix_seed_hash: String,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: String,
    ring_degree: usize,
    modulus: u64,
}

impl ProjectionTermCacheKey {
    fn from_input(input: ProjectionTermsInput<'_>) -> Self {
        Self {
            public_matrix_seed_hash: input.public_matrix_seed_hash.to_owned(),
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column: input.input_column.to_owned(),
            ring_degree: input.ring_degree,
            modulus: input.modulus,
        }
    }
}

pub(super) type ProjectionTerm = (usize, u64);
pub(super) type ProjectionTermCache = HashMap<ProjectionTermCacheKey, Arc<[ProjectionTerm]>>;

static PROJECTION_TERM_CACHE: OnceLock<Mutex<ProjectionTermCache>> = OnceLock::new();

// Returns the shared cached term slice; callers iterate it in place instead of
// copying the whole row per innermost relation-vector accumulation.
pub(in crate::bgv::setup) fn projection_terms(
    input: ProjectionTermsInput<'_>,
) -> CanonicalResult<Arc<[ProjectionTerm]>> {
    cached_projection_terms(input)
}

pub(super) fn cached_projection_terms(
    input: ProjectionTermsInput<'_>,
) -> CanonicalResult<Arc<[ProjectionTerm]>> {
    let cache_key = ProjectionTermCacheKey::from_input(input);
    let cache = PROJECTION_TERM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached_terms) = cache
        .lock()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS projection-term cache is unavailable",
            )
        })?
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached_terms);
    }

    let term_count = if is_vss_public_message_digit_column_label(input.input_column) {
        vss_public_message_coverage_terms_per_coordinate(input.ring_degree)?
    } else {
        VSS_PUBLIC_RANDOMNESS_PROJECTION_WEIGHT
    };
    let mut terms = Vec::with_capacity(term_count);
    for projection_term_index in 0..term_count {
        let ring_coefficient_index = if is_vss_public_message_digit_column_label(input.input_column)
        {
            let scheduled_index = vss_public_covered_message_ring_coefficient_index(
                input.commitment_modulus_index,
                input.output_coordinate_index,
                projection_term_index,
            )?;
            if scheduled_index >= input.ring_degree {
                continue;
            }
            scheduled_index
        } else {
            sample_projection_index(SampleProjectionInput {
                public_matrix_seed_hash: input.public_matrix_seed_hash,
                rns_limb_index: input.rns_limb_index,
                commitment_modulus_index: input.commitment_modulus_index,
                output_coordinate_index: input.output_coordinate_index,
                input_column: input.input_column,
                projection_term_index,
                ring_degree: input.ring_degree,
            })?
        };
        let matrix_residue = sample_matrix_residue(SampleMatrixInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column: input.input_column,
            projection_term_index,
            modulus: input.modulus,
        })?;
        terms.push((ring_coefficient_index, matrix_residue));
    }
    let computed_terms: Arc<[ProjectionTerm]> = Arc::from(terms.into_boxed_slice());

    let mut cache_guard = cache.lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "VSS projection-term cache is unavailable",
        )
    })?;
    let cached_terms = cache_guard
        .entry(cache_key)
        .or_insert_with(|| Arc::clone(&computed_terms));

    Ok(Arc::clone(cached_terms))
}

pub(super) struct SampleMatrixInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    modulus: u64,
}

pub(super) fn sample_matrix_residue(input: SampleMatrixInput<'_>) -> CanonicalResult<u64> {
    let modulus = u128::from(input.modulus);
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let mut preimage = sampler_preimage_prefix(&input);
        push_sampler_u64_field(&mut preimage, input.modulus);
        push_sampler_usize_field(&mut preimage, block_index);
        let digest = hash512(
            VSS_PUBLIC_MATRIX_RESIDUE_HASH_DOMAIN,
            &[preimage.as_slice()],
        );
        for chunk in digest.chunks_exact(8) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            let value = u128::from(u64::from_le_bytes(bytes));
            if value < limit {
                return Ok((value % modulus) as u64);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS matrix-residue sampler block index overflowed",
            )
        })?;
    }
}

pub(super) struct SampleProjectionInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    ring_degree: usize,
}

pub(super) fn sample_projection_index(input: SampleProjectionInput<'_>) -> CanonicalResult<usize> {
    let modulus = input.ring_degree as u128;
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let mut preimage = sampler_preimage_prefix(&input);
        push_sampler_usize_field(&mut preimage, input.ring_degree);
        push_sampler_usize_field(&mut preimage, block_index);
        let digest = hash512(
            VSS_PUBLIC_PROJECTION_INDEX_HASH_DOMAIN,
            &[preimage.as_slice()],
        );
        for chunk in digest.chunks_exact(8) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            let value = u128::from(u64::from_le_bytes(bytes));
            if value < limit {
                return Ok((value % modulus) as usize);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS projection-index sampler block index overflowed",
            )
        })?;
    }
}

pub(super) trait SamplerInput {
    fn public_matrix_seed_hash(&self) -> &str;
    fn rns_limb_index(&self) -> usize;
    fn commitment_modulus_index(&self) -> usize;
    fn output_coordinate_index(&self) -> usize;
    fn input_column(&self) -> &str;
    fn projection_term_index(&self) -> usize;
}

impl SamplerInput for SampleMatrixInput<'_> {
    fn public_matrix_seed_hash(&self) -> &str {
        self.public_matrix_seed_hash
    }

    fn rns_limb_index(&self) -> usize {
        self.rns_limb_index
    }

    fn commitment_modulus_index(&self) -> usize {
        self.commitment_modulus_index
    }

    fn output_coordinate_index(&self) -> usize {
        self.output_coordinate_index
    }

    fn input_column(&self) -> &str {
        self.input_column
    }

    fn projection_term_index(&self) -> usize {
        self.projection_term_index
    }
}

impl SamplerInput for SampleProjectionInput<'_> {
    fn public_matrix_seed_hash(&self) -> &str {
        self.public_matrix_seed_hash
    }

    fn rns_limb_index(&self) -> usize {
        self.rns_limb_index
    }

    fn commitment_modulus_index(&self) -> usize {
        self.commitment_modulus_index
    }

    fn output_coordinate_index(&self) -> usize {
        self.output_coordinate_index
    }

    fn input_column(&self) -> &str {
        self.input_column
    }

    fn projection_term_index(&self) -> usize {
        self.projection_term_index
    }
}

pub(super) fn sampler_preimage_prefix(input: &impl SamplerInput) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        input.public_matrix_seed_hash().len()
            + VSS_PUBLIC_SAMPLER_DOMAIN.len()
            + input.input_column().len()
            + 96,
    );
    push_sampler_bytes_field(&mut preimage, input.public_matrix_seed_hash().as_bytes());
    push_sampler_bytes_field(&mut preimage, VSS_PUBLIC_SAMPLER_DOMAIN.as_bytes());
    push_sampler_usize_field(&mut preimage, input.rns_limb_index());
    push_sampler_usize_field(&mut preimage, input.commitment_modulus_index());
    push_sampler_usize_field(&mut preimage, input.output_coordinate_index());
    push_sampler_bytes_field(&mut preimage, input.input_column().as_bytes());
    push_sampler_usize_field(&mut preimage, input.projection_term_index());

    preimage
}

pub(super) fn push_sampler_bytes_field(preimage: &mut Vec<u8>, field: &[u8]) {
    if !preimage.is_empty() {
        preimage.push(b'|');
    }
    preimage.extend_from_slice(field);
}

pub(super) fn push_sampler_usize_field(preimage: &mut Vec<u8>, value: usize) {
    push_sampler_u64_field(preimage, value as u64);
}

pub(super) fn push_sampler_u64_field(preimage: &mut Vec<u8>, value: u64) {
    if !preimage.is_empty() {
        preimage.push(b'|');
    }
    let mut remaining = value;
    if remaining == 0 {
        preimage.push(b'0');
        return;
    }
    let mut digits = [0_u8; 20];
    let mut digit_count = 0_usize;
    while remaining > 0 {
        digits[digit_count] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        digit_count += 1;
    }
    for digit in digits[..digit_count].iter().rev() {
        preimage.push(*digit);
    }
}

pub(super) fn add_product_mod(accumulator: u128, left: u64, right: u64, modulus: u64) -> u128 {
    (accumulator + (u128::from(left) * u128::from(right))) % u128::from(modulus)
}

pub(super) fn signed_integer_to_residue(value: i64, modulus: u64) -> u64 {
    i128::from(value).rem_euclid(i128::from(modulus)) as u64
}

pub(super) fn vss_public_opening_payload_hash(
    message_coefficients: &[u64],
    message_digit_columns: &[Vec<u64>],
    randomness_by_column: &[Vec<i64>],
) -> CanonicalResult<String> {
    let word_count = 3_usize
        .checked_add(message_coefficients.len())
        .and_then(|count| {
            message_digit_columns
                .iter()
                .try_fold(count, |total, column| {
                    total.checked_add(1)?.checked_add(column.len())
                })
        })
        .and_then(|count| {
            randomness_by_column
                .iter()
                .try_fold(count, |total, column| {
                    total.checked_add(1)?.checked_add(column.len())
                })
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS opening payload length overflowed",
            )
        })?;
    let mut bytes = Vec::with_capacity(word_count * 8);
    bytes.extend((message_coefficients.len() as u64).to_le_bytes());
    for coefficient in message_coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes.extend((message_digit_columns.len() as u64).to_le_bytes());
    for column in message_digit_columns {
        bytes.extend((column.len() as u64).to_le_bytes());
        for digit in column {
            bytes.extend(digit.to_le_bytes());
        }
    }
    bytes.extend((randomness_by_column.len() as u64).to_le_bytes());
    for column in randomness_by_column {
        bytes.extend((column.len() as u64).to_le_bytes());
        for coefficient in column {
            bytes.extend(coefficient.to_le_bytes());
        }
    }

    Ok(hash512_hex(
        VSS_PUBLIC_OPENING_PAYLOAD_HASH_DOMAIN,
        &[&bytes],
    ))
}
