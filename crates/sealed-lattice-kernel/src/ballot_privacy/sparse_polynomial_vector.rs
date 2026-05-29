use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::polynomial_ring::PolynomialRing;
#[cfg(test)]
use super::polynomial_vector::PolynomialVector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialVectorEntry {
    position: usize,
    coefficients: Vec<u64>,
}

impl SparsePolynomialVectorEntry {
    pub fn new(position: usize, coefficients: Vec<u64>) -> Self {
        Self {
            position,
            coefficients,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialVector {
    ring: PolynomialRing,
    length: usize,
    entries: Vec<SparsePolynomialVectorEntry>,
}

impl SparsePolynomialVector {
    pub fn new(
        ring: PolynomialRing,
        length: usize,
        entries: Vec<SparsePolynomialVectorEntry>,
    ) -> CanonicalResult<Self> {
        if length == 0 {
            return Err(invalid_sparse_vector(
                "sparse vector length must be non-zero",
            ));
        }

        let mut previous_position = None;
        for entry in &entries {
            if entry.position >= length {
                return Err(invalid_sparse_vector(
                    "sparse vector entry position is out of range",
                ));
            }
            if let Some(previous_position) = previous_position
                && entry.position <= previous_position
            {
                return Err(invalid_sparse_vector(
                    "sparse vector entries must be strictly sorted by position",
                ));
            }
            ring.validate_coefficients(&entry.coefficients)?;
            if is_zero_polynomial(&entry.coefficients) {
                return Err(invalid_sparse_vector(
                    "sparse vector entries must not store zero polynomials",
                ));
            }
            previous_position = Some(entry.position);
        }

        Ok(Self {
            ring,
            length,
            entries,
        })
    }

    pub fn zero(ring: PolynomialRing, length: usize) -> CanonicalResult<Self> {
        Self::new(ring, length, Vec::new())
    }

    pub fn ring(&self) -> PolynomialRing {
        self.ring
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn entries(&self) -> &[SparsePolynomialVectorEntry] {
        &self.entries
    }

    #[cfg(test)]
    pub fn to_dense(&self) -> CanonicalResult<PolynomialVector> {
        let mut dense_entries = vec![vec![0_u64; self.ring.degree()]; self.length];
        for entry in &self.entries {
            dense_entries[entry.position] = entry.coefficients.clone();
        }

        PolynomialVector::new(self.ring, dense_entries)
    }

    pub fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;

        let mut merged_entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        while left_index < self.entries.len() || right_index < other.entries.len() {
            match (self.entries.get(left_index), other.entries.get(right_index)) {
                (Some(left_entry), Some(right_entry))
                    if left_entry.position == right_entry.position =>
                {
                    let sum = self
                        .ring
                        .add(&left_entry.coefficients, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&sum) {
                        merged_entries
                            .push(SparsePolynomialVectorEntry::new(left_entry.position, sum));
                    }
                    left_index += 1;
                    right_index += 1;
                }
                (Some(left_entry), Some(right_entry))
                    if left_entry.position < right_entry.position =>
                {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (Some(_), Some(right_entry)) => {
                    merged_entries.push(right_entry.clone());
                    right_index += 1;
                }
                (Some(left_entry), None) => {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (None, Some(right_entry)) => {
                    merged_entries.push(right_entry.clone());
                    right_index += 1;
                }
                (None, None) => break,
            }
        }

        Self::new(self.ring, self.length, merged_entries)
    }

    pub(crate) fn add_scaled(&self, other: &Self, scalar: u64) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;
        if scalar >= self.ring.modulus() {
            return Err(invalid_sparse_vector(
                "scalar is not canonical for this modulus",
            ));
        }
        if scalar == 0 {
            return Ok(self.clone());
        }

        let mut merged_entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        while left_index < self.entries.len() || right_index < other.entries.len() {
            match (self.entries.get(left_index), other.entries.get(right_index)) {
                (Some(left_entry), Some(right_entry))
                    if left_entry.position == right_entry.position =>
                {
                    let mut sum = left_entry.coefficients.clone();
                    self.ring
                        .scaled_add_assign(&mut sum, scalar, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&sum) {
                        merged_entries
                            .push(SparsePolynomialVectorEntry::new(left_entry.position, sum));
                    }
                    left_index += 1;
                    right_index += 1;
                }
                (Some(left_entry), Some(right_entry))
                    if left_entry.position < right_entry.position =>
                {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (Some(_), Some(right_entry)) => {
                    let scaled_coefficients = self.ring.scale(scalar, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&scaled_coefficients) {
                        merged_entries.push(SparsePolynomialVectorEntry::new(
                            right_entry.position,
                            scaled_coefficients,
                        ));
                    }
                    right_index += 1;
                }
                (Some(left_entry), None) => {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (None, Some(right_entry)) => {
                    let scaled_coefficients = self.ring.scale(scalar, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&scaled_coefficients) {
                        merged_entries.push(SparsePolynomialVectorEntry::new(
                            right_entry.position,
                            scaled_coefficients,
                        ));
                    }
                    right_index += 1;
                }
                (None, None) => break,
            }
        }

        Self::new(self.ring, self.length, merged_entries)
    }

    pub fn scale(&self, scalar: u64) -> CanonicalResult<Self> {
        let mut scaled_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let scaled_coefficients = self.ring.scale(scalar, &entry.coefficients)?;
            if !is_zero_polynomial(&scaled_coefficients) {
                scaled_entries.push(SparsePolynomialVectorEntry::new(
                    entry.position,
                    scaled_coefficients,
                ));
            }
        }

        Self::new(self.ring, self.length, scaled_entries)
    }

    #[cfg(test)]
    pub(crate) fn scale_by_polynomial(&self, polynomial: &[u64]) -> CanonicalResult<Self> {
        self.ring.validate_coefficients(polynomial)?;

        let mut scaled_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let scaled_coefficients = self.ring.mul_negacyclic(polynomial, &entry.coefficients)?;
            if !is_zero_polynomial(&scaled_coefficients) {
                scaled_entries.push(SparsePolynomialVectorEntry::new(
                    entry.position,
                    scaled_coefficients,
                ));
            }
        }

        Self::new(self.ring, self.length, scaled_entries)
    }

    pub(crate) fn add_polynomial_scaled(
        &self,
        other: &Self,
        polynomial: &[u64],
    ) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;
        self.ring.validate_coefficients(polynomial)?;
        if is_zero_polynomial(polynomial) {
            return Ok(self.clone());
        }

        let mut merged_entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        while left_index < self.entries.len() || right_index < other.entries.len() {
            match (self.entries.get(left_index), other.entries.get(right_index)) {
                (Some(left_entry), Some(right_entry))
                    if left_entry.position == right_entry.position =>
                {
                    let mut sum = left_entry.coefficients.clone();
                    self.ring.mul_negacyclic_accumulate(
                        &mut sum,
                        polynomial,
                        &right_entry.coefficients,
                    )?;
                    if !is_zero_polynomial(&sum) {
                        merged_entries
                            .push(SparsePolynomialVectorEntry::new(left_entry.position, sum));
                    }
                    left_index += 1;
                    right_index += 1;
                }
                (Some(left_entry), Some(right_entry))
                    if left_entry.position < right_entry.position =>
                {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (Some(_), Some(right_entry)) => {
                    let scaled_coefficients = self
                        .ring
                        .mul_negacyclic(polynomial, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&scaled_coefficients) {
                        merged_entries.push(SparsePolynomialVectorEntry::new(
                            right_entry.position,
                            scaled_coefficients,
                        ));
                    }
                    right_index += 1;
                }
                (Some(left_entry), None) => {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (None, Some(right_entry)) => {
                    let scaled_coefficients = self
                        .ring
                        .mul_negacyclic(polynomial, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&scaled_coefficients) {
                        merged_entries.push(SparsePolynomialVectorEntry::new(
                            right_entry.position,
                            scaled_coefficients,
                        ));
                    }
                    right_index += 1;
                }
                (None, None) => break,
            }
        }

        Self::new(self.ring, self.length, merged_entries)
    }

    pub(crate) fn resize(&self, resized_length: usize) -> CanonicalResult<Self> {
        if resized_length < self.length {
            return Err(invalid_sparse_vector(
                "sparse vector resize cannot shrink existing entries",
            ));
        }

        Self::new(self.ring, resized_length, self.entries.clone())
    }

    pub fn left_rotate_negacyclic(&self, rotation: usize) -> CanonicalResult<Self> {
        let mut rotated_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            rotated_entries.push(SparsePolynomialVectorEntry::new(
                entry.position,
                self.ring
                    .left_rotate_negacyclic(&entry.coefficients, rotation)?,
            ));
        }

        Self::new(self.ring, self.length, rotated_entries)
    }

    #[cfg(test)]
    pub fn automorphism(&self) -> CanonicalResult<Self> {
        let mut transformed_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            transformed_entries.push(SparsePolynomialVectorEntry::new(
                entry.position,
                self.ring.automorphism(&entry.coefficients)?,
            ));
        }

        Self::new(self.ring, self.length, transformed_entries)
    }

    pub fn shuffle_automorphism_by_pairs(&self) -> CanonicalResult<Self> {
        if !self.length.is_multiple_of(2) {
            return Err(invalid_sparse_vector(
                "pair shuffle requires an even sparse vector length",
            ));
        }

        let mut transformed_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let transformed_position = if entry.position.is_multiple_of(2) {
                entry.position + 1
            } else {
                entry.position - 1
            };
            transformed_entries.push(SparsePolynomialVectorEntry::new(
                transformed_position,
                self.ring.automorphism(&entry.coefficients)?,
            ));
        }
        transformed_entries.sort_by_key(|entry| entry.position);

        Self::new(self.ring, self.length, transformed_entries)
    }

    fn require_same_shape(&self, other: &Self) -> CanonicalResult<()> {
        if self.ring != other.ring {
            return Err(invalid_sparse_vector("sparse vector rings do not match"));
        }
        if self.length != other.length {
            return Err(invalid_sparse_vector("sparse vector lengths do not match"));
        }

        Ok(())
    }
}

fn is_zero_polynomial(coefficients: &[u64]) -> bool {
    coefficients.iter().all(|coefficient| *coefficient == 0)
}

fn invalid_sparse_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{PolynomialRing, SparsePolynomialVector, SparsePolynomialVectorEntry};

    #[test]
    fn converts_sparse_vector_to_dense_vector() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            4,
            vec![
                SparsePolynomialVectorEntry::new(1, vec![2, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(3, vec![0, 3, 0, 0]),
            ],
        )
        .expect("sparse vector should validate");

        assert_eq!(sparse_vector.length(), 4);
        assert_eq!(
            sparse_vector
                .to_dense()
                .expect("dense conversion should succeed")
                .entries(),
            &[
                vec![0, 0, 0, 0],
                vec![2, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 3, 0, 0],
            ]
        );
    }

    #[test]
    fn adds_sparse_vectors_and_drops_cancelled_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![3, 4, 0, 0]),
            ],
        )
        .expect("left vector should validate");
        let right = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(2, vec![14, 13, 0, 0]),
                SparsePolynomialVectorEntry::new(4, vec![5, 0, 0, 0]),
            ],
        )
        .expect("right vector should validate");
        let sum = left.add(&right).expect("addition should succeed");

        assert_eq!(sum.entries().len(), 2);
        assert_eq!(sum.entries()[0].position(), 0);
        assert_eq!(sum.entries()[0].coefficients(), &[1, 0, 0, 0]);
        assert_eq!(sum.entries()[1].position(), 4);
        assert_eq!(sum.entries()[1].coefficients(), &[5, 0, 0, 0]);
    }

    #[test]
    fn adds_scaled_sparse_vectors_without_storing_cancelled_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![3, 4, 0, 0]),
            ],
        )
        .expect("left vector should validate");
        let right = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(2, vec![7, 2, 0, 0]),
                SparsePolynomialVectorEntry::new(4, vec![5, 0, 0, 0]),
            ],
        )
        .expect("right vector should validate");

        let sum = left
            .add_scaled(&right, 2)
            .expect("scaled addition should succeed");

        assert_eq!(sum.entries().len(), 3);
        assert_eq!(sum.entries()[0].coefficients(), &[1, 0, 0, 0]);
        assert_eq!(sum.entries()[1].coefficients(), &[0, 8, 0, 0]);
        assert_eq!(sum.entries()[2].position(), 4);
        assert_eq!(sum.entries()[2].coefficients(), &[10, 0, 0, 0]);
        assert_eq!(
            left.add_scaled(&right, 0)
                .expect("zero scaled addition should keep left"),
            left
        );
    }

    #[test]
    fn rejects_noncanonical_sparse_vector_layouts() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");

        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![
                    SparsePolynomialVectorEntry::new(2, vec![1, 0, 0, 0]),
                    SparsePolynomialVectorEntry::new(1, vec![1, 0, 0, 0]),
                ],
            )
            .expect_err("unsorted positions should fail")
            .message
            .contains("strictly sorted")
        );
        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![SparsePolynomialVectorEntry::new(3, vec![1, 0, 0, 0])],
            )
            .expect_err("out-of-range position should fail")
            .message
            .contains("out of range")
        );
        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![SparsePolynomialVectorEntry::new(1, vec![0, 0, 0, 0])],
            )
            .expect_err("stored zero polynomial should fail")
            .message
            .contains("zero polynomials")
        );
    }

    #[test]
    fn maps_ring_operations_across_sparse_entries_without_changing_positions() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            4,
            vec![
                SparsePolynomialVectorEntry::new(1, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                SparsePolynomialVectorEntry::new(3, vec![8, 7, 6, 5, 4, 3, 2, 1]),
            ],
        )
        .expect("sparse vector should validate");

        let scaled = sparse_vector.scale(3).expect("scaling should succeed");
        assert_eq!(scaled.entries()[0].position(), 1);
        assert_eq!(
            scaled.entries()[0].coefficients(),
            &[3, 6, 9, 12, 15, 1, 4, 7]
        );
        assert_eq!(scaled.entries()[1].position(), 3);
        assert_eq!(
            scaled.entries()[1].coefficients(),
            &[7, 4, 1, 15, 12, 9, 6, 3]
        );

        let rotated = sparse_vector
            .left_rotate_negacyclic(3)
            .expect("rotation should succeed");
        assert_eq!(rotated.entries()[0].position(), 1);
        assert_eq!(
            rotated.entries()[0].coefficients(),
            &[11, 10, 9, 1, 2, 3, 4, 5]
        );
        assert_eq!(rotated.entries()[1].position(), 3);
        assert_eq!(
            rotated.entries()[1].coefficients(),
            &[14, 15, 16, 8, 7, 6, 5, 4]
        );

        let transformed = sparse_vector
            .automorphism()
            .expect("automorphism should succeed");
        assert_eq!(transformed.entries()[0].position(), 1);
        assert_eq!(
            transformed.entries()[0].coefficients(),
            &[1, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(transformed.entries()[1].position(), 3);
        assert_eq!(
            transformed.entries()[1].coefficients(),
            &[8, 16, 15, 14, 13, 12, 11, 10]
        );
    }

    #[test]
    fn scaling_sparse_vector_by_zero_drops_all_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            3,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![0, 2, 0, 0]),
            ],
        )
        .expect("sparse vector should validate");

        let scaled = sparse_vector.scale(0).expect("scaling should succeed");

        assert!(scaled.entries().is_empty());
        assert_eq!(scaled.length(), 3);
    }

    #[test]
    fn polynomial_scaling_multiplies_each_sparse_vector_entry() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            3,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 2, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![0, 1, 0, 0]),
            ],
        )
        .expect("sparse vector should validate");

        let scaled = sparse_vector
            .scale_by_polynomial(&[3, 4, 0, 0])
            .expect("polynomial scaling should succeed");

        assert_eq!(scaled.entries().len(), 2);
        assert_eq!(scaled.entries()[0].coefficients(), &[3, 10, 8, 0]);
        assert_eq!(scaled.entries()[1].coefficients(), &[0, 3, 4, 0]);
    }

    #[test]
    fn adds_polynomial_scaled_sparse_vector_without_intermediate_scale() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = SparsePolynomialVector::new(
            ring,
            3,
            vec![SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0])],
        )
        .expect("left vector should validate");
        let right = SparsePolynomialVector::new(
            ring,
            3,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![2, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![0, 1, 0, 0]),
            ],
        )
        .expect("right vector should validate");

        let polynomial = [3, 4, 0, 0];
        let fused = left
            .add_polynomial_scaled(&right, &polynomial)
            .expect("fused polynomial-scaled addition should succeed");
        let scaled = right
            .scale_by_polynomial(&polynomial)
            .expect("polynomial scaling should succeed");
        let expected = left.add(&scaled).expect("vector addition should succeed");

        assert_eq!(fused, expected);
        assert_eq!(
            left.add_polynomial_scaled(&right, &[0, 0, 0, 0])
                .expect("zero polynomial should keep left"),
            left
        );
    }

    #[test]
    fn resize_expands_sparse_vector_without_moving_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            2,
            vec![SparsePolynomialVectorEntry::new(1, vec![7, 0, 0, 0])],
        )
        .expect("sparse vector should validate");

        let resized = sparse_vector
            .resize(5)
            .expect("expanding resize should succeed");

        assert_eq!(resized.length(), 5);
        assert_eq!(resized.entries()[0].position(), 1);
        assert!(
            sparse_vector
                .resize(1)
                .expect_err("shrinking length should fail")
                .message
                .contains("cannot shrink")
        );
    }

    #[test]
    fn shuffle_automorphism_swaps_adjacent_sparse_positions() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            6,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                SparsePolynomialVectorEntry::new(3, vec![8, 7, 6, 5, 4, 3, 2, 1]),
                SparsePolynomialVectorEntry::new(4, vec![2, 0, 0, 0, 0, 0, 0, 0]),
            ],
        )
        .expect("sparse vector should validate");

        let transformed = sparse_vector
            .shuffle_automorphism_by_pairs()
            .expect("shuffle automorphism should succeed");

        assert_eq!(transformed.entries()[0].position(), 1);
        assert_eq!(
            transformed.entries()[0].coefficients(),
            &[1, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(transformed.entries()[1].position(), 2);
        assert_eq!(
            transformed.entries()[1].coefficients(),
            &[8, 16, 15, 14, 13, 12, 11, 10]
        );
        assert_eq!(transformed.entries()[2].position(), 5);
        assert_eq!(
            transformed.entries()[2].coefficients(),
            &[2, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn shuffle_automorphism_rejects_odd_sparse_vector_length() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            3,
            vec![SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0])],
        )
        .expect("sparse vector should validate");

        let error = sparse_vector
            .shuffle_automorphism_by_pairs()
            .expect_err("odd vector length should fail");

        assert!(error.message.contains("even"));
    }
}
