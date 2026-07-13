use std::{collections::BTreeSet, error::Error, fmt};

use crate::bgv::parameters::{
    DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS, RootParameters,
    SPECIAL_PRIME,
};

use super::suite_record::{is_prime_u64, modular_power, modular_product};

const PRIMARY_SLOT_GENERATOR: u64 = 3;
const MAXIMUM_SCALAR_ENCODER_SLOT_COUNT: u32 = POLYNOMIAL_DEGREE as u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SuiteArithmeticDerivation {
    pub(crate) polynomial_degree: u32,
    pub(crate) plaintext_modulus: u64,
    pub(crate) primitive_two_n_root: u64,
    pub(crate) slot_generator: u64,
    pub(crate) scalar_encoder_slots: Vec<ScalarEncoderSlot>,
    pub(crate) ordered_data_ntt_parameters: Vec<NttModulusDerivation>,
    pub(crate) ordered_special_ntt_parameters: Vec<NttModulusDerivation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScalarEncoderSlot {
    pub(crate) exponent: u32,
    pub(crate) natural_transform_index: u32,
    pub(crate) evaluation_point: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NttModulusDerivation {
    pub(crate) modulus: u64,
    pub(crate) negacyclic_root: u64,
    pub(crate) cyclic_root: u64,
    pub(crate) inverse_negacyclic_root: u64,
    pub(crate) inverse_cyclic_root: u64,
    pub(crate) inverse_polynomial_degree: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SuiteArithmeticError {
    InvalidPolynomialDegree {
        polynomial_degree: u32,
    },
    PolynomialDegreeExceedsBound {
        polynomial_degree: u32,
        maximum_polynomial_degree: u32,
    },
    ArithmeticOverflow,
    EmptyDataPrimeCatalog,
    EmptySpecialPrimeCatalog,
    DuplicateModulus {
        modulus: u64,
    },
    RootCatalogLengthMismatch {
        expected_count: usize,
        actual_count: usize,
    },
    RootCatalogModulusMismatch {
        catalog_position: usize,
        expected_modulus: u64,
        actual_modulus: u64,
    },
    ModulusNotPrime {
        modulus: u64,
    },
    ModulusCongruenceMismatch {
        modulus: u64,
        required_divisor: u64,
    },
    RootGeneratorOutsideMultiplicativeGroup {
        modulus: u64,
        generator: u64,
    },
    NegacyclicRootOrderMismatch {
        modulus: u64,
        root: u64,
    },
    DerivedNegacyclicRootMismatch {
        modulus: u64,
        derived_root: u64,
        selected_root: u64,
    },
    CyclicRootMismatch {
        modulus: u64,
        expected_root: u64,
        selected_root: u64,
    },
    CyclicRootOrderMismatch {
        modulus: u64,
        root: u64,
    },
    NegacyclicRootInverseMismatch {
        modulus: u64,
    },
    CyclicRootInverseMismatch {
        modulus: u64,
    },
    PolynomialDegreeInverseMismatch {
        modulus: u64,
    },
    SlotGeneratorOutsideUnitGroup {
        generator: u64,
        exponent_modulus: u64,
    },
    SlotGeneratorOrderMismatch {
        generator: u64,
        required_order: u64,
    },
    SlotGeneratorContainsNegativeOne {
        generator: u64,
        exponent_modulus: u64,
    },
    SlotExponentCountMismatch {
        expected_count: usize,
        actual_count: usize,
    },
    SlotExponentOutsideOddDomain {
        exponent: u64,
        exponent_modulus: u64,
    },
    DuplicateSlotExponent {
        exponent: u64,
    },
    MissingOddSlotExponent {
        exponent: u64,
    },
}

impl fmt::Display for SuiteArithmeticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolynomialDegree { polynomial_degree } => write!(
                formatter,
                "polynomial degree {polynomial_degree} must be a power of two of at least four",
            ),
            Self::PolynomialDegreeExceedsBound {
                polynomial_degree,
                maximum_polynomial_degree,
            } => write!(
                formatter,
                "polynomial degree {polynomial_degree} exceeds the arithmetic bound {maximum_polynomial_degree}",
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("suite arithmetic size calculation overflowed")
            }
            Self::EmptyDataPrimeCatalog => formatter.write_str("data-prime catalog is empty"),
            Self::EmptySpecialPrimeCatalog => {
                formatter.write_str("special-prime catalog is empty")
            }
            Self::DuplicateModulus { modulus } => {
                write!(formatter, "modulus {modulus} occurs more than once")
            }
            Self::RootCatalogLengthMismatch {
                expected_count,
                actual_count,
            } => write!(
                formatter,
                "root catalog has {actual_count} entries instead of {expected_count}",
            ),
            Self::RootCatalogModulusMismatch {
                catalog_position,
                expected_modulus,
                actual_modulus,
            } => write!(
                formatter,
                "root catalog position {catalog_position} names modulus {actual_modulus} instead of {expected_modulus}",
            ),
            Self::ModulusNotPrime { modulus } => {
                write!(formatter, "modulus {modulus} is not prime")
            }
            Self::ModulusCongruenceMismatch {
                modulus,
                required_divisor,
            } => write!(
                formatter,
                "modulus {modulus} is not congruent to one modulo {required_divisor}",
            ),
            Self::RootGeneratorOutsideMultiplicativeGroup { modulus, generator } => write!(
                formatter,
                "root generator {generator} is outside the multiplicative group modulo {modulus}",
            ),
            Self::NegacyclicRootOrderMismatch { modulus, root } => write!(
                formatter,
                "negacyclic root {root} does not have the required exact order modulo {modulus}",
            ),
            Self::DerivedNegacyclicRootMismatch {
                modulus,
                derived_root,
                selected_root,
            } => write!(
                formatter,
                "generator-derived negacyclic root {derived_root} differs from selected root {selected_root} modulo {modulus}",
            ),
            Self::CyclicRootMismatch {
                modulus,
                expected_root,
                selected_root,
            } => write!(
                formatter,
                "cyclic root {selected_root} differs from squared negacyclic root {expected_root} modulo {modulus}",
            ),
            Self::CyclicRootOrderMismatch { modulus, root } => write!(
                formatter,
                "cyclic root {root} does not have the required exact order modulo {modulus}",
            ),
            Self::NegacyclicRootInverseMismatch { modulus } => write!(
                formatter,
                "negacyclic root inverse is inconsistent modulo {modulus}",
            ),
            Self::CyclicRootInverseMismatch { modulus } => write!(
                formatter,
                "cyclic root inverse is inconsistent modulo {modulus}",
            ),
            Self::PolynomialDegreeInverseMismatch { modulus } => write!(
                formatter,
                "polynomial-degree inverse is inconsistent modulo {modulus}",
            ),
            Self::SlotGeneratorOutsideUnitGroup {
                generator,
                exponent_modulus,
            } => write!(
                formatter,
                "slot generator {generator} is outside the unit group modulo {exponent_modulus}",
            ),
            Self::SlotGeneratorOrderMismatch {
                generator,
                required_order,
            } => write!(
                formatter,
                "slot generator {generator} does not have exact order {required_order}",
            ),
            Self::SlotGeneratorContainsNegativeOne {
                generator,
                exponent_modulus,
            } => write!(
                formatter,
                "slot generator {generator} contains negative one in its subgroup modulo {exponent_modulus}",
            ),
            Self::SlotExponentCountMismatch {
                expected_count,
                actual_count,
            } => write!(
                formatter,
                "slot exponent list has {actual_count} entries instead of {expected_count}",
            ),
            Self::SlotExponentOutsideOddDomain {
                exponent,
                exponent_modulus,
            } => write!(
                formatter,
                "slot exponent {exponent} is not an odd residue modulo {exponent_modulus}",
            ),
            Self::DuplicateSlotExponent { exponent } => {
                write!(formatter, "slot exponent {exponent} occurs more than once")
            }
            Self::MissingOddSlotExponent { exponent } => {
                write!(formatter, "odd slot exponent {exponent} is missing")
            }
        }
    }
}

impl Error for SuiteArithmeticError {}

struct SuiteArithmeticCandidate<'a> {
    polynomial_degree: u32,
    plaintext_modulus: u64,
    slot_generator: u64,
    ordered_data_primes: &'a [u64],
    ordered_special_primes: &'a [u64],
    root_parameters: &'a [RootParameters],
}

pub(crate) fn derive_primary_suite_arithmetic(
) -> Result<SuiteArithmeticDerivation, SuiteArithmeticError> {
    let ordered_special_primes = [SPECIAL_PRIME];
    derive_suite_arithmetic(SuiteArithmeticCandidate {
        polynomial_degree: POLYNOMIAL_DEGREE as u32,
        plaintext_modulus: PLAINTEXT_MODULUS,
        slot_generator: PRIMARY_SLOT_GENERATOR,
        ordered_data_primes: &DATA_PRIMES,
        ordered_special_primes: &ordered_special_primes,
        root_parameters: &ROOT_PARAMETERS,
    })
}

fn derive_suite_arithmetic(
    candidate: SuiteArithmeticCandidate<'_>,
) -> Result<SuiteArithmeticDerivation, SuiteArithmeticError> {
    validate_polynomial_degree(candidate.polynomial_degree)?;
    if candidate.ordered_data_primes.is_empty() {
        return Err(SuiteArithmeticError::EmptyDataPrimeCatalog);
    }
    if candidate.ordered_special_primes.is_empty() {
        return Err(SuiteArithmeticError::EmptySpecialPrimeCatalog);
    }

    let expected_root_count = 1_usize
        .checked_add(candidate.ordered_data_primes.len())
        .and_then(|count| count.checked_add(candidate.ordered_special_primes.len()))
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    if candidate.root_parameters.len() != expected_root_count {
        return Err(SuiteArithmeticError::RootCatalogLengthMismatch {
            expected_count: expected_root_count,
            actual_count: candidate.root_parameters.len(),
        });
    }

    let ordered_moduli = std::iter::once(candidate.plaintext_modulus)
        .chain(candidate.ordered_data_primes.iter().copied())
        .chain(candidate.ordered_special_primes.iter().copied())
        .collect::<Vec<_>>();
    let mut distinct_moduli = BTreeSet::new();
    for modulus in &ordered_moduli {
        if !distinct_moduli.insert(*modulus) {
            return Err(SuiteArithmeticError::DuplicateModulus { modulus: *modulus });
        }
    }

    for (catalog_position, (expected_modulus, parameters)) in ordered_moduli
        .iter()
        .zip(candidate.root_parameters)
        .enumerate()
    {
        if parameters.modulus != *expected_modulus {
            return Err(SuiteArithmeticError::RootCatalogModulusMismatch {
                catalog_position,
                expected_modulus: *expected_modulus,
                actual_modulus: parameters.modulus,
            });
        }
    }

    let root_derivations = candidate
        .root_parameters
        .iter()
        .copied()
        .map(|parameters| derive_ntt_modulus(candidate.polynomial_degree, parameters))
        .collect::<Result<Vec<_>, _>>()?;
    let primitive_two_n_root = root_derivations[0].negacyclic_root;
    let scalar_encoder_slots = derive_scalar_encoder_slots(
        candidate.polynomial_degree,
        candidate.plaintext_modulus,
        primitive_two_n_root,
        candidate.slot_generator,
    )?;

    let data_prime_count = candidate.ordered_data_primes.len();
    let ordered_data_ntt_parameters = root_derivations[1..=data_prime_count].to_vec();
    let ordered_special_ntt_parameters = root_derivations[data_prime_count + 1..].to_vec();

    Ok(SuiteArithmeticDerivation {
        polynomial_degree: candidate.polynomial_degree,
        plaintext_modulus: candidate.plaintext_modulus,
        primitive_two_n_root,
        slot_generator: candidate.slot_generator,
        scalar_encoder_slots,
        ordered_data_ntt_parameters,
        ordered_special_ntt_parameters,
    })
}

fn validate_polynomial_degree(polynomial_degree: u32) -> Result<(), SuiteArithmeticError> {
    if polynomial_degree < 4 || !polynomial_degree.is_power_of_two() {
        return Err(SuiteArithmeticError::InvalidPolynomialDegree { polynomial_degree });
    }
    if polynomial_degree > MAXIMUM_SCALAR_ENCODER_SLOT_COUNT {
        return Err(SuiteArithmeticError::PolynomialDegreeExceedsBound {
            polynomial_degree,
            maximum_polynomial_degree: MAXIMUM_SCALAR_ENCODER_SLOT_COUNT,
        });
    }

    Ok(())
}

fn derive_ntt_modulus(
    polynomial_degree: u32,
    parameters: RootParameters,
) -> Result<NttModulusDerivation, SuiteArithmeticError> {
    let twice_polynomial_degree = u64::from(polynomial_degree)
        .checked_mul(2)
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    validate_prime_and_congruence(parameters.modulus, twice_polynomial_degree)?;

    if parameters.primitive_generator < 2
        || parameters.primitive_generator >= parameters.modulus
    {
        return Err(
            SuiteArithmeticError::RootGeneratorOutsideMultiplicativeGroup {
                modulus: parameters.modulus,
                generator: parameters.primitive_generator,
            },
        );
    }
    validate_exact_negacyclic_root(
        parameters.modulus,
        polynomial_degree,
        parameters.negacyclic_root,
    )?;

    let root_projection_exponent = (parameters.modulus - 1) / twice_polynomial_degree;
    let derived_negacyclic_root = modular_power(
        parameters.primitive_generator,
        root_projection_exponent,
        parameters.modulus,
    );
    if derived_negacyclic_root != parameters.negacyclic_root {
        return Err(SuiteArithmeticError::DerivedNegacyclicRootMismatch {
            modulus: parameters.modulus,
            derived_root: derived_negacyclic_root,
            selected_root: parameters.negacyclic_root,
        });
    }

    let expected_cyclic_root = modular_product(
        parameters.negacyclic_root,
        parameters.negacyclic_root,
        parameters.modulus,
    );
    if parameters.cyclic_root != expected_cyclic_root {
        return Err(SuiteArithmeticError::CyclicRootMismatch {
            modulus: parameters.modulus,
            expected_root: expected_cyclic_root,
            selected_root: parameters.cyclic_root,
        });
    }
    validate_exact_cyclic_root(
        parameters.modulus,
        polynomial_degree,
        parameters.cyclic_root,
    )?;

    if parameters.inverse_negacyclic_root >= parameters.modulus
        || modular_product(
            parameters.negacyclic_root,
            parameters.inverse_negacyclic_root,
            parameters.modulus,
        ) != 1
    {
        return Err(SuiteArithmeticError::NegacyclicRootInverseMismatch {
            modulus: parameters.modulus,
        });
    }
    if parameters.inverse_cyclic_root >= parameters.modulus
        || modular_product(
            parameters.cyclic_root,
            parameters.inverse_cyclic_root,
            parameters.modulus,
        ) != 1
    {
        return Err(SuiteArithmeticError::CyclicRootInverseMismatch {
            modulus: parameters.modulus,
        });
    }
    if parameters.inverse_polynomial_degree >= parameters.modulus
        || modular_product(
            u64::from(polynomial_degree),
            parameters.inverse_polynomial_degree,
            parameters.modulus,
        ) != 1
    {
        return Err(SuiteArithmeticError::PolynomialDegreeInverseMismatch {
            modulus: parameters.modulus,
        });
    }

    Ok(NttModulusDerivation {
        modulus: parameters.modulus,
        negacyclic_root: parameters.negacyclic_root,
        cyclic_root: parameters.cyclic_root,
        inverse_negacyclic_root: parameters.inverse_negacyclic_root,
        inverse_cyclic_root: parameters.inverse_cyclic_root,
        inverse_polynomial_degree: parameters.inverse_polynomial_degree,
    })
}

fn validate_prime_and_congruence(
    modulus: u64,
    required_divisor: u64,
) -> Result<(), SuiteArithmeticError> {
    if !is_prime_u64(modulus) {
        return Err(SuiteArithmeticError::ModulusNotPrime { modulus });
    }
    if !(modulus - 1).is_multiple_of(required_divisor) {
        return Err(SuiteArithmeticError::ModulusCongruenceMismatch {
            modulus,
            required_divisor,
        });
    }

    Ok(())
}

fn validate_exact_negacyclic_root(
    modulus: u64,
    polynomial_degree: u32,
    root: u64,
) -> Result<(), SuiteArithmeticError> {
    let twice_polynomial_degree = u64::from(polynomial_degree)
        .checked_mul(2)
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    if root == 0
        || root >= modulus
        || modular_power(root, u64::from(polynomial_degree), modulus) != modulus - 1
        || modular_power(root, twice_polynomial_degree, modulus) != 1
    {
        return Err(SuiteArithmeticError::NegacyclicRootOrderMismatch { modulus, root });
    }

    Ok(())
}

fn validate_exact_cyclic_root(
    modulus: u64,
    polynomial_degree: u32,
    root: u64,
) -> Result<(), SuiteArithmeticError> {
    let polynomial_degree = u64::from(polynomial_degree);
    if root == 0
        || root >= modulus
        || modular_power(root, polynomial_degree, modulus) != 1
        || modular_power(root, polynomial_degree / 2, modulus) == 1
    {
        return Err(SuiteArithmeticError::CyclicRootOrderMismatch { modulus, root });
    }

    Ok(())
}

fn derive_scalar_encoder_slots(
    polynomial_degree: u32,
    plaintext_modulus: u64,
    primitive_two_n_root: u64,
    slot_generator: u64,
) -> Result<Vec<ScalarEncoderSlot>, SuiteArithmeticError> {
    validate_polynomial_degree(polynomial_degree)?;
    let exponent_modulus = u64::from(polynomial_degree)
        .checked_mul(2)
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    validate_prime_and_congruence(plaintext_modulus, exponent_modulus)?;
    validate_exact_negacyclic_root(
        plaintext_modulus,
        polynomial_degree,
        primitive_two_n_root,
    )?;

    let ordered_exponents = derive_ordered_slot_exponents(polynomial_degree, slot_generator)?;
    let mut scalar_encoder_slots = Vec::with_capacity(ordered_exponents.len());
    for exponent in ordered_exponents {
        let natural_transform_index = (exponent - 1) / 2;
        scalar_encoder_slots.push(ScalarEncoderSlot {
            exponent: u32::try_from(exponent)
                .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?,
            natural_transform_index: u32::try_from(natural_transform_index)
                .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?,
            evaluation_point: modular_power(
                primitive_two_n_root,
                exponent,
                plaintext_modulus,
            ),
        });
    }

    Ok(scalar_encoder_slots)
}

fn derive_ordered_slot_exponents(
    polynomial_degree: u32,
    slot_generator: u64,
) -> Result<Vec<u64>, SuiteArithmeticError> {
    validate_polynomial_degree(polynomial_degree)?;
    let exponent_modulus = u64::from(polynomial_degree)
        .checked_mul(2)
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    if slot_generator == 0
        || slot_generator >= exponent_modulus
        || slot_generator.is_multiple_of(2)
    {
        return Err(SuiteArithmeticError::SlotGeneratorOutsideUnitGroup {
            generator: slot_generator,
            exponent_modulus,
        });
    }

    let required_order = u64::from(polynomial_degree / 2);
    if modular_power(slot_generator, required_order, exponent_modulus) != 1
        || modular_power(slot_generator, required_order / 2, exponent_modulus) == 1
    {
        return Err(SuiteArithmeticError::SlotGeneratorOrderMismatch {
            generator: slot_generator,
            required_order,
        });
    }

    let required_order_usize = usize::try_from(required_order)
        .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
    let mut positive_exponents = Vec::with_capacity(required_order_usize);
    let mut exponent = 1_u64;
    for _ in 0..required_order_usize {
        if exponent == exponent_modulus - 1 {
            return Err(SuiteArithmeticError::SlotGeneratorContainsNegativeOne {
                generator: slot_generator,
                exponent_modulus,
            });
        }
        positive_exponents.push(exponent);
        exponent = modular_product(exponent, slot_generator, exponent_modulus);
    }

    let slot_count = usize::try_from(polynomial_degree)
        .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
    let mut ordered_exponents = Vec::with_capacity(slot_count);
    ordered_exponents.extend(positive_exponents.iter().copied());
    ordered_exponents.extend(
        positive_exponents
            .iter()
            .map(|positive_exponent| exponent_modulus - positive_exponent),
    );
    validate_slot_exponent_coverage(polynomial_degree, &ordered_exponents)?;

    Ok(ordered_exponents)
}

fn validate_slot_exponent_coverage(
    polynomial_degree: u32,
    ordered_exponents: &[u64],
) -> Result<(), SuiteArithmeticError> {
    validate_polynomial_degree(polynomial_degree)?;
    let expected_count = usize::try_from(polynomial_degree)
        .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
    if ordered_exponents.len() != expected_count {
        return Err(SuiteArithmeticError::SlotExponentCountMismatch {
            expected_count,
            actual_count: ordered_exponents.len(),
        });
    }

    let exponent_modulus = u64::from(polynomial_degree)
        .checked_mul(2)
        .ok_or(SuiteArithmeticError::ArithmeticOverflow)?;
    let exponent_modulus_usize = usize::try_from(exponent_modulus)
        .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
    let mut present = vec![false; exponent_modulus_usize];
    for exponent in ordered_exponents {
        if *exponent >= exponent_modulus || exponent.is_multiple_of(2) {
            return Err(SuiteArithmeticError::SlotExponentOutsideOddDomain {
                exponent: *exponent,
                exponent_modulus,
            });
        }
        let exponent_index = usize::try_from(*exponent)
            .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
        if present[exponent_index] {
            return Err(SuiteArithmeticError::DuplicateSlotExponent {
                exponent: *exponent,
            });
        }
        present[exponent_index] = true;
    }
    for exponent in (1..exponent_modulus).step_by(2) {
        let exponent_index = usize::try_from(exponent)
            .map_err(|_| SuiteArithmeticError::ArithmeticOverflow)?;
        if !present[exponent_index] {
            return Err(SuiteArithmeticError::MissingOddSlotExponent { exponent });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAXIMUM_SCALAR_ENCODER_SLOT_COUNT, PRIMARY_SLOT_GENERATOR, SuiteArithmeticCandidate,
        SuiteArithmeticError, derive_primary_suite_arithmetic, derive_scalar_encoder_slots,
        derive_suite_arithmetic, derive_ordered_slot_exponents, validate_prime_and_congruence,
        validate_slot_exponent_coverage,
    };
    use crate::bgv::{
        ntt::forward_negacyclic_ntt,
        parameters::{
            DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS, RootParameters,
            SPECIAL_PRIME,
        },
    };

    #[test]
    fn primary_arithmetic_reproduces_roots_and_the_complete_scalar_encoder_layout() {
        let first = derive_primary_suite_arithmetic().expect("primary arithmetic");
        let second = derive_primary_suite_arithmetic().expect("repeat primary arithmetic");

        assert_eq!(first, second);
        assert_eq!(first.polynomial_degree, 32_768);
        assert_eq!(first.plaintext_modulus, 65_537);
        assert_eq!(first.primitive_two_n_root, 3);
        assert_eq!(first.slot_generator, 3);
        assert_eq!(first.scalar_encoder_slots.len(), POLYNOMIAL_DEGREE);
        assert_eq!(first.ordered_data_ntt_parameters.len(), DATA_PRIMES.len());
        assert_eq!(first.ordered_special_ntt_parameters.len(), 1);
        assert_eq!(
            first
                .ordered_data_ntt_parameters
                .iter()
                .map(|parameters| parameters.modulus)
                .collect::<Vec<_>>(),
            DATA_PRIMES,
        );
        assert_eq!(
            first.ordered_special_ntt_parameters[0].modulus,
            SPECIAL_PRIME,
        );

        let positive_slot_count = POLYNOMIAL_DEGREE / 2;
        assert_eq!(first.scalar_encoder_slots[0].exponent, 1);
        assert_eq!(first.scalar_encoder_slots[1].exponent, 3);
        assert_eq!(first.scalar_encoder_slots[2].exponent, 9);
        assert_eq!(first.scalar_encoder_slots[3].exponent, 27);
        assert_eq!(
            first.scalar_encoder_slots[positive_slot_count].exponent,
            65_535,
        );
        assert_eq!(
            first.scalar_encoder_slots[positive_slot_count + 1].exponent,
            65_533,
        );

        let mut natural_transform_indexes = first
            .scalar_encoder_slots
            .iter()
            .map(|slot| slot.natural_transform_index)
            .collect::<Vec<_>>();
        natural_transform_indexes.sort_unstable();
        assert_eq!(
            natural_transform_indexes,
            (0..POLYNOMIAL_DEGREE as u32).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn scalar_encoder_mapping_matches_independent_polynomial_evaluation() {
        let derivation = derive_primary_suite_arithmetic().expect("primary arithmetic");
        let coefficients = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                let coefficient = coefficient_index as u64;
                (coefficient * 17 + coefficient.rotate_left(11) + 29) % PLAINTEXT_MODULUS
            })
            .collect::<Vec<_>>();
        let natural_transform =
            forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS).expect("forward NTT");

        for logical_slot_index in [
            0,
            1,
            POLYNOMIAL_DEGREE / 2 - 1,
            POLYNOMIAL_DEGREE / 2,
            POLYNOMIAL_DEGREE - 1,
        ] {
            let slot = derivation.scalar_encoder_slots[logical_slot_index];
            let independently_evaluated = evaluate_polynomial(
                &coefficients,
                slot.evaluation_point,
                PLAINTEXT_MODULUS,
            );
            assert_eq!(
                natural_transform[slot.natural_transform_index as usize],
                independently_evaluated,
                "logical slot {logical_slot_index}",
            );
        }
    }

    #[test]
    fn arithmetic_rejects_composites_pseudoprimes_and_wrong_congruence() {
        for composite in [0, 1, 4, 341, 3_215_031_751] {
            assert!(matches!(
                validate_prime_and_congruence(composite, 8),
                Err(SuiteArithmeticError::ModulusNotPrime { modulus }) if modulus == composite
            ));
        }
        assert!(matches!(
            validate_prime_and_congruence(97, 64),
            Err(SuiteArithmeticError::ModulusCongruenceMismatch {
                modulus: 97,
                required_divisor: 64,
            })
        ));
    }

    #[test]
    fn every_selected_negacyclic_root_rejects_an_order_reducing_mutation() {
        for root_position in 0..ROOT_PARAMETERS.len() {
            let mut owned = OwnedCandidate::primary();
            owned.root_parameters[root_position].negacyclic_root = 1;

            assert!(matches!(
                derive_suite_arithmetic(owned.as_borrowed()),
                Err(SuiteArithmeticError::NegacyclicRootOrderMismatch { root: 1, .. })
            ));
        }
    }

    #[test]
    fn ntt_parameter_mutations_reject_at_the_exact_broken_invariant() {
        let mut wrong_generator = OwnedCandidate::primary();
        wrong_generator.root_parameters[1].primitive_generator = 1;
        assert!(matches!(
            derive_suite_arithmetic(wrong_generator.as_borrowed()),
            Err(SuiteArithmeticError::RootGeneratorOutsideMultiplicativeGroup { .. })
        ));

        let mut wrong_derivation = OwnedCandidate::primary();
        wrong_derivation.root_parameters[1].primitive_generator = 3;
        assert!(matches!(
            derive_suite_arithmetic(wrong_derivation.as_borrowed()),
            Err(SuiteArithmeticError::DerivedNegacyclicRootMismatch { .. })
        ));

        let mut wrong_cyclic_root = OwnedCandidate::primary();
        wrong_cyclic_root.root_parameters[1].cyclic_root = 1;
        assert!(matches!(
            derive_suite_arithmetic(wrong_cyclic_root.as_borrowed()),
            Err(SuiteArithmeticError::CyclicRootMismatch { .. })
        ));

        let mut wrong_negacyclic_inverse = OwnedCandidate::primary();
        wrong_negacyclic_inverse.root_parameters[1].inverse_negacyclic_root = 0;
        assert!(matches!(
            derive_suite_arithmetic(wrong_negacyclic_inverse.as_borrowed()),
            Err(SuiteArithmeticError::NegacyclicRootInverseMismatch { .. })
        ));

        let mut wrong_cyclic_inverse = OwnedCandidate::primary();
        wrong_cyclic_inverse.root_parameters[1].inverse_cyclic_root = 0;
        assert!(matches!(
            derive_suite_arithmetic(wrong_cyclic_inverse.as_borrowed()),
            Err(SuiteArithmeticError::CyclicRootInverseMismatch { .. })
        ));

        let mut wrong_degree_inverse = OwnedCandidate::primary();
        wrong_degree_inverse.root_parameters[1].inverse_polynomial_degree = 0;
        assert!(matches!(
            derive_suite_arithmetic(wrong_degree_inverse.as_borrowed()),
            Err(SuiteArithmeticError::PolynomialDegreeInverseMismatch { .. })
        ));
    }

    #[test]
    fn catalogs_reject_missing_misaligned_and_duplicate_moduli() {
        let mut missing_root = OwnedCandidate::primary();
        missing_root.root_parameters.pop();
        assert!(matches!(
            derive_suite_arithmetic(missing_root.as_borrowed()),
            Err(SuiteArithmeticError::RootCatalogLengthMismatch { .. })
        ));

        let mut misaligned_root = OwnedCandidate::primary();
        misaligned_root.root_parameters.swap(1, 2);
        assert!(matches!(
            derive_suite_arithmetic(misaligned_root.as_borrowed()),
            Err(SuiteArithmeticError::RootCatalogModulusMismatch {
                catalog_position: 1,
                ..
            })
        ));

        let mut duplicate_modulus = OwnedCandidate::primary();
        duplicate_modulus.ordered_special_primes[0] = DATA_PRIMES[0];
        duplicate_modulus.root_parameters.last_mut().expect("last root").modulus = DATA_PRIMES[0];
        assert!(matches!(
            derive_suite_arithmetic(duplicate_modulus.as_borrowed()),
            Err(SuiteArithmeticError::DuplicateModulus { modulus }) if modulus == DATA_PRIMES[0]
        ));

        let mut empty_data_primes = OwnedCandidate::primary();
        empty_data_primes.ordered_data_primes.clear();
        assert!(matches!(
            derive_suite_arithmetic(empty_data_primes.as_borrowed()),
            Err(SuiteArithmeticError::EmptyDataPrimeCatalog)
        ));

        let mut empty_special_primes = OwnedCandidate::primary();
        empty_special_primes.ordered_special_primes.clear();
        assert!(matches!(
            derive_suite_arithmetic(empty_special_primes.as_borrowed()),
            Err(SuiteArithmeticError::EmptySpecialPrimeCatalog)
        ));
    }

    #[test]
    fn slot_generator_checks_reject_nonunits_short_order_and_negative_one() {
        assert!(matches!(
            derive_ordered_slot_exponents(32_768, 2),
            Err(SuiteArithmeticError::SlotGeneratorOutsideUnitGroup { .. })
        ));
        assert!(matches!(
            derive_ordered_slot_exponents(32_768, 1),
            Err(SuiteArithmeticError::SlotGeneratorOrderMismatch { .. })
        ));

        assert!(matches!(
            derive_ordered_slot_exponents(4, 7),
            Err(SuiteArithmeticError::SlotGeneratorContainsNegativeOne {
                generator: 7,
                exponent_modulus: 8,
            })
        ));
    }

    #[test]
    fn slot_coverage_checks_reject_count_even_duplicate_and_missing_exponents() {
        let exponents = derive_ordered_slot_exponents(32, 3).expect("slot exponents");

        let mut short = exponents.clone();
        short.pop();
        assert!(matches!(
            validate_slot_exponent_coverage(32, &short),
            Err(SuiteArithmeticError::SlotExponentCountMismatch { .. })
        ));

        let mut even = exponents.clone();
        even[7] = 2;
        assert!(matches!(
            validate_slot_exponent_coverage(32, &even),
            Err(SuiteArithmeticError::SlotExponentOutsideOddDomain { exponent: 2, .. })
        ));

        let mut duplicate = exponents.clone();
        duplicate[7] = duplicate[0];
        assert!(matches!(
            validate_slot_exponent_coverage(32, &duplicate),
            Err(SuiteArithmeticError::DuplicateSlotExponent { .. })
        ));

        let mut missing = exponents;
        let removed = missing.remove(7);
        missing.push(65);
        assert!(matches!(
            validate_slot_exponent_coverage(32, &missing),
            Err(SuiteArithmeticError::SlotExponentOutsideOddDomain {
                exponent: 65,
                exponent_modulus: 64,
            })
        ));

        let mut present = derive_ordered_slot_exponents(32, 3).expect("slot exponents");
        let removed_position = present
            .iter()
            .position(|exponent| *exponent == removed)
            .expect("removed exponent");
        present[removed_position] = present[0];
        let duplicate_error = validate_slot_exponent_coverage(32, &present)
            .expect_err("replacement must reject before missing coverage");
        assert!(matches!(
            duplicate_error,
            SuiteArithmeticError::DuplicateSlotExponent { .. }
        ));
    }

    #[test]
    fn scalar_encoder_bounds_reject_invalid_and_oversized_degrees() {
        for invalid_degree in [0, 1, 2, 3, 6, 12] {
            assert!(matches!(
                derive_scalar_encoder_slots(invalid_degree, 17, 2, 3),
                Err(SuiteArithmeticError::InvalidPolynomialDegree { polynomial_degree })
                    if polynomial_degree == invalid_degree
            ));
        }
        assert!(matches!(
            derive_scalar_encoder_slots(
                MAXIMUM_SCALAR_ENCODER_SLOT_COUNT * 2,
                PLAINTEXT_MODULUS,
                3,
                PRIMARY_SLOT_GENERATOR,
            ),
            Err(SuiteArithmeticError::PolynomialDegreeExceedsBound { .. })
        ));
    }

    fn evaluate_polynomial(coefficients: &[u64], point: u64, modulus: u64) -> u64 {
        coefficients
            .iter()
            .rev()
            .fold(0_u64, |accumulated_value, coefficient| {
                ((u128::from(accumulated_value) * u128::from(point) + u128::from(*coefficient))
                    % u128::from(modulus)) as u64
            })
    }

    struct OwnedCandidate {
        polynomial_degree: u32,
        plaintext_modulus: u64,
        slot_generator: u64,
        ordered_data_primes: Vec<u64>,
        ordered_special_primes: Vec<u64>,
        root_parameters: Vec<RootParameters>,
    }

    impl OwnedCandidate {
        fn primary() -> Self {
            Self {
                polynomial_degree: POLYNOMIAL_DEGREE as u32,
                plaintext_modulus: PLAINTEXT_MODULUS,
                slot_generator: PRIMARY_SLOT_GENERATOR,
                ordered_data_primes: DATA_PRIMES.to_vec(),
                ordered_special_primes: vec![SPECIAL_PRIME],
                root_parameters: ROOT_PARAMETERS.to_vec(),
            }
        }

        fn as_borrowed(&self) -> SuiteArithmeticCandidate<'_> {
            SuiteArithmeticCandidate {
                polynomial_degree: self.polynomial_degree,
                plaintext_modulus: self.plaintext_modulus,
                slot_generator: self.slot_generator,
                ordered_data_primes: &self.ordered_data_primes,
                ordered_special_primes: &self.ordered_special_primes,
                root_parameters: &self.root_parameters,
            }
        }
    }
}
