//! Attempt-private salts for secret-bearing Merkle leaves.

use tiny_keccak::{Hasher, Kmac};

pub(super) const PRIVATE_LEAF_SALT_BYTE_LENGTH: usize = 128;
pub(super) type PrivateLeafSalt = [u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];

const PRIVATE_LEAF_SALT_CUSTOMIZATION: &[u8] = b"sealed-lattice/row-code-whir/private-leaf-salt/v1";

/// Derives one coordinate salt from an attempt-private seed.
///
/// The commitment role, complete leaf geometry, matrix ordinal, and leaf
/// coordinate are length-delimited before KMAC. The seed is never part of the
/// proof; only salts for challenged coordinates are transported. Distinct
/// domains used with the same attempt seed therefore remain separate PRF
/// inputs, including from the row-padding stream.
pub(super) fn derive_private_leaf_salt(
    private_seed: &[u8],
    commitment_role: &[u8],
    leaf_count: usize,
    logical_leaf_width: usize,
    matrix_ordinal: usize,
    leaf_index: usize,
) -> Result<PrivateLeafSalt, String> {
    if private_seed.len() < 32
        || commitment_role.is_empty()
        || leaf_count == 0
        || !leaf_count.is_power_of_two()
        || logical_leaf_width == 0
        || leaf_index >= leaf_count
    {
        return Err("private leaf-salt geometry is invalid".to_owned());
    }
    let mut kmac = Kmac::v256(private_seed, PRIVATE_LEAF_SALT_CUSTOMIZATION);
    update_framed(&mut kmac, commitment_role)?;
    update_framed(
        &mut kmac,
        &checked_u64(leaf_count, "leaf count")?.to_le_bytes(),
    )?;
    update_framed(
        &mut kmac,
        &checked_u64(logical_leaf_width, "logical leaf width")?.to_le_bytes(),
    )?;
    update_framed(
        &mut kmac,
        &checked_u64(matrix_ordinal, "matrix ordinal")?.to_le_bytes(),
    )?;
    update_framed(
        &mut kmac,
        &checked_u64(leaf_index, "leaf index")?.to_le_bytes(),
    )?;
    let mut salt = [0_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
    kmac.finalize(&mut salt);
    Ok(salt)
}

fn update_framed(kmac: &mut Kmac, bytes: &[u8]) -> Result<(), String> {
    let byte_length = checked_u64(bytes.len(), "private leaf-salt frame length")?;
    kmac.update(&byte_length.to_le_bytes());
    kmac.update(bytes);
    Ok(())
}

fn checked_u64(value: usize, label: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{label} does not fit u64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_leaf_salts_bind_every_coordinate_and_geometry_field() {
        let seed = [0x5a_u8; 64];
        let baseline = derive_private_leaf_salt(&seed, b"phase/base", 64, 17, 0, 7)
            .expect("baseline salt derives");
        assert_ne!(baseline, [0_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH]);
        for changed in [
            derive_private_leaf_salt(&seed, b"phase/auxiliary", 64, 17, 0, 7),
            derive_private_leaf_salt(&seed, b"phase/base", 128, 17, 0, 7),
            derive_private_leaf_salt(&seed, b"phase/base", 64, 18, 0, 7),
            derive_private_leaf_salt(&seed, b"phase/base", 64, 17, 1, 7),
            derive_private_leaf_salt(&seed, b"phase/base", 64, 17, 0, 8),
            derive_private_leaf_salt(&[0x5b_u8; 64], b"phase/base", 64, 17, 0, 7),
        ] {
            assert_ne!(baseline, changed.expect("changed salt derives"));
        }
    }

    #[test]
    fn private_leaf_salt_derivation_refuses_invalid_or_ambiguous_shapes() {
        let seed = [0x31_u8; 64];
        assert!(derive_private_leaf_salt(&seed[..31], b"phase/base", 64, 1, 0, 0).is_err());
        assert!(derive_private_leaf_salt(&seed, b"", 64, 1, 0, 0).is_err());
        assert!(derive_private_leaf_salt(&seed, b"phase/base", 0, 1, 0, 0).is_err());
        assert!(derive_private_leaf_salt(&seed, b"phase/base", 63, 1, 0, 0).is_err());
        assert!(derive_private_leaf_salt(&seed, b"phase/base", 64, 0, 0, 0).is_err());
        assert!(derive_private_leaf_salt(&seed, b"phase/base", 64, 1, 0, 64).is_err());
    }
}
