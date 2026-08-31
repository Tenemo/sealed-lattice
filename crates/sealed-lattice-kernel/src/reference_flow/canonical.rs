use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, RefusalReason};

use super::{ProtocolRefusal, ProtocolResult};

pub(crate) fn require_tuple(
    tuple: &CanonicalTuple,
    expected_schema_identifier: u16,
    expected_schema_version: u16,
    expected_item_count: usize,
) -> ProtocolResult<()> {
    if tuple.schema_identifier != expected_schema_identifier {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol tuple has the wrong schema",
        ));
    }
    if tuple.schema_version != expected_schema_version {
        return Err(ProtocolRefusal::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "protocol tuple version is unsupported",
        ));
    }
    if tuple.items.len() != expected_item_count {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol tuple has the wrong item count",
        ));
    }
    Ok(())
}

pub(crate) fn read_fixed_bytes<const LENGTH: usize>(
    item: &CanonicalItem,
) -> ProtocolResult<[u8; LENGTH]> {
    read_fixed_byte_slice(item, LENGTH)?
        .try_into()
        .map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "protocol byte string has the wrong length",
            )
        })
}

pub(crate) fn read_fixed_byte_slice(
    item: &CanonicalItem,
    expected_byte_length: usize,
) -> ProtocolResult<&[u8]> {
    require_item_type(item, CanonicalItemType::RawBytes)?;
    if item.canonical_bytes().len() != expected_byte_length {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol byte string has the wrong length",
        ));
    }
    Ok(item.canonical_bytes())
}

pub(crate) fn read_variable_bytes(item: &CanonicalItem) -> ProtocolResult<&[u8]> {
    require_item_type(item, CanonicalItemType::RawBytes)?;
    item.variable_value_bytes().map_err(Into::into)
}

pub(crate) fn read_hash(item: &CanonicalItem) -> ProtocolResult<Hash512> {
    require_item_type(item, CanonicalItemType::Hash512)?;
    let bytes = item.canonical_bytes().try_into().map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol hash has the wrong length",
        )
    })?;
    Ok(Hash512::from_bytes(bytes))
}

pub(crate) fn read_hash_array<const COUNT: usize>(
    items: &[CanonicalItem],
) -> ProtocolResult<[Hash512; COUNT]> {
    if items.len() != COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol hash inventory has the wrong item count",
        ));
    }
    items
        .iter()
        .map(read_hash)
        .collect::<ProtocolResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "protocol hash inventory has the wrong item count",
            )
        })
}

pub(crate) fn read_u16(item: &CanonicalItem) -> ProtocolResult<u16> {
    require_item_type(item, CanonicalItemType::Unsigned16)?;
    let bytes = item.canonical_bytes().try_into().map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol unsigned 16-bit value has the wrong length",
        )
    })?;
    Ok(u16::from_le_bytes(bytes))
}

pub(crate) fn read_u64(item: &CanonicalItem) -> ProtocolResult<u64> {
    require_item_type(item, CanonicalItemType::Unsigned64)?;
    let bytes = item.canonical_bytes().try_into().map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol unsigned 64-bit value has the wrong length",
        )
    })?;
    Ok(u64::from_le_bytes(bytes))
}

fn require_item_type(
    item: &CanonicalItem,
    expected_item_type: CanonicalItemType,
) -> ProtocolResult<()> {
    if item.item_type() != expected_item_type {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol item has the wrong semantic type",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_readers_reject_semantic_type_and_length_mismatches() {
        assert!(read_u16(&CanonicalItem::unsigned64(1)).is_err());
        assert!(read_hash(&CanonicalItem::fixed_bytes([0; 64]).unwrap()).is_err());
        assert!(read_hash_array::<2>(&[CanonicalItem::hash512([0; 64])]).is_err());
        assert!(read_fixed_bytes::<3>(&CanonicalItem::fixed_bytes([0; 2]).unwrap()).is_err());
        assert!(read_fixed_byte_slice(&CanonicalItem::fixed_bytes([0; 2]).unwrap(), 3).is_err());
        assert!(read_variable_bytes(&CanonicalItem::fixed_bytes([0; 2]).unwrap()).is_err());
    }
}
