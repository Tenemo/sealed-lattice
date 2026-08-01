use core::fmt;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalItemType, CanonicalTuple,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512([u8; 64]);

impl Hash512 {
    pub const BYTE_LENGTH: usize = 64;

    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }

    pub fn to_lowercase_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(128);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for Hash512 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Hash512")
            .field(&self.to_lowercase_hex())
            .finish()
    }
}

impl fmt::Display for Hash512 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lowercase_hex())
    }
}

/// Hashes typed items through the sole foundation SHAKE256 framing.
pub fn hash_foundation_tuple_512(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Hash512, CanonicalCodecError> {
    let hasher = foundation_tuple_hasher(domain, items)?;
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512(output))
}

fn foundation_tuple_hasher(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Shake256, CanonicalCodecError> {
    let framed_bytes = canonical_foundation_tuple_hash_preimage(domain, items)?;

    let mut hasher = Shake256::default();
    hasher.update(&framed_bytes);
    Ok(hasher)
}

/// Returns the exact canonical byte string absorbed by the foundation
/// SHAKE256 invocation. Security experiments use this to match an observed
/// oracle-query preimage without re-evaluating the fixed oracle.
pub(crate) fn canonical_foundation_tuple_hash_preimage(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Zeroizing<Vec<u8>>, CanonicalCodecError> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(domain)?);
    framed_items.extend_from_slice(items);
    Ok(Zeroizing::new(
        CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            framed_items,
        )
        .encode()?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamingFoundationHashError {
    InvalidDomain,
    ItemCountOverflow,
    ItemLengthOverflow,
    PayloadOverrun,
    PayloadIncomplete,
    OutputOverrun,
    OutputIncomplete,
}

/// Bounded reader for one canonically framed SHAKE256 XOF invocation.
///
/// The requested output length is the final typed tuple item, so two logical
/// verifier messages with different fixed widths cannot share an oracle-query
/// preimage. Reading in fragments does not start another SHAKE invocation and
/// never materializes the complete output in memory.
pub(crate) struct FoundationTupleXofReader {
    reader: <Shake256 as ExtendableOutput>::Reader,
    remaining_output_byte_length: usize,
}

impl FoundationTupleXofReader {
    pub(crate) fn new(
        domain: &str,
        prefix_items: &[CanonicalItem],
        output_byte_length: usize,
    ) -> Result<Self, StreamingFoundationHashError> {
        if output_byte_length == 0 {
            return Err(StreamingFoundationHashError::OutputIncomplete);
        }
        CanonicalItem::nonempty_ascii(domain)
            .map_err(|_| StreamingFoundationHashError::InvalidDomain)?;
        let output_byte_length = u64::try_from(output_byte_length)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(
                prefix_items
                    .len()
                    .checked_add(1)
                    .ok_or(StreamingFoundationHashError::ItemCountOverflow)?,
            )
            .map_err(|_| StreamingFoundationHashError::ItemCountOverflow)?;
        items.extend_from_slice(prefix_items);
        items.push(CanonicalItem::unsigned64(output_byte_length));
        let hasher = foundation_tuple_hasher(domain, &items)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
        Ok(Self {
            reader: hasher.finalize_xof(),
            remaining_output_byte_length: usize::try_from(output_byte_length)
                .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?,
        })
    }

    pub(crate) fn read(
        &mut self,
        output_fragment: &mut [u8],
    ) -> Result<(), StreamingFoundationHashError> {
        if output_fragment.len() > self.remaining_output_byte_length {
            return Err(StreamingFoundationHashError::OutputOverrun);
        }
        self.reader.read(output_fragment);
        self.remaining_output_byte_length -= output_fragment.len();
        Ok(())
    }

    pub(crate) fn discard(
        &mut self,
        output_byte_length: usize,
    ) -> Result<(), StreamingFoundationHashError> {
        if output_byte_length > self.remaining_output_byte_length {
            return Err(StreamingFoundationHashError::OutputOverrun);
        }
        let mut buffer = [0_u8; 256];
        let mut remaining = output_byte_length;
        while remaining > 0 {
            let fragment_byte_length = remaining.min(buffer.len());
            self.reader.read(&mut buffer[..fragment_byte_length]);
            remaining -= fragment_byte_length;
        }
        self.remaining_output_byte_length -= output_byte_length;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), StreamingFoundationHashError> {
        if self.remaining_output_byte_length == 0 {
            Ok(())
        } else {
            Err(StreamingFoundationHashError::OutputIncomplete)
        }
    }
}

/// Incremental form of `H_512(domain, prefixItems..., bytes(payload))`.
///
/// The tuple and raw-byte item lengths are committed before any payload byte
/// is accepted.  This produces byte-for-byte the same SHAKE256 preimage as
/// [`hash_foundation_tuple_512`] without allocating or cloning the streamed
/// payload, which is required for proof query-opening absorption in WASM.
pub(crate) struct StreamingFoundationTupleHash512 {
    hasher: Shake256,
    remaining_payload_byte_length: usize,
}

impl StreamingFoundationTupleHash512 {
    pub(crate) fn new_variable_bytes(
        domain: &str,
        prefix_items: &[CanonicalItem],
        payload_byte_length: usize,
    ) -> Result<Self, StreamingFoundationHashError> {
        let domain_item = CanonicalItem::nonempty_ascii(domain)
            .map_err(|_| StreamingFoundationHashError::InvalidDomain)?;
        let item_count = prefix_items
            .len()
            .checked_add(2)
            .ok_or(StreamingFoundationHashError::ItemCountOverflow)?;
        let item_count = u32::try_from(item_count)
            .map_err(|_| StreamingFoundationHashError::ItemCountOverflow)?;
        let payload_byte_length_u32 = u32::try_from(payload_byte_length)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
        let streamed_item_byte_length = payload_byte_length
            .checked_add(4)
            .ok_or(StreamingFoundationHashError::ItemLengthOverflow)?;
        let streamed_item_byte_length_u32 = u32::try_from(streamed_item_byte_length)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;

        let mut hasher = Shake256::default();
        hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
        hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
        hasher.update(&item_count.to_le_bytes());
        update_canonical_hash_item(&mut hasher, &domain_item)?;
        for item in prefix_items {
            update_canonical_hash_item(&mut hasher, item)?;
        }
        hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
        hasher.update(&streamed_item_byte_length_u32.to_le_bytes());
        hasher.update(&payload_byte_length_u32.to_le_bytes());
        Ok(Self {
            hasher,
            remaining_payload_byte_length: payload_byte_length,
        })
    }

    pub(crate) fn absorb(
        &mut self,
        payload_fragment: &[u8],
    ) -> Result<(), StreamingFoundationHashError> {
        if payload_fragment.len() > self.remaining_payload_byte_length {
            return Err(StreamingFoundationHashError::PayloadOverrun);
        }
        self.hasher.update(payload_fragment);
        self.remaining_payload_byte_length -= payload_fragment.len();
        Ok(())
    }

    pub(crate) fn finalize(self) -> Result<Hash512, StreamingFoundationHashError> {
        if self.remaining_payload_byte_length != 0 {
            return Err(StreamingFoundationHashError::PayloadIncomplete);
        }
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; Hash512::BYTE_LENGTH];
        reader.read(&mut output);
        Ok(Hash512(output))
    }
}

fn update_canonical_hash_item(
    hasher: &mut Shake256,
    item: &CanonicalItem,
) -> Result<(), StreamingFoundationHashError> {
    let byte_length = u32::try_from(item.canonical_bytes().len())
        .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
    hasher.update(&item.item_type().canonical_code().to_le_bytes());
    hasher.update(&byte_length.to_le_bytes());
    hasher.update(item.canonical_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    #[test]
    fn hash_uses_exact_typed_tuple_framing() {
        let items = [
            CanonicalItem::unsigned16(0x0201),
            CanonicalItem::variable_bytes([7, 8, 9]).expect("raw bytes fit u32"),
        ];
        let actual = hash_foundation_tuple_512("sealed-lattice/test/hash/v1", &items)
            .expect("hash input is valid");

        let mut expected_frame = Vec::new();
        expected_frame.extend_from_slice(&0x0001_u16.to_le_bytes());
        expected_frame.extend_from_slice(&1_u16.to_le_bytes());
        expected_frame.extend_from_slice(&3_u32.to_le_bytes());
        let domain = b"sealed-lattice/test/hash/v1";
        expected_frame.extend_from_slice(&0x02_u16.to_le_bytes());
        expected_frame.extend_from_slice(&((domain.len() + 4) as u32).to_le_bytes());
        expected_frame.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        expected_frame.extend_from_slice(domain);
        expected_frame.extend_from_slice(&0x03_u16.to_le_bytes());
        expected_frame.extend_from_slice(&2_u32.to_le_bytes());
        expected_frame.extend_from_slice(&0x0201_u16.to_le_bytes());
        expected_frame.extend_from_slice(&0x01_u16.to_le_bytes());
        expected_frame.extend_from_slice(&7_u32.to_le_bytes());
        expected_frame.extend_from_slice(&3_u32.to_le_bytes());
        expected_frame.extend_from_slice(&[7, 8, 9]);

        let mut hasher = Shake256::default();
        hasher.update(&expected_frame);
        let mut reader = hasher.finalize_xof();
        let mut expected = [0u8; 64];
        reader.read(&mut expected);
        assert_eq!(actual, Hash512::from_bytes(expected));
        assert_eq!(actual.to_lowercase_hex().len(), 128);
    }

    #[test]
    fn streaming_variable_bytes_hash_matches_one_shot_for_every_fragmentation() {
        let prefix_items = [
            CanonicalItem::hash512([0x31; 64]),
            CanonicalItem::nonempty_ascii("proof/1216/query-openings").expect("test tag"),
        ];
        let payload = (0_u16..=1024)
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut one_shot_items = prefix_items.to_vec();
        one_shot_items.push(CanonicalItem::variable_bytes(&payload).expect("bounded test payload"));
        let expected =
            hash_foundation_tuple_512("sealed-lattice/proof/transcript/absorb/v1", &one_shot_items)
                .expect("one-shot hash");

        for fragment_byte_length in [1, 3, 63, 64, 65, 511, payload.len()] {
            let mut streaming = StreamingFoundationTupleHash512::new_variable_bytes(
                "sealed-lattice/proof/transcript/absorb/v1",
                &prefix_items,
                payload.len(),
            )
            .expect("streaming hash initializes");
            for fragment in payload.chunks(fragment_byte_length) {
                streaming.absorb(fragment).expect("fragment fits");
            }
            assert_eq!(streaming.finalize().expect("payload is complete"), expected);
        }
    }

    #[test]
    fn streaming_variable_bytes_hash_rejects_overrun_and_incomplete_payloads() {
        let mut overrun = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/test/streaming-hash/v1",
            &[],
            2,
        )
        .expect("stream initializes");
        assert_eq!(
            overrun.absorb(&[1, 2, 3]),
            Err(StreamingFoundationHashError::PayloadOverrun),
        );

        let mut incomplete = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/test/streaming-hash/v1",
            &[],
            2,
        )
        .expect("stream initializes");
        incomplete.absorb(&[1]).expect("prefix fits");
        assert_eq!(
            incomplete.finalize(),
            Err(StreamingFoundationHashError::PayloadIncomplete),
        );
    }

    #[test]
    fn bounded_xof_reader_matches_one_shot_framing_across_fragmentation() {
        let domain = "sealed-lattice/test/bounded-xof/v1";
        let prefix_items = [
            CanonicalItem::hash512([0x51; 64]),
            CanonicalItem::nonempty_ascii("aggregate/query-vector").expect("test tag"),
            CanonicalItem::unsigned32(393),
        ];
        let output_byte_length = 1_025_usize;
        let mut expected_items = prefix_items.to_vec();
        expected_items.push(CanonicalItem::unsigned64(
            u64::try_from(output_byte_length).expect("test length fits u64"),
        ));
        let mut expected_reader = foundation_tuple_hasher(domain, &expected_items)
            .expect("one-shot XOF framing")
            .finalize_xof();
        let mut expected = vec![0_u8; output_byte_length];
        expected_reader.read(&mut expected);

        for fragment_byte_length in [1, 7, 63, 64, 65, 256, output_byte_length] {
            let mut actual_reader =
                FoundationTupleXofReader::new(domain, &prefix_items, output_byte_length)
                    .expect("bounded XOF reader initializes");
            let mut actual = vec![0_u8; output_byte_length];
            for fragment in actual.chunks_mut(fragment_byte_length) {
                actual_reader.read(fragment).expect("fragment is in bounds");
            }
            actual_reader.finish().expect("all output was consumed");
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn bounded_xof_reader_binds_output_width_into_the_oracle_preimage() {
        let domain = "sealed-lattice/test/bounded-xof-width/v1";
        let prefix_items = [CanonicalItem::hash512([0x52; 64])];
        let mut short_reader = FoundationTupleXofReader::new(domain, &prefix_items, 64)
            .expect("short reader initializes");
        let mut long_reader = FoundationTupleXofReader::new(domain, &prefix_items, 65)
            .expect("long reader initializes");
        let mut short_prefix = [0_u8; 64];
        let mut long_prefix = [0_u8; 64];
        short_reader
            .read(&mut short_prefix)
            .expect("short output fits");
        long_reader
            .read(&mut long_prefix)
            .expect("long output prefix fits");
        short_reader.finish().expect("short output is complete");
        long_reader.discard(1).expect("long suffix fits");
        long_reader.finish().expect("long output is complete");
        assert_ne!(short_prefix, long_prefix);

        let mut short_items = prefix_items.to_vec();
        short_items.push(CanonicalItem::unsigned64(64));
        let mut long_items = prefix_items.to_vec();
        long_items.push(CanonicalItem::unsigned64(65));
        assert_ne!(
            canonical_foundation_tuple_hash_preimage(domain, &short_items).expect("short preimage"),
            canonical_foundation_tuple_hash_preimage(domain, &long_items).expect("long preimage"),
        );
    }

    #[test]
    fn bounded_xof_reader_discard_preserves_the_exact_stream_suffix() {
        let domain = "sealed-lattice/test/bounded-xof-discard/v1";
        let prefix_items = [CanonicalItem::unsigned64(17)];
        let output_byte_length = 777_usize;
        let discarded_prefix_byte_length = 513_usize;
        let mut complete_reader =
            FoundationTupleXofReader::new(domain, &prefix_items, output_byte_length)
                .expect("complete reader initializes");
        let mut complete_output = vec![0_u8; output_byte_length];
        complete_reader
            .read(&mut complete_output)
            .expect("complete output fits");
        complete_reader.finish().expect("complete output consumed");

        let mut discarded_reader =
            FoundationTupleXofReader::new(domain, &prefix_items, output_byte_length)
                .expect("discarding reader initializes");
        discarded_reader
            .discard(discarded_prefix_byte_length)
            .expect("discarded prefix fits");
        let mut suffix = vec![0_u8; output_byte_length - discarded_prefix_byte_length];
        discarded_reader.read(&mut suffix).expect("suffix fits");
        discarded_reader
            .finish()
            .expect("discarded output consumed");
        assert_eq!(suffix, complete_output[discarded_prefix_byte_length..]);
    }

    #[test]
    fn bounded_xof_reader_refuses_zero_width_overrun_and_incomplete_consumption() {
        assert!(matches!(
            FoundationTupleXofReader::new("sealed-lattice/test/bounded-xof-errors/v1", &[], 0),
            Err(StreamingFoundationHashError::OutputIncomplete),
        ));

        let mut overrun =
            FoundationTupleXofReader::new("sealed-lattice/test/bounded-xof-errors/v1", &[], 2)
                .expect("reader initializes");
        assert_eq!(
            overrun.read(&mut [0_u8; 3]),
            Err(StreamingFoundationHashError::OutputOverrun),
        );
        assert_eq!(
            overrun.discard(3),
            Err(StreamingFoundationHashError::OutputOverrun),
        );

        let mut incomplete =
            FoundationTupleXofReader::new("sealed-lattice/test/bounded-xof-errors/v1", &[], 2)
                .expect("reader initializes");
        incomplete.read(&mut [0_u8; 1]).expect("prefix fits");
        assert_eq!(
            incomplete.finish(),
            Err(StreamingFoundationHashError::OutputIncomplete),
        );

        assert!(matches!(
            FoundationTupleXofReader::new("", &[], 1),
            Err(StreamingFoundationHashError::InvalidDomain),
        ));
        assert!(matches!(
            FoundationTupleXofReader::new("sealed-lattice/test\n", &[], 1),
            Err(StreamingFoundationHashError::InvalidDomain),
        ));
    }

    #[test]
    fn domain_and_item_boundaries_cannot_alias() {
        let first = hash_foundation_tuple_512(
            "sealed-lattice/test/a",
            &[CanonicalItem::variable_bytes(b"bc").expect("raw bytes")],
        )
        .expect("hash");
        let second = hash_foundation_tuple_512(
            "sealed-lattice/test/ab",
            &[CanonicalItem::variable_bytes(b"c").expect("raw bytes")],
        )
        .expect("hash");
        let split = hash_foundation_tuple_512(
            "sealed-lattice/test/a",
            &[
                CanonicalItem::variable_bytes(b"b").expect("raw bytes"),
                CanonicalItem::variable_bytes(b"c").expect("raw bytes"),
            ],
        )
        .expect("hash");
        assert_ne!(first, second);
        assert_ne!(first, split);
        assert_ne!(second, split);
    }

    #[test]
    fn empty_or_non_printable_domains_refuse() {
        assert!(hash_foundation_tuple_512("", &[]).is_err());
        assert!(hash_foundation_tuple_512("sealed-lattice/test\n", &[]).is_err());
    }
}
