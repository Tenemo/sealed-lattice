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

/// Expands one canonically framed foundation tuple through one bounded
/// SHAKE256 invocation.
///
/// The caller must include the exact requested output width in the typed
/// tuple whenever output width is part of the protocol query. This helper
/// performs one XOF call; it does not synthesize a stream from multiple
/// fixed-width hash calls.
pub(crate) fn xof_foundation_tuple(
    domain: &str,
    items: &[CanonicalItem],
    output_byte_length: usize,
) -> Result<Vec<u8>, CanonicalCodecError> {
    let hasher = foundation_tuple_hasher(domain, items)?;
    let mut output = vec![0_u8; output_byte_length];
    hasher.finalize_xof().read(&mut output);
    Ok(output)
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

/// Returns the exact number of fixed 512-bit hash calls needed to fill a
/// bounded byte string.
pub(crate) fn foundation_tuple_hash512_block_count(
    output_byte_length: usize,
) -> Result<u64, StreamingFoundationHashError> {
    if output_byte_length == 0 {
        return Err(StreamingFoundationHashError::OutputIncomplete);
    }
    let output_byte_length = u64::try_from(output_byte_length)
        .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
    output_byte_length
        .checked_add(Hash512::BYTE_LENGTH as u64 - 1)
        .and_then(|rounded| rounded.checked_div(Hash512::BYTE_LENGTH as u64))
        .ok_or(StreamingFoundationHashError::ItemLengthOverflow)
}

/// Returns the fixed-hash query count for one seed plus every output block.
pub(crate) fn foundation_tuple_hash512_seeded_stream_query_count(
    output_byte_length: usize,
) -> Result<u64, StreamingFoundationHashError> {
    foundation_tuple_hash512_block_count(output_byte_length)?
        .checked_add(1)
        .ok_or(StreamingFoundationHashError::ItemLengthOverflow)
}

/// Bounded reader backed exclusively by canonically framed 512-bit hashes.
///
/// One fixed hash derives the construction-bound seed. Output block zero and
/// every later block commit to that seed, the immediately preceding value,
/// the complete requested width, and the block ordinal under a separate
/// domain. Thus every oracle answer is exactly 512 bits, fragment boundaries
/// cannot change the byte stream, and producing a later block requires the
/// complete predecessor chain.
pub(crate) struct FoundationTupleHash512BlockReader {
    seed: [u8; Hash512::BYTE_LENGTH],
    preceding_block: [u8; Hash512::BYTE_LENGTH],
    current_block: [u8; Hash512::BYTE_LENGTH],
    current_block_offset: usize,
    next_block_ordinal: u64,
    total_output_byte_length: u64,
    remaining_output_byte_length: usize,
    block_domain: &'static str,
}

impl FoundationTupleHash512BlockReader {
    pub(crate) fn new(
        seed_domain: &'static str,
        block_domain: &'static str,
        prefix_items: &[CanonicalItem],
        output_byte_length: usize,
    ) -> Result<Self, StreamingFoundationHashError> {
        if output_byte_length == 0 {
            return Err(StreamingFoundationHashError::OutputIncomplete);
        }
        CanonicalItem::nonempty_ascii(seed_domain)
            .map_err(|_| StreamingFoundationHashError::InvalidDomain)?;
        CanonicalItem::nonempty_ascii(block_domain)
            .map_err(|_| StreamingFoundationHashError::InvalidDomain)?;
        if seed_domain == block_domain {
            return Err(StreamingFoundationHashError::InvalidDomain);
        }
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
        let seed = hash_foundation_tuple_512(seed_domain, &items)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
        let seed = seed.into_bytes();
        let first_block = hash_foundation_tuple_512(
            block_domain,
            &[
                CanonicalItem::hash512(seed),
                CanonicalItem::hash512(seed),
                CanonicalItem::unsigned64(output_byte_length),
                CanonicalItem::unsigned64(0),
            ],
        )
        .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?
        .into_bytes();
        Ok(Self {
            seed,
            preceding_block: first_block,
            current_block: first_block,
            current_block_offset: 0,
            next_block_ordinal: 1,
            total_output_byte_length: output_byte_length,
            remaining_output_byte_length: usize::try_from(output_byte_length)
                .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?,
            block_domain,
        })
    }

    fn advance_block(&mut self) -> Result<(), StreamingFoundationHashError> {
        let block = hash_foundation_tuple_512(
            self.block_domain,
            &[
                CanonicalItem::hash512(self.seed),
                CanonicalItem::hash512(self.preceding_block),
                CanonicalItem::unsigned64(self.total_output_byte_length),
                CanonicalItem::unsigned64(self.next_block_ordinal),
            ],
        )
        .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?
        .into_bytes();
        self.preceding_block = block;
        self.current_block = block;
        self.current_block_offset = 0;
        self.next_block_ordinal = self
            .next_block_ordinal
            .checked_add(1)
            .ok_or(StreamingFoundationHashError::ItemLengthOverflow)?;
        Ok(())
    }

    pub(crate) fn read(
        &mut self,
        output_fragment: &mut [u8],
    ) -> Result<(), StreamingFoundationHashError> {
        if output_fragment.len() > self.remaining_output_byte_length {
            return Err(StreamingFoundationHashError::OutputOverrun);
        }
        let mut written_byte_length = 0;
        while written_byte_length < output_fragment.len() {
            if self.current_block_offset == Hash512::BYTE_LENGTH {
                self.advance_block()?;
            }
            let available_byte_length = Hash512::BYTE_LENGTH - self.current_block_offset;
            let copied_byte_length =
                available_byte_length.min(output_fragment.len() - written_byte_length);
            output_fragment[written_byte_length..written_byte_length + copied_byte_length]
                .copy_from_slice(
                    &self.current_block
                        [self.current_block_offset..self.current_block_offset + copied_byte_length],
                );
            self.current_block_offset += copied_byte_length;
            written_byte_length += copied_byte_length;
        }
        self.remaining_output_byte_length -= output_fragment.len();
        Ok(())
    }

    #[cfg(test)]
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
            self.read(&mut buffer[..fragment_byte_length])?;
            remaining -= fragment_byte_length;
        }
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

/// Exact-width reader for one canonically framed SHAKE256 invocation.
///
/// The caller fixes the complete output width before any byte is consumed.
/// Fragmented reads and discards therefore expose one XOF answer without
/// buffering it or silently extending the requested verifier message.
pub(crate) struct BoundedFoundationTupleXofReader {
    reader: <Shake256 as ExtendableOutput>::Reader,
    remaining_output_byte_length: usize,
}

impl BoundedFoundationTupleXofReader {
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

    pub(crate) fn finish(self) -> Result<(), StreamingFoundationHashError> {
        if self.remaining_output_byte_length == 0 {
            Ok(())
        } else {
            Err(StreamingFoundationHashError::OutputIncomplete)
        }
    }
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

    pub(crate) fn finalize_bounded_xof(
        self,
        output_byte_length: usize,
    ) -> Result<BoundedFoundationTupleXofReader, StreamingFoundationHashError> {
        if self.remaining_payload_byte_length != 0 {
            return Err(StreamingFoundationHashError::PayloadIncomplete);
        }
        if output_byte_length == 0 {
            return Err(StreamingFoundationHashError::OutputIncomplete);
        }
        Ok(BoundedFoundationTupleXofReader {
            reader: self.hasher.finalize_xof(),
            remaining_output_byte_length: output_byte_length,
        })
    }

    pub(crate) fn finalize(self) -> Result<Hash512, StreamingFoundationHashError> {
        let mut reader = self.finalize_bounded_xof(Hash512::BYTE_LENGTH)?;
        let mut output = [0_u8; Hash512::BYTE_LENGTH];
        reader.read(&mut output)?;
        reader.finish()?;
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
    fn bounded_streaming_xof_matches_one_canonical_shake_answer() {
        let domain = "sealed-lattice/test/bounded-streaming-xof/v1";
        let prefix_items = [
            CanonicalItem::unsigned32(17),
            CanonicalItem::hash512([0x42; Hash512::BYTE_LENGTH]),
        ];
        let payload = (0_u16..=1024)
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut one_shot_items = prefix_items.to_vec();
        one_shot_items.push(CanonicalItem::variable_bytes(&payload).expect("bounded test payload"));
        let preimage = canonical_foundation_tuple_hash_preimage(domain, &one_shot_items)
            .expect("the independent canonical preimage encodes");
        let mut expected_hasher = Shake256::default();
        expected_hasher.update(&preimage);
        let mut expected_reader = expected_hasher.finalize_xof();
        let mut expected = vec![0_u8; 777];
        expected_reader.read(&mut expected);

        let mut streaming = StreamingFoundationTupleHash512::new_variable_bytes(
            domain,
            &prefix_items,
            payload.len(),
        )
        .expect("the streaming XOF initializes");
        for fragment in payload.chunks(73) {
            streaming.absorb(fragment).expect("fragment fits");
        }
        let mut actual_reader = streaming
            .finalize_bounded_xof(expected.len())
            .expect("the declared output width is nonzero");
        let mut actual = vec![0_u8; expected.len()];
        actual_reader
            .read(&mut actual[..211])
            .expect("the first fragment fits");
        actual_reader
            .read(&mut actual[211..])
            .expect("the second fragment completes the output");
        actual_reader.finish().expect("the exact width is consumed");
        assert_eq!(actual, expected);
    }

    #[test]
    fn bounded_streaming_xof_refuses_zero_width_overrun_and_incomplete_output() {
        let complete = || {
            StreamingFoundationTupleHash512::new_variable_bytes(
                "sealed-lattice/test/bounded-streaming-xof-errors/v1",
                &[],
                0,
            )
            .expect("empty payload is complete")
        };
        assert!(matches!(
            complete().finalize_bounded_xof(0),
            Err(StreamingFoundationHashError::OutputIncomplete),
        ));
        let mut overrun = complete()
            .finalize_bounded_xof(2)
            .expect("two output bytes are declared");
        assert_eq!(
            overrun.read(&mut [0_u8; 3]),
            Err(StreamingFoundationHashError::OutputOverrun),
        );
        assert_eq!(
            complete()
                .finalize_bounded_xof(2)
                .expect("two output bytes are declared")
                .finish(),
            Err(StreamingFoundationHashError::OutputIncomplete),
        );
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

    fn expected_fixed_hash_block_stream(
        seed_domain: &str,
        block_domain: &str,
        prefix_items: &[CanonicalItem],
        output_byte_length: usize,
    ) -> Vec<u8> {
        let mut seed_items = prefix_items.to_vec();
        seed_items.push(CanonicalItem::unsigned64(
            u64::try_from(output_byte_length).expect("test length fits u64"),
        ));
        let seed = hash_foundation_tuple_512(seed_domain, &seed_items)
            .expect("seed hash")
            .into_bytes();
        let mut output = Vec::with_capacity(output_byte_length);
        let mut preceding_value = seed;
        let mut block_ordinal = 0_u64;
        while output.len() < output_byte_length {
            let block = hash_foundation_tuple_512(
                block_domain,
                &[
                    CanonicalItem::hash512(seed),
                    CanonicalItem::hash512(preceding_value),
                    CanonicalItem::unsigned64(
                        u64::try_from(output_byte_length).expect("test length fits u64"),
                    ),
                    CanonicalItem::unsigned64(block_ordinal),
                ],
            )
            .expect("block hash")
            .into_bytes();
            let remaining_byte_length = output_byte_length - output.len();
            output.extend_from_slice(&block[..remaining_byte_length.min(Hash512::BYTE_LENGTH)]);
            preceding_value = block;
            block_ordinal += 1;
        }
        output
    }

    #[test]
    fn fixed_hash_block_reader_matches_the_complete_chain_across_fragmentation() {
        const SEED_DOMAIN: &str = "sealed-lattice/test/fixed-hash-seed/v1";
        const BLOCK_DOMAIN: &str = "sealed-lattice/test/fixed-hash-block/v1";
        let prefix_items = [
            CanonicalItem::hash512([0x51; 64]),
            CanonicalItem::nonempty_ascii("aggregate/query-vector").expect("test tag"),
            CanonicalItem::unsigned32(393),
        ];
        let output_byte_length = 1_025_usize;
        let expected = expected_fixed_hash_block_stream(
            SEED_DOMAIN,
            BLOCK_DOMAIN,
            &prefix_items,
            output_byte_length,
        );

        for fragment_byte_length in [1, 7, 63, 64, 65, 256, output_byte_length] {
            let mut actual_reader = FoundationTupleHash512BlockReader::new(
                SEED_DOMAIN,
                BLOCK_DOMAIN,
                &prefix_items,
                output_byte_length,
            )
            .expect("fixed-hash reader initializes");
            let mut actual = vec![0_u8; output_byte_length];
            for fragment in actual.chunks_mut(fragment_byte_length) {
                actual_reader.read(fragment).expect("fragment is in bounds");
            }
            actual_reader.finish().expect("all output was consumed");
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn fixed_hash_block_reader_binds_width_domains_ordinals_and_predecessors() {
        const SEED_DOMAIN: &str = "sealed-lattice/test/fixed-hash-width-seed/v1";
        const BLOCK_DOMAIN: &str = "sealed-lattice/test/fixed-hash-width-block/v1";
        const OTHER_BLOCK_DOMAIN: &str = "sealed-lattice/test/fixed-hash-width-other-block/v1";
        let prefix_items = [CanonicalItem::hash512([0x52; 64])];
        let mut short_reader =
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, BLOCK_DOMAIN, &prefix_items, 64)
                .expect("short reader initializes");
        let mut long_reader =
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, BLOCK_DOMAIN, &prefix_items, 65)
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
            canonical_foundation_tuple_hash_preimage(SEED_DOMAIN, &short_items)
                .expect("short preimage"),
            canonical_foundation_tuple_hash_preimage(SEED_DOMAIN, &long_items)
                .expect("long preimage"),
        );

        let expected =
            expected_fixed_hash_block_stream(SEED_DOMAIN, BLOCK_DOMAIN, &prefix_items, 129);
        let changed_domain =
            expected_fixed_hash_block_stream(SEED_DOMAIN, OTHER_BLOCK_DOMAIN, &prefix_items, 129);
        assert_ne!(expected, changed_domain);

        let mut seed_items = prefix_items.to_vec();
        seed_items.push(CanonicalItem::unsigned64(129));
        let seed = hash_foundation_tuple_512(SEED_DOMAIN, &seed_items)
            .expect("seed hash")
            .into_bytes();
        let first_block: [u8; Hash512::BYTE_LENGTH] = expected[..64]
            .try_into()
            .expect("first block has the fixed width");
        let correct_second_block = hash_foundation_tuple_512(
            BLOCK_DOMAIN,
            &[
                CanonicalItem::hash512(seed),
                CanonicalItem::hash512(first_block),
                CanonicalItem::unsigned64(129),
                CanonicalItem::unsigned64(1),
            ],
        )
        .expect("correct second block");
        let wrong_predecessor = hash_foundation_tuple_512(
            BLOCK_DOMAIN,
            &[
                CanonicalItem::hash512(seed),
                CanonicalItem::hash512([0x91; Hash512::BYTE_LENGTH]),
                CanonicalItem::unsigned64(129),
                CanonicalItem::unsigned64(1),
            ],
        )
        .expect("changed-predecessor block");
        let wrong_ordinal = hash_foundation_tuple_512(
            BLOCK_DOMAIN,
            &[
                CanonicalItem::hash512(seed),
                CanonicalItem::hash512(first_block),
                CanonicalItem::unsigned64(129),
                CanonicalItem::unsigned64(2),
            ],
        )
        .expect("changed-ordinal block");
        assert_eq!(correct_second_block.as_bytes(), &expected[64..128]);
        assert_ne!(correct_second_block, wrong_predecessor);
        assert_ne!(correct_second_block, wrong_ordinal);
    }

    #[test]
    fn fixed_hash_block_reader_discard_preserves_the_exact_stream_suffix() {
        const SEED_DOMAIN: &str = "sealed-lattice/test/fixed-hash-discard-seed/v1";
        const BLOCK_DOMAIN: &str = "sealed-lattice/test/fixed-hash-discard-block/v1";
        let prefix_items = [CanonicalItem::unsigned64(17)];
        let output_byte_length = 777_usize;
        let discarded_prefix_byte_length = 513_usize;
        let mut complete_reader = FoundationTupleHash512BlockReader::new(
            SEED_DOMAIN,
            BLOCK_DOMAIN,
            &prefix_items,
            output_byte_length,
        )
        .expect("complete reader initializes");
        let mut complete_output = vec![0_u8; output_byte_length];
        complete_reader
            .read(&mut complete_output)
            .expect("complete output fits");
        complete_reader.finish().expect("complete output consumed");

        let mut discarded_reader = FoundationTupleHash512BlockReader::new(
            SEED_DOMAIN,
            BLOCK_DOMAIN,
            &prefix_items,
            output_byte_length,
        )
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
    fn fixed_hash_block_reader_counts_blocks_and_refuses_invalid_streams() {
        assert_eq!(foundation_tuple_hash512_block_count(1), Ok(1));
        assert_eq!(foundation_tuple_hash512_block_count(64), Ok(1));
        assert_eq!(foundation_tuple_hash512_block_count(65), Ok(2));
        assert_eq!(foundation_tuple_hash512_block_count(402_432), Ok(6_288));
        assert_eq!(foundation_tuple_hash512_seeded_stream_query_count(1), Ok(2));
        assert_eq!(
            foundation_tuple_hash512_seeded_stream_query_count(64),
            Ok(2)
        );
        assert_eq!(
            foundation_tuple_hash512_seeded_stream_query_count(65),
            Ok(3)
        );
        assert_eq!(
            foundation_tuple_hash512_seeded_stream_query_count(402_432),
            Ok(6_289)
        );
        assert_eq!(
            foundation_tuple_hash512_block_count(0),
            Err(StreamingFoundationHashError::OutputIncomplete),
        );

        const SEED_DOMAIN: &str = "sealed-lattice/test/fixed-hash-errors-seed/v1";
        const BLOCK_DOMAIN: &str = "sealed-lattice/test/fixed-hash-errors-block/v1";
        assert!(matches!(
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, BLOCK_DOMAIN, &[], 0),
            Err(StreamingFoundationHashError::OutputIncomplete),
        ));

        let mut overrun = FoundationTupleHash512BlockReader::new(SEED_DOMAIN, BLOCK_DOMAIN, &[], 2)
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
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, BLOCK_DOMAIN, &[], 2)
                .expect("reader initializes");
        incomplete.read(&mut [0_u8; 1]).expect("prefix fits");
        assert_eq!(
            incomplete.finish(),
            Err(StreamingFoundationHashError::OutputIncomplete),
        );

        assert!(matches!(
            FoundationTupleHash512BlockReader::new("", BLOCK_DOMAIN, &[], 1),
            Err(StreamingFoundationHashError::InvalidDomain),
        ));
        assert!(matches!(
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, "sealed-lattice/test\n", &[], 1),
            Err(StreamingFoundationHashError::InvalidDomain),
        ));
        assert!(matches!(
            FoundationTupleHash512BlockReader::new(SEED_DOMAIN, SEED_DOMAIN, &[], 1),
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
