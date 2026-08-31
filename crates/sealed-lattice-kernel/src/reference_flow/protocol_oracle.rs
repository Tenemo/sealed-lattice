use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    Hash512,
};

use super::ProtocolResult;

const PROTOCOL_ORACLE_CUSTOMIZATION: &[u8] = b"sealed-lattice/protocol-oracle/v1";

pub(crate) fn protocol_oracle_512(
    domain: &str,
    items: &[CanonicalItem],
) -> ProtocolResult<Hash512> {
    let mut reader = protocol_oracle_reader(domain, items)?;
    let mut output = [0_u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512::from_bytes(output))
}

pub(crate) fn protocol_oracle_output<const OUTPUT_BYTE_LENGTH: usize>(
    domain: &str,
    items: &[CanonicalItem],
) -> ProtocolResult<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut reader = protocol_oracle_reader(domain, items)?;
    let mut output = [0_u8; OUTPUT_BYTE_LENGTH];
    reader.read(&mut output);
    Ok(output)
}

pub(crate) struct ProtocolOracleReader(sha3::CShake256Reader);

impl ProtocolOracleReader {
    pub(crate) fn new(domain: &str, items: &[CanonicalItem]) -> ProtocolResult<Self> {
        Ok(Self(protocol_oracle_reader(domain, items)?))
    }

    pub(crate) fn fill(&mut self, output: &mut [u8]) {
        self.0.read(output);
    }
}

fn protocol_oracle_reader(
    domain: &str,
    items: &[CanonicalItem],
) -> ProtocolResult<sha3::CShake256Reader> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(domain)?);
    framed_items.extend_from_slice(items);
    let preimage = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()?;

    let core = CShake256Core::new(PROTOCOL_ORACLE_CUSTOMIZATION);
    let mut state = CShake256::from_core(core);
    state.update(&preimage);
    Ok(state.finalize_xof())
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    #[test]
    fn oracle_matches_manual_customized_cshake_framing() {
        let items = [
            CanonicalItem::hash512([0x31; 64]),
            CanonicalItem::unsigned64(17),
        ];
        let actual = protocol_oracle_512("sealed-lattice/test/oracle/v1", &items)
            .expect("oracle input is canonical");

        let mut framed_items = vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/test/oracle/v1")
                .expect("domain is canonical"),
        ];
        framed_items.extend_from_slice(&items);
        let preimage = CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            framed_items,
        )
        .encode()
        .expect("frame encodes");
        let core = CShake256Core::new(PROTOCOL_ORACLE_CUSTOMIZATION);
        let mut state = CShake256::from_core(core);
        state.update(&preimage);
        let mut expected = [0_u8; Hash512::BYTE_LENGTH];
        state.finalize_xof().read(&mut expected);
        assert_eq!(actual, Hash512::from_bytes(expected));
    }

    #[test]
    fn customized_protocol_oracle_is_not_the_foundation_raw_shake() {
        let domain = "sealed-lattice/test/oracle/v1";
        let items = [CanonicalItem::unsigned16(9)];
        let actual = protocol_oracle_512(domain, &items).expect("oracle input is canonical");

        let mut framed_items = vec![CanonicalItem::nonempty_ascii(domain).expect("domain")];
        framed_items.extend_from_slice(&items);
        let preimage = CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            framed_items,
        )
        .encode()
        .expect("frame encodes");
        let mut raw = Shake256::default();
        raw.update(&preimage);
        let mut raw_output = [0_u8; Hash512::BYTE_LENGTH];
        raw.finalize_xof().read(&mut raw_output);
        assert_ne!(actual, Hash512::from_bytes(raw_output));
    }

    #[test]
    fn reader_continuation_matches_one_shot_read() {
        let items = [CanonicalItem::fixed_bytes([0x82; 32]).expect("seed")];
        let mut split = ProtocolOracleReader::new("sealed-lattice/test/tape/v1", &items)
            .expect("reader initializes");
        let mut first = [0_u8; 13];
        let mut second = [0_u8; 79];
        split.fill(&mut first);
        split.fill(&mut second);

        let mut whole = ProtocolOracleReader::new("sealed-lattice/test/tape/v1", &items)
            .expect("reader initializes");
        let mut expected = [0_u8; 92];
        whole.fill(&mut expected);
        assert_eq!([first.as_slice(), second.as_slice()].concat(), expected);
    }
}
