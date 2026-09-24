use crate::{Error, foundation::hash::StreamingFoundationTupleHash512};

pub const CONTEXT_BYTES: usize = 136;
pub const HEADER_BYTES: usize = 12 + CONTEXT_BYTES;
pub const MINIMUM_PROOF_BYTES: usize = 4004;
pub const MAXIMUM_PROOF_BYTES: usize = 11_105_120;
pub const CIPHERTEXT_BYTES: usize = 2 * 65536 * 109 + 2 * 4096 * 6;
pub const BODY_DOMAIN: &str = "sealed-lattice/ballot-body/v1";

pub fn header(context: &[u8], proof_length: usize) -> Result<Vec<u8>, Error> {
    if context.len() != CONTEXT_BYTES
        || &context[..4] != b"LBS1"
        || !(2..=20).contains(&context[134])
        || context[135] == 0
        || context[135] > context[134]
        || u16::from_le_bytes(context[132..134].try_into().unwrap()) >= 20
        || !(MINIMUM_PROOF_BYTES..=MAXIMUM_PROOF_BYTES).contains(&proof_length)
    {
        return Err(Error::Shape);
    }
    let mut bytes = Vec::from(b"LBB1".as_slice());
    bytes.extend((proof_length as u64).to_le_bytes());
    bytes.extend(context);
    Ok(bytes)
}
pub fn proof_length(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() != HEADER_BYTES || &bytes[..4] != b"LBB1" {
        return Err(Error::Shape);
    }
    let length = usize::try_from(u64::from_le_bytes(bytes[4..12].try_into().unwrap()))
        .map_err(|_| Error::Shape)?;
    if header(&bytes[12..], length)? != bytes {
        return Err(Error::Shape);
    }
    Ok(length)
}
pub fn polynomial(ordinal: usize) -> Option<(usize, usize)> {
    match ordinal {
        0 => Some((2, 65536 * 109)),
        1 => Some((3, 65536 * 109)),
        2 => Some((6, 4096 * 6)),
        3 => Some((7, 4096 * 6)),
        _ => None,
    }
}
/// Computes the exact framed body identity; it supplies no proof or signing authority.
pub struct BallotBodyHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    remaining: usize,
}
impl BallotBodyHasher {
    pub fn new(header: &[u8]) -> Result<Self, Error> {
        let remaining = CIPHERTEXT_BYTES + proof_length(header)?;
        let mut hash = Self::for_body_length(HEADER_BYTES + remaining)?;
        hash.push(header)?;
        Ok(hash)
    }
    /// Hashes the committed bytes even if their inner header or proof is malformed.
    /// Completion supplies a byte identity, not semantic validity.
    pub fn for_body_length(length: usize) -> Result<Self, Error> {
        if !(HEADER_BYTES + CIPHERTEXT_BYTES + MINIMUM_PROOF_BYTES
            ..=HEADER_BYTES + CIPHERTEXT_BYTES + MAXIMUM_PROOF_BYTES)
            .contains(&length)
        {
            return Err(Error::Shape);
        }
        let hash = StreamingFoundationTupleHash512::new_variable_bytes(BODY_DOMAIN, &[], length)
            .map_err(|_| Error::Shape)?;
        Ok(Self {
            hash: Some(hash),
            remaining: length,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > 1 << 20 || bytes.len() > self.remaining {
            self.hash = None;
            return Err(Error::Shape);
        }
        self.hash
            .as_mut()
            .ok_or(Error::Consumed)?
            .absorb(bytes)
            .map_err(|_| Error::Shape)?;
        self.remaining -= bytes.len();
        Ok(())
    }
    pub fn finish(mut self) -> Result<[u8; 64], Error> {
        if self.remaining != 0 {
            return Err(Error::Shape);
        }
        self.hash
            .take()
            .ok_or(Error::Consumed)?
            .finalize()
            .map(|hash| hash.into_bytes())
            .map_err(|_| Error::Shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_refuses_unsupported_contexts_and_proof_lengths() {
        let mut context = vec![0; CONTEXT_BYTES];
        context[..4].copy_from_slice(b"LBS1");
        context[134] = 10;
        context[135] = 10;
        for length in [MINIMUM_PROOF_BYTES, MAXIMUM_PROOF_BYTES] {
            let bytes = header(&context, length).unwrap();
            assert_eq!(proof_length(&bytes).unwrap(), length);
        }
        for length in [MINIMUM_PROOF_BYTES - 1, MAXIMUM_PROOF_BYTES + 1, usize::MAX] {
            assert!(header(&context, length).is_err());
        }
        context[135] = 11;
        assert!(header(&context, MINIMUM_PROOF_BYTES).is_err());
        context[135] = 1;
        context[132] = 20;
        assert!(header(&context, MINIMUM_PROOF_BYTES).is_err());
    }
    #[test]
    fn incomplete_oversized_and_excess_streams_cannot_return_a_digest() {
        let mut context = vec![0; CONTEXT_BYTES];
        context[..4].copy_from_slice(b"LBS1");
        context[134] = 2;
        context[135] = 1;
        let header = header(&context, MINIMUM_PROOF_BYTES).unwrap();
        assert!(BallotBodyHasher::new(&header).unwrap().finish().is_err());
        let mut hasher = BallotBodyHasher::new(&header).unwrap();
        assert!(hasher.push(&vec![0; (1 << 20) + 1]).is_err());
        assert!(hasher.finish().is_err());
        let mut hasher = BallotBodyHasher::new(&header).unwrap();
        let bytes = vec![0; 1 << 20];
        while hasher.remaining > 0 {
            let count = bytes.len().min(hasher.remaining);
            hasher.push(&bytes[..count]).unwrap();
        }
        assert!(hasher.push(&[0]).is_err());
        assert!(hasher.finish().is_err());
    }
}
