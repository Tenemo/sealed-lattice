/// Random-access byte reads over a retained canonical proof stream.
///
/// Implementations expose only length-checked copies. Incremental verifiers
/// own all cursor movement and never require the source to join its chunks.
pub(crate) trait ProofByteSource {
    fn byte_length(&self) -> usize;
    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool;
}

impl ProofByteSource for [u8] {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        let Some(source) = self.get(offset..end) else {
            return false;
        };
        destination.copy_from_slice(source);
        true
    }
}

impl ProofByteSource for Vec<u8> {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        self.as_slice().copy_bytes(offset, destination)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofDecodeError {
    EmptyProof,
    ProofByteCeilingExceeded,
    DeclaredLengthMismatch,
    Truncated,
}
