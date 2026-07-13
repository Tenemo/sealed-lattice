use std::sync::{Mutex, OnceLock};

use super::{
    CanonicalDecodeLimits, CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    FOUNDATION_PROFILE, MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, RefusalReason, StreamDescriptor,
    canonical_stream::VerifiedCanonicalStreamSummary,
};

pub(crate) const CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE: u32 = u32::MAX;
pub(crate) const CANONICAL_STREAM_RUNTIME_INVALID_SESSION: u32 = u32::MAX - 1;

const MAXIMUM_CANONICAL_STREAM_CHUNK_COUNT: usize = (MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH as usize)
    .div_ceil(FOUNDATION_PROFILE.stream_chunk_byte_length);
pub(crate) const MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH: usize =
    104 + 64 * MAXIMUM_CANONICAL_STREAM_CHUNK_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalStreamRuntimeBegin {
    pub handle: u32,
    pub total_byte_length: u32,
    pub chunk_count: u32,
}

enum CanonicalStreamRuntimeSessionKind {
    Writer(Box<CanonicalStreamWriter>),
    Verifier(Box<CanonicalStreamVerifier>),
}

struct CanonicalStreamRuntimeSession {
    handle: u32,
    kind: CanonicalStreamRuntimeSessionKind,
}

struct CanonicalStreamRuntimeRegistry {
    active_session: Option<CanonicalStreamRuntimeSession>,
    next_handle: u32,
}

impl Default for CanonicalStreamRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_handle: 1,
        }
    }
}

impl CanonicalStreamRuntimeRegistry {
    fn begin_writer(
        &mut self,
        stream_domain_code: u32,
        total_byte_length: u32,
    ) -> Result<CanonicalStreamRuntimeBegin, u32> {
        self.refuse_overlapping_begin()?;
        let stream_domain = stream_domain(stream_domain_code)?;
        let writer = CanonicalStreamWriter::new(stream_domain, u64::from(total_byte_length))
            .map_err(refusal_status)?;
        let chunk_count = canonical_stream_chunk_count(u64::from(total_byte_length))?;
        let handle = self.take_handle()?;
        self.active_session = Some(CanonicalStreamRuntimeSession {
            handle,
            kind: CanonicalStreamRuntimeSessionKind::Writer(Box::new(writer)),
        });
        Ok(CanonicalStreamRuntimeBegin {
            handle,
            total_byte_length,
            chunk_count,
        })
    }

    fn begin_verifier(
        &mut self,
        stream_domain_code: u32,
        descriptor_bytes: &[u8],
    ) -> Result<CanonicalStreamRuntimeBegin, u32> {
        self.refuse_overlapping_begin()?;
        if descriptor_bytes.len() > MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let stream_domain = stream_domain(stream_domain_code)?;
        let descriptor = StreamDescriptor::decode(descriptor_bytes, &descriptor_decode_limits())
            .map_err(|error| refusal_status(error.refusal_reason))?;
        let total_byte_length = u32::try_from(descriptor.total_byte_length)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let chunk_count = u32::try_from(descriptor.ordered_chunk_digests.len())
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let verifier =
            CanonicalStreamVerifier::new(stream_domain, descriptor).map_err(refusal_status)?;
        let handle = self.take_handle()?;
        self.active_session = Some(CanonicalStreamRuntimeSession {
            handle,
            kind: CanonicalStreamRuntimeSessionKind::Verifier(Box::new(verifier)),
        });
        Ok(CanonicalStreamRuntimeBegin {
            handle,
            total_byte_length,
            chunk_count,
        })
    }

    fn absorb_chunk(
        &mut self,
        handle: u32,
        chunk_index: u32,
        chunk_bytes: &[u8],
    ) -> Result<(), u32> {
        let mut session = self.take_owned_session(handle)?;
        let result = match &mut session.kind {
            CanonicalStreamRuntimeSessionKind::Writer(writer) => writer
                .absorb_chunk(chunk_index as usize, chunk_bytes)
                .map_err(refusal_status),
            CanonicalStreamRuntimeSessionKind::Verifier(verifier) => verifier
                .absorb_chunk(chunk_index as usize, chunk_bytes)
                .into_result()
                .map_err(refusal_status),
        };
        if result.is_ok() {
            self.active_session = Some(session);
        }
        result
    }

    fn finish_writer(&mut self, handle: u32) -> Result<Vec<u8>, u32> {
        let session = self.take_owned_session(handle)?;
        let CanonicalStreamRuntimeSessionKind::Writer(writer) = session.kind else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        let descriptor = writer.finish().map_err(refusal_status)?;
        let encoded = descriptor
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?;
        if encoded.len() > MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH {
            return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
        }
        Ok(encoded)
    }

    fn finish_verifier(&mut self, handle: u32) -> Result<(), u32> {
        self.finish_verifier_with_summary(handle).map(|_| ())
    }

    fn finish_verifier_with_summary(
        &mut self,
        handle: u32,
    ) -> Result<VerifiedCanonicalStreamSummary, u32> {
        let session = self.take_owned_session(handle)?;
        let CanonicalStreamRuntimeSessionKind::Verifier(verifier) = session.kind else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        verifier
            .finish_with_summary()
            .into_result()
            .map_err(refusal_status)
    }

    fn cancel(&mut self, handle: u32) -> Result<(), u32> {
        let Some(session) = self.active_session.as_ref() else {
            return Ok(());
        };
        if session.handle == handle {
            self.active_session = None;
            Ok(())
        } else {
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION)
        }
    }

    fn refuse_overlapping_begin(&mut self) -> Result<(), u32> {
        if self.active_session.is_some() {
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        } else {
            Ok(())
        }
    }

    fn take_owned_session(&mut self, handle: u32) -> Result<CanonicalStreamRuntimeSession, u32> {
        let session = self
            .active_session
            .as_ref()
            .ok_or(CANONICAL_STREAM_RUNTIME_INVALID_SESSION)?;
        if session.handle != handle {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        }
        self.active_session
            .take()
            .ok_or(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
    }

    fn take_handle(&mut self) -> Result<u32, u32> {
        if self.next_handle == 0 {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).unwrap_or(0);
        Ok(handle)
    }
}

static CANONICAL_STREAM_RUNTIME_REGISTRY: OnceLock<Mutex<CanonicalStreamRuntimeRegistry>> =
    OnceLock::new();

fn runtime_registry() -> &'static Mutex<CanonicalStreamRuntimeRegistry> {
    CANONICAL_STREAM_RUNTIME_REGISTRY
        .get_or_init(|| Mutex::new(CanonicalStreamRuntimeRegistry::default()))
}

fn with_runtime_registry<ResultValue>(
    operation: impl FnOnce(&mut CanonicalStreamRuntimeRegistry) -> Result<ResultValue, u32>,
) -> Result<ResultValue, u32> {
    let mut registry = match runtime_registry().lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
        }
    };
    operation(&mut registry)
}

pub(crate) fn begin_canonical_stream_writer(
    stream_domain_code: u32,
    total_byte_length: u32,
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    with_runtime_registry(|registry| registry.begin_writer(stream_domain_code, total_byte_length))
}

pub(crate) fn begin_canonical_stream_verifier(
    stream_domain_code: u32,
    descriptor_bytes: &[u8],
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    with_runtime_registry(|registry| registry.begin_verifier(stream_domain_code, descriptor_bytes))
}

pub(crate) fn absorb_canonical_stream_chunk(
    handle: u32,
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.absorb_chunk(handle, chunk_index, chunk_bytes))
}

pub(crate) fn finish_canonical_stream_writer(handle: u32) -> Result<Vec<u8>, u32> {
    with_runtime_registry(|registry| registry.finish_writer(handle))
}

pub(crate) fn finish_canonical_stream_verifier(handle: u32) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.finish_verifier(handle))
}

pub(crate) fn finish_canonical_stream_verifier_with_summary(
    handle: u32,
) -> Result<VerifiedCanonicalStreamSummary, u32> {
    with_runtime_registry(|registry| registry.finish_verifier_with_summary(handle))
}

pub(crate) fn cancel_canonical_stream(handle: u32) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.cancel(handle))
}

fn stream_domain(stream_domain_code: u32) -> Result<CanonicalStreamDomain, u32> {
    CanonicalStreamDomain::from_canonical_code(stream_domain_code)
        .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))
}

fn canonical_stream_chunk_count(total_byte_length: u64) -> Result<u32, u32> {
    if total_byte_length == 0 || total_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
        return Err(refusal_status(if total_byte_length == 0 {
            RefusalReason::WrongTypeOrLength
        } else {
            RefusalReason::OutsideSupportedProfile
        }));
    }
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
    u32::try_from(total_byte_length.div_ceil(chunk_byte_length))
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
}

fn descriptor_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH,
        maximum_item_byte_length: MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH,
        maximum_cumulative_work_byte_length: MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH * 2,
        maximum_cumulative_allocation_byte_length: MAXIMUM_CANONICAL_STREAM_DESCRIPTOR_BYTE_LENGTH
            * 2,
        ..CanonicalDecodeLimits::default()
    }
}

fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    u32::from(refusal_reason.canonical_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(bytes: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
        bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
            .map(|(index, chunk)| (u32::try_from(index).expect("test chunk index"), chunk))
    }

    #[test]
    fn writer_and_verifier_round_trip_by_handle() {
        let bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 31)
            .map(|index| (index.wrapping_mul(173) & 0xff) as u8)
            .collect::<Vec<_>>();
        let mut registry = CanonicalStreamRuntimeRegistry::default();
        let writer = registry
            .begin_writer(
                CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(),
                u32::try_from(bytes.len()).expect("test byte length"),
            )
            .expect("writer begins");
        for (chunk_index, chunk) in chunks(&bytes) {
            registry
                .absorb_chunk(writer.handle, chunk_index, chunk)
                .expect("writer absorbs chunk");
        }
        let descriptor = registry
            .finish_writer(writer.handle)
            .expect("writer finishes");

        let verifier = registry
            .begin_verifier(
                CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(),
                &descriptor,
            )
            .expect("verifier begins");
        assert_eq!(verifier.total_byte_length as usize, bytes.len());
        assert_eq!(verifier.chunk_count, 2);
        for (chunk_index, chunk) in chunks(&bytes) {
            registry
                .absorb_chunk(verifier.handle, chunk_index, chunk)
                .expect("verifier absorbs chunk");
        }
        registry
            .finish_verifier(verifier.handle)
            .expect("verifier finishes");
        assert!(registry.active_session.is_none());
    }

    #[test]
    fn failed_operations_are_terminal_but_overlap_is_not() {
        let mut registry = CanonicalStreamRuntimeRegistry::default();
        let first = registry
            .begin_writer(CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(), 17)
            .expect("first writer begins");
        assert_eq!(
            registry.begin_writer(CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(), 17),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );
        registry
            .absorb_chunk(first.handle, 0, &[0; 17])
            .expect("the original writer remains active");
        registry
            .finish_writer(first.handle)
            .expect("the original writer finishes");

        let second = registry
            .begin_writer(CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(), 17)
            .expect("second writer begins");
        assert_eq!(
            registry.absorb_chunk(second.handle, 1, &[0; 17]),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
        assert!(registry.active_session.is_none());
    }

    #[test]
    fn malformed_domains_descriptors_and_lengths_are_rejected() {
        let mut registry = CanonicalStreamRuntimeRegistry::default();
        assert_eq!(
            registry.begin_writer(0, 1),
            Err(refusal_status(RefusalReason::MalformedEncoding))
        );
        assert_eq!(
            registry.begin_writer(CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(), 0),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
        assert_eq!(
            registry.begin_verifier(
                CanonicalStreamDomain::EvaluatorKeyStore.canonical_code(),
                &[0; 12],
            ),
            Err(refusal_status(RefusalReason::MalformedEncoding))
        );
    }
}
