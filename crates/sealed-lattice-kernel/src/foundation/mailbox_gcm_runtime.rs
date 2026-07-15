use std::sync::{Mutex, OnceLock};

use super::{
    RefusalReason,
    mailbox_gcm::{
        MAILBOX_GCM_KEY_BYTE_LENGTH, MAILBOX_GCM_NONCE_BYTE_LENGTH, MAILBOX_GCM_TAG_BYTE_LENGTH,
        MailboxGcmDecryptor, MailboxGcmEncryptor, MailboxGcmVerifier,
    },
};

pub(crate) const MAILBOX_GCM_RUNTIME_INTERNAL_FAILURE: u32 = u32::MAX;
pub(crate) const MAILBOX_GCM_RUNTIME_INVALID_SESSION: u32 = u32::MAX - 1;
pub(crate) const MAXIMUM_MAILBOX_GCM_ASSOCIATED_DATA_BYTE_LENGTH: usize = 65_536;

enum MailboxGcmRuntimeSessionKind {
    Encryptor(Box<MailboxGcmEncryptor>),
    Verifier(Box<MailboxGcmVerifier>),
    Decryptor(Box<MailboxGcmDecryptor>),
}

struct MailboxGcmRuntimeSession {
    handle: u32,
    kind: MailboxGcmRuntimeSessionKind,
}

struct MailboxGcmRuntimeRegistry {
    active_session: Option<MailboxGcmRuntimeSession>,
    next_handle: u32,
}

impl Default for MailboxGcmRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_handle: 1,
        }
    }
}

impl MailboxGcmRuntimeRegistry {
    fn begin_encryptor(
        &mut self,
        key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        total_byte_length: u32,
    ) -> Result<u32, u32> {
        self.refuse_overlapping_begin()?;
        require_associated_data_length(associated_data)?;
        let encryptor =
            MailboxGcmEncryptor::new(key, nonce, associated_data, u64::from(total_byte_length))
                .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = self.take_handle()?;
        self.active_session = Some(MailboxGcmRuntimeSession {
            handle,
            kind: MailboxGcmRuntimeSessionKind::Encryptor(Box::new(encryptor)),
        });
        Ok(handle)
    }

    fn begin_verifier(
        &mut self,
        key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        total_byte_length: u32,
    ) -> Result<u32, u32> {
        self.refuse_overlapping_begin()?;
        require_associated_data_length(associated_data)?;
        let verifier =
            MailboxGcmVerifier::new(key, nonce, associated_data, u64::from(total_byte_length))
                .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = self.take_handle()?;
        self.active_session = Some(MailboxGcmRuntimeSession {
            handle,
            kind: MailboxGcmRuntimeSessionKind::Verifier(Box::new(verifier)),
        });
        Ok(handle)
    }

    fn encrypt_chunk(&mut self, handle: u32, bytes: &mut [u8]) -> Result<(), u32> {
        let mut session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Encryptor(encryptor) = &mut session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        let result = encryptor
            .encrypt_chunk(bytes)
            .map_err(|error| refusal_status(error.refusal_reason));
        if result.is_ok() {
            self.active_session = Some(session);
        }
        result
    }

    fn authenticate_chunk(&mut self, handle: u32, bytes: &[u8]) -> Result<(), u32> {
        let mut session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Verifier(verifier) = &mut session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        let result = verifier
            .absorb_ciphertext(bytes)
            .map_err(|error| refusal_status(error.refusal_reason));
        if result.is_ok() {
            self.active_session = Some(session);
        }
        result
    }

    fn finish_encryptor(&mut self, handle: u32) -> Result<[u8; MAILBOX_GCM_TAG_BYTE_LENGTH], u32> {
        let session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Encryptor(encryptor) = session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        encryptor
            .finish()
            .map_err(|error| refusal_status(error.refusal_reason))
    }

    fn finish_authentication(
        &mut self,
        handle: u32,
        tag: &[u8; MAILBOX_GCM_TAG_BYTE_LENGTH],
    ) -> Result<(), u32> {
        let session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Verifier(verifier) = session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        let opening = verifier
            .finish(tag)
            .map_err(|error| refusal_status(error.refusal_reason))?;
        let decryptor = opening
            .begin_decryption()
            .map_err(|error| refusal_status(error.refusal_reason))?;
        self.active_session = Some(MailboxGcmRuntimeSession {
            handle,
            kind: MailboxGcmRuntimeSessionKind::Decryptor(Box::new(decryptor)),
        });
        Ok(())
    }

    fn decrypt_chunk(&mut self, handle: u32, bytes: &mut [u8]) -> Result<(), u32> {
        let mut session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Decryptor(decryptor) = &mut session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        let result = decryptor
            .decrypt_chunk(bytes)
            .map_err(|error| refusal_status(error.refusal_reason));
        if result.is_ok() {
            self.active_session = Some(session);
        }
        result
    }

    fn finish_decryptor(&mut self, handle: u32) -> Result<(), u32> {
        let session = self.take_owned_session(handle)?;
        let MailboxGcmRuntimeSessionKind::Decryptor(decryptor) = session.kind else {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        };
        decryptor
            .finish()
            .map_err(|error| refusal_status(error.refusal_reason))
    }

    fn cancel(&mut self, handle: u32) -> Result<(), u32> {
        let Some(session) = self.active_session.as_ref() else {
            return Ok(());
        };
        if session.handle != handle {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        }
        self.active_session = None;
        Ok(())
    }

    fn refuse_overlapping_begin(&self) -> Result<(), u32> {
        if self.active_session.is_some() {
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        } else {
            Ok(())
        }
    }

    fn take_owned_session(&mut self, handle: u32) -> Result<MailboxGcmRuntimeSession, u32> {
        let session = self
            .active_session
            .as_ref()
            .ok_or(MAILBOX_GCM_RUNTIME_INVALID_SESSION)?;
        if session.handle != handle {
            return Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION);
        }
        self.active_session
            .take()
            .ok_or(MAILBOX_GCM_RUNTIME_INTERNAL_FAILURE)
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

static MAILBOX_GCM_RUNTIME_REGISTRY: OnceLock<Mutex<MailboxGcmRuntimeRegistry>> = OnceLock::new();

fn runtime_registry() -> &'static Mutex<MailboxGcmRuntimeRegistry> {
    MAILBOX_GCM_RUNTIME_REGISTRY.get_or_init(|| Mutex::new(MailboxGcmRuntimeRegistry::default()))
}

fn with_runtime_registry<ResultValue>(
    operation: impl FnOnce(&mut MailboxGcmRuntimeRegistry) -> Result<ResultValue, u32>,
) -> Result<ResultValue, u32> {
    let mut registry = match runtime_registry().lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(MAILBOX_GCM_RUNTIME_INTERNAL_FAILURE);
        }
    };
    operation(&mut registry)
}

pub(crate) fn begin_mailbox_gcm_encryptor(
    key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
    nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
    associated_data: &[u8],
    total_byte_length: u32,
) -> Result<u32, u32> {
    with_runtime_registry(|registry| {
        registry.begin_encryptor(key, nonce, associated_data, total_byte_length)
    })
}

pub(crate) fn begin_mailbox_gcm_verifier(
    key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
    nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
    associated_data: &[u8],
    total_byte_length: u32,
) -> Result<u32, u32> {
    with_runtime_registry(|registry| {
        registry.begin_verifier(key, nonce, associated_data, total_byte_length)
    })
}

pub(crate) fn encrypt_mailbox_gcm_chunk(handle: u32, bytes: &mut [u8]) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.encrypt_chunk(handle, bytes))
}

pub(crate) fn authenticate_mailbox_gcm_chunk(handle: u32, bytes: &[u8]) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.authenticate_chunk(handle, bytes))
}

pub(crate) fn finish_mailbox_gcm_encryptor(
    handle: u32,
) -> Result<[u8; MAILBOX_GCM_TAG_BYTE_LENGTH], u32> {
    with_runtime_registry(|registry| registry.finish_encryptor(handle))
}

pub(crate) fn finish_mailbox_gcm_authentication(
    handle: u32,
    tag: &[u8; MAILBOX_GCM_TAG_BYTE_LENGTH],
) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.finish_authentication(handle, tag))
}

pub(crate) fn decrypt_mailbox_gcm_chunk(handle: u32, bytes: &mut [u8]) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.decrypt_chunk(handle, bytes))
}

pub(crate) fn finish_mailbox_gcm_decryptor(handle: u32) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.finish_decryptor(handle))
}

pub(crate) fn cancel_mailbox_gcm(handle: u32) -> Result<(), u32> {
    with_runtime_registry(|registry| registry.cancel(handle))
}

fn require_associated_data_length(associated_data: &[u8]) -> Result<(), u32> {
    if associated_data.is_empty()
        || associated_data.len() > MAXIMUM_MAILBOX_GCM_ASSOCIATED_DATA_BYTE_LENGTH
    {
        return Err(refusal_status(if associated_data.is_empty() {
            RefusalReason::WrongTypeOrLength
        } else {
            RefusalReason::OutsideSupportedProfile
        }));
    }
    Ok(())
}

fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    u32::from(refusal_reason.canonical_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_requires_authentication_before_decryption() {
        let key = [0x31_u8; MAILBOX_GCM_KEY_BYTE_LENGTH];
        let nonce = [0x42_u8; MAILBOX_GCM_NONCE_BYTE_LENGTH];
        let associated_data = b"mailbox associated data";
        let plaintext = b"fragmented mailbox plaintext";
        let mut registry = MailboxGcmRuntimeRegistry::default();

        let encryptor = registry
            .begin_encryptor(
                key,
                nonce,
                associated_data,
                u32::try_from(plaintext.len()).expect("test length"),
            )
            .expect("encryptor begins");
        let mut ciphertext = plaintext.to_vec();
        for fragment in ciphertext.chunks_mut(5) {
            registry
                .encrypt_chunk(encryptor, fragment)
                .expect("fragment encrypts");
        }
        let tag = registry
            .finish_encryptor(encryptor)
            .expect("encryptor finishes");

        let verifier = registry
            .begin_verifier(
                key,
                nonce,
                associated_data,
                u32::try_from(ciphertext.len()).expect("test length"),
            )
            .expect("verifier begins");
        assert_eq!(
            registry.decrypt_chunk(verifier, &mut ciphertext),
            Err(MAILBOX_GCM_RUNTIME_INVALID_SESSION)
        );
        assert!(registry.active_session.is_none());

        let verifier = registry
            .begin_verifier(
                key,
                nonce,
                associated_data,
                u32::try_from(ciphertext.len()).expect("test length"),
            )
            .expect("replacement verifier begins");
        for fragment in ciphertext.chunks(7) {
            registry
                .authenticate_chunk(verifier, fragment)
                .expect("fragment authenticates");
        }
        registry
            .finish_authentication(verifier, &tag)
            .expect("tag authenticates");
        for fragment in ciphertext.chunks_mut(3) {
            registry
                .decrypt_chunk(verifier, fragment)
                .expect("fragment decrypts");
        }
        registry
            .finish_decryptor(verifier)
            .expect("decryptor finishes");
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn failed_tag_is_terminal_and_never_creates_a_decryptor() {
        let mut registry = MailboxGcmRuntimeRegistry::default();
        let handle = registry
            .begin_verifier([0_u8; 32], [0_u8; 12], b"aad", 16)
            .expect("verifier begins");
        registry
            .authenticate_chunk(handle, &[0_u8; 16])
            .expect("ciphertext authenticates structurally");
        assert_eq!(
            registry.finish_authentication(handle, &[0_u8; 16]),
            Err(refusal_status(RefusalReason::InvalidArithmeticRelation))
        );
        assert!(registry.active_session.is_none());
    }
}
