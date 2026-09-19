use crate::{
    BodyHasher, Credential, foundation::RegistrationHeader, registration_proof_role,
    verify_registration_signature,
};
use sha3::{Digest, Sha3_512};
use std::cell::RefCell;
use zeroize::Zeroizing;

const CHUNK: usize = 1 << 20;
const KEY_BYTES: usize = 65536 * 21;

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    #[link(wasm_import_module = "credentials")]
    unsafe extern "C" {
        fn fill_random(pointer: *mut u8, length: usize) -> u32;
    }
    let mut value = Zeroizing::new([0; N]);
    assert_eq!(unsafe { fill_random(value.as_mut_ptr(), N) }, 0);
    value
}

struct Verification {
    username: Vec<u8>,
    proof_hash: Sha3_512,
    body: BodyHasher,
    signature: [u8; 3309],
    role: Vec<u8>,
    key_hash: Sha3_512,
    expected_key: [u8; 64],
    key_bytes: usize,
    key_verified: bool,
}
struct Session {
    input: Vec<u8>,
    credential: Option<Credential>,
    poll: [u8; 64],
    runtime: [u8; 64],
    username: Option<crate::foundation::StabilizedDisplayText>,
    verified_username: Vec<u8>,
    verified_proof_hash: [u8; 64],
    verified_body_digest: [u8; 64],
    public: Vec<u8>,
    role: Vec<u8>,
    header: Vec<u8>,
    signature: Vec<u8>,
    signing: Option<BodyHasher>,
    signing_started: bool,
    verification: Option<Verification>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;CHUNK],credential:None,poll:[0;64],runtime:[0;64],username:None,verified_username:Vec::new(),verified_proof_hash:[0;64],verified_body_digest:[0;64],public:Vec::new(),role:Vec::new(),header:Vec::new(),signature:Vec::new(),signing:None,signing_started:false,verification:None});}

#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn public_pointer() -> usize {
    SESSION.with(|state| state.borrow().public.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn role_pointer() -> usize {
    SESSION.with(|state| state.borrow().role.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn role_length() -> usize {
    SESSION.with(|state| state.borrow().role.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn header_pointer() -> usize {
    SESSION.with(|state| state.borrow().header.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn header_length() -> usize {
    SESSION.with(|state| state.borrow().header.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn signature_pointer() -> usize {
    SESSION.with(|state| state.borrow().signature.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn signature_length() -> usize {
    SESSION.with(|state| state.borrow().signature.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn create(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if !(133..=644).contains(&length) || state.credential.is_some() {
            return 1;
        }
        let name_length = u32::from_le_bytes(state.input[128..132].try_into().unwrap()) as usize;
        if name_length != length - 132 {
            return 1;
        }
        let Ok(username) = crate::foundation::normalize_username(&state.input[132..length]) else {
            return 1;
        };
        let poll = state.input[..64].try_into().unwrap();
        let runtime = state.input[64..128].try_into().unwrap();
        let seeds = random::<96>();
        let credential = Credential::from_seeds(
            seeds[..32].try_into().unwrap(),
            seeds[32..64].try_into().unwrap(),
            seeds[64..].try_into().unwrap(),
        );
        state.public.extend(credential.signing_public());
        state.public.extend(credential.mailbox_public());
        state.role = credential.proof_role(poll, runtime);
        state.poll = poll;
        state.runtime = runtime;
        state.username = Some(username);
        state.credential = Some(credential);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn begin_sign(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if length != 68 || state.signing_started {
            return 1;
        }
        let Some(credential) = state.credential.as_ref() else {
            return 1;
        };
        let key_hash = state.input[..64].try_into().unwrap();
        let proof_length = u32::from_le_bytes(state.input[64..68].try_into().unwrap()) as usize;
        let header = RegistrationHeader {
            username: state.username.as_ref().unwrap().clone(),
            poll: state.poll,
            runtime: state.runtime,
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: key_hash,
            proof_length,
        }
        .encode();
        let Ok(header) = header else {
            return 1;
        };
        let Ok((body, consumed)) = BodyHasher::from_header(&header, state.poll, state.runtime)
        else {
            return 1;
        };
        if consumed != header.len() {
            return 1;
        }
        state.signing_started = true;
        state.header = header;
        state.signing = Some(body);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_sign(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(mut body) = state.signing.take() else {
            return 1;
        };
        if length > CHUNK || body.absorb(&state.input[..length]).is_err() {
            return 1;
        }
        state.signing = Some(body);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish_sign() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(body) = state.signing.take() else {
            return 1;
        };
        let Ok(body) = body.finish() else {
            return 1;
        };
        let randomness = random::<32>();
        let Some(credential) = state.credential.as_mut() else {
            return 1;
        };
        let Ok(signature) = credential.sign_registration(body, *randomness) else {
            return 1;
        };
        state.signature = signature.to_vec();
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn begin_verify(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.verification = None;
        state.verified_username.clear();
        state.verified_proof_hash.fill(0);
        state.verified_body_digest.fill(0);
        if !(132 + 3309..=132 + 4096 + 3309).contains(&length) {
            return 1;
        }
        let poll = state.input[..64].try_into().unwrap();
        let runtime = state.input[64..128].try_into().unwrap();
        let header_length = u32::from_le_bytes(state.input[128..132].try_into().unwrap()) as usize;
        if header_length > 4096 || length != 132 + header_length + 3309 {
            return 1;
        }
        let header_bytes = &state.input[132..132 + header_length];
        let Ok((body, consumed)) = BodyHasher::from_header(header_bytes, poll, runtime) else {
            return 1;
        };
        if consumed != header_length {
            return 1;
        }
        let Ok((header, _)) = RegistrationHeader::decode_prefix(header_bytes) else {
            return 1;
        };
        let role = registration_proof_role(poll, runtime, &header.signing_public);
        let signature = state.input[132 + header_length..length].try_into().unwrap();
        state.verification = Some(Verification {
            username: header.username.as_str().as_bytes().to_vec(),
            proof_hash: Sha3_512::new(),
            body,
            signature,
            role,
            key_hash: Sha3_512::new(),
            expected_key: header.recipient_key_hash,
            key_bytes: 0,
            key_verified: false,
        });
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn verification_role_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .verification
            .as_ref()
            .map_or(0, |value| value.role.as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn verification_role_length() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .verification
            .as_ref()
            .map_or(0, |value| value.role.len())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn verified_username_pointer() -> usize {
    SESSION.with(|state| state.borrow().verified_username.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn verified_username_length() -> usize {
    SESSION.with(|state| state.borrow().verified_username.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn verified_proof_hash_pointer() -> usize {
    SESSION.with(|state| state.borrow().verified_proof_hash.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn verified_body_digest_pointer() -> usize {
    SESSION.with(|state| state.borrow().verified_body_digest.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_verify_key(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(mut verifier) = state.verification.take() else {
            return 1;
        };
        if verifier.key_verified || length > CHUNK || length > KEY_BYTES - verifier.key_bytes {
            return 1;
        }
        verifier.key_hash.update(&state.input[..length]);
        verifier.key_bytes += length;
        state.verification = Some(verifier);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish_verify_key() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(mut verifier) = state.verification.take() else {
            return 1;
        };
        if verifier.key_verified
            || verifier.key_bytes != KEY_BYTES
            || <[u8; 64]>::from(verifier.key_hash.clone().finalize()) != verifier.expected_key
        {
            return 1;
        }
        verifier.key_verified = true;
        state.verification = Some(verifier);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_verify_proof(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(mut verifier) = state.verification.take() else {
            return 1;
        };
        if !verifier.key_verified
            || length > CHUNK
            || verifier.body.absorb(&state.input[..length]).is_err()
        {
            return 1;
        }
        verifier.proof_hash.update(&state.input[..length]);
        state.verification = Some(verifier);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish_verify() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(verifier) = state.verification.take() else {
            return 0;
        };
        if !verifier.key_verified {
            return 0;
        }
        let Ok(body) = verifier.body.finish() else {
            return 0;
        };
        let digest = body.bytes();
        if !verify_registration_signature(body, &verifier.signature) {
            return 0;
        }
        state.verified_body_digest = digest;
        state.verified_proof_hash = verifier.proof_hash.finalize().into();
        state.verified_username = verifier.username;
        1
    })
}
