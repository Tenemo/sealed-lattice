use purpose_signature as primitive;

pub const SEED_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 64;
pub const SIGNATURE_BYTES: usize = primitive::SIGNATURE_BYTES;

pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self(bytes)
    }
    pub fn into_bytes(self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0
    }
    pub fn verify(&self, message: &[u8], signature: &[u8], context: &[u8]) -> bool {
        primitive::verify_context(&self.0, context, message, signature)
    }
}

pub struct SigningKey(primitive::Credential);

impl SigningKey {
    pub fn sign(
        &mut self,
        message: &[u8],
        context: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], &'static str> {
        self.0
            .sign_context(context, message)?
            .try_into()
            .map_err(|_| "Signature length")
    }
}

pub fn keypair_from_seed(seed: &[u8; SEED_BYTES]) -> (PublicKey, SigningKey) {
    let key = primitive::Credential::new(*seed);
    (PublicKey(key.public_key()), SigningKey(key))
}
