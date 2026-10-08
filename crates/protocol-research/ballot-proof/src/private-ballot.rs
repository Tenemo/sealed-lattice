use crate::{
    columns,
    context::private_proof_role,
    proof::prove,
    statement::{PublicStatement, coefficient_bytes, encode_polynomial, setup_input},
};
use ballot_encryption::{context::BallotComputationContext, encryption::LinkedBallotWitness};
use registration_credentials::{ballot_authentication::BallotEnvelope, ballot_body};
use setup_aggregate::RetainedAggregatePolynomial;
use supported_profile::{
    Family,
    relation::{PROOF_HEADER_BYTES, ballot_relation},
};
use word_proof::oracles::Witness;

#[derive(Debug)]
pub enum Error {
    Context,
    Encoding,
    Proof,
}

fn verify_expanded(
    context: &ballot_encryption::context::BallotComputationContext,
    public: &PublicStatement,
    proof: &[u8],
) -> Result<(), Error> {
    let profile = context.profile();
    if !ballot_body::proof_lengths(profile).contains(&proof.len()) {
        return Err(Error::Encoding);
    }
    let role = private_proof_role(context).map_err(|_| Error::Context)?;
    let mut verifier = crate::verifier(
        profile,
        &role,
        public.digest(),
        &proof[..PROOF_HEADER_BYTES],
    )
    .map_err(|_| Error::Proof)?;
    verifier
        .push_statement(&public.header)
        .map_err(|_| Error::Proof)?;
    for polynomial in &public.polynomials {
        for bytes in polynomial.chunks(crate::CHUNK_LIMIT) {
            verifier.push_statement(bytes).map_err(|_| Error::Proof)?;
        }
    }
    verifier.finish_statement().map_err(|_| Error::Proof)?;
    for bytes in proof[PROOF_HEADER_BYTES..].chunks(crate::CHUNK_LIMIT) {
        verifier.push_proof(bytes).map_err(|_| Error::Proof)?;
    }
    if !verifier.finish() {
        return Err(Error::Proof);
    }
    Ok(())
}
fn envelope(
    context: &BallotComputationContext,
    ballot_time: u64,
    bytes: &[u8],
) -> Result<BallotEnvelope, Error> {
    let profile = context.profile();
    let mut hash = ballot_body::body_hasher(profile, bytes.len()).map_err(|_| Error::Encoding)?;
    for bytes in bytes.chunks(crate::CHUNK_LIMIT) {
        hash.push(bytes).map_err(|_| Error::Encoding)?;
    }
    BallotEnvelope::new(
        profile,
        context.poll().identity(),
        *context.setup_identity(),
        context.position(),
        ballot_time,
        bytes.len(),
        hash.finish().map_err(|_| Error::Encoding)?,
    )
    .map_err(|_| Error::Context)
}

/// Whether this build is a corrupt participant's, whose ballot creation
/// proves a false statement. An honest consumer asserts that it is not, so
/// Cargo's feature unification cannot bring the feature into its build.
pub const FALSE_STATEMENT: bool = cfg!(feature = "invalid-ballot");

/// A corrupt participant's runtime changes one ciphertext coefficient by one
/// before proving, so its proof cannot meet the affine relation and the
/// ballot it signs is authentic and invalid.
#[cfg(feature = "invalid-ballot")]
fn falsify(mut public: PublicStatement) -> PublicStatement {
    public.polynomials[2][1] ^= 1;
    public
}

/// Executes and checks one private computation under original retained inputs.
/// It returns public bytes and an envelope, never a public setup capability.
/// The ballot time was fixed when the attempt was locked.
pub fn create(
    context: BallotComputationContext,
    fhe: RetainedAggregatePolynomial,
    scores: &[u8],
    ballot_time: u64,
) -> Result<(Vec<u8>, BallotEnvelope), Error> {
    let encryption = LinkedBallotWitness::create_with_context(context, fhe, scores)
        .map_err(|_| Error::Context)?;
    let profile = encryption.context.profile();
    let public = PublicStatement::from_encryption(&encryption).map_err(|_| Error::Encoding)?;
    #[cfg(feature = "invalid-ballot")]
    let public = falsify(public);
    let mut columns = columns::from_encryption(&encryption).map_err(|_| Error::Encoding)?;
    let witness = Witness::from_columns(
        &ballot_relation(profile),
        public.digest(),
        std::mem::take(&mut *columns),
    )
    .map_err(|_| Error::Encoding)?;
    let role = private_proof_role(&encryption.context).map_err(|_| Error::Context)?;
    let context = encryption.into_context();
    let proof = prove(&role, &public, witness, FALSE_STATEMENT);
    let mut proof_bytes = Vec::with_capacity(*ballot_body::proof_lengths(profile).end());
    proof.write(&mut proof_bytes);
    drop(proof);
    if !FALSE_STATEMENT {
        verify_expanded(&context, &public, &proof_bytes)?;
    }
    let mut body = ballot_body::header(profile, &public.header, proof_bytes.len())
        .map_err(|_| Error::Encoding)?;
    body.reserve_exact(ballot_body::ciphertext_bytes(profile) + proof_bytes.len());
    for (index, _) in ballot_body::polynomials(profile) {
        body.extend(&public.polynomials[index]);
    }
    body.extend(proof_bytes);
    let envelope = envelope(&context, ballot_time, &body)?;
    Ok((body, envelope))
}

/// Verifies a bounded retained body using immutable original input values.
/// The caller must first authenticate its current participant root and records.
pub fn verify(
    context: &BallotComputationContext,
    key: &RetainedAggregatePolynomial,
    body: &[u8],
    ballot_time: u64,
) -> Result<BallotEnvelope, Error> {
    let profile = context.profile();
    let header = body
        .get(..ballot_body::HEADER_BYTES)
        .ok_or(Error::Encoding)?;
    let proof_length = ballot_body::proof_length(profile, header).map_err(|_| Error::Encoding)?;
    if body.len()
        != ballot_body::HEADER_BYTES + ballot_body::ciphertext_bytes(profile) + proof_length
    {
        return Err(Error::Encoding);
    }
    let statement = &header[12..];
    if statement[4..68] != context.poll().identity()
        || statement[68..132] != *context.setup_identity()
        || u16::from_le_bytes(statement[132..134].try_into().unwrap()) as usize
            != context.position()
        || statement[134] as usize != context.poll().manifest().option_count()
        || u16::from(statement[135]) != context.poll().top_count()
    {
        return Err(Error::Context);
    }
    let mut polynomials = Vec::with_capacity(8);
    let mut offset = ballot_body::HEADER_BYTES;
    let (_, common, index) = setup_input(profile);
    if key.index() != index
        || key.setup_identity() != context.setup_identity()
        || key.coefficients().len() != profile.family_degree(Family::Fhe)
    {
        return Err(Error::Context);
    }
    for (family, common, public_key) in [
        (
            Family::Fhe,
            setup_witness::contribution::common_records(profile, common)
                .map_err(|_| Error::Encoding)?,
            encode_polynomial(key.coefficients(), coefficient_bytes(profile, Family::Fhe))
                .map_err(|_| Error::Encoding)?,
        ),
        (
            Family::Auxiliary,
            setup_witness::fixed_auxiliary::common_records(),
            setup_witness::fixed_auxiliary::public_key_records(),
        ),
    ] {
        let width = coefficient_bytes(profile, family);
        let degree = profile.family_degree(family);
        polynomials.push(common);
        polynomials.push(public_key);
        for _ in 0..2 {
            polynomials.push(body[offset..offset + degree * width].to_vec());
            offset += degree * width;
        }
    }
    let public = PublicStatement {
        profile,
        header: statement.to_vec(),
        polynomials,
    };
    verify_expanded(context, &public, &body[offset..])?;
    envelope(context, ballot_time, body)
}
