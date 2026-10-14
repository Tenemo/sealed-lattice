use crate::{
    columns,
    context::private_proof_role,
    proof::prove,
    statement::{PublicStatement, coefficient_bytes, encode_polynomial, setup_input},
};
use ballot_encryption::{context::BallotComputationContext, encryption::LinkedBallotWitness};
use protocol_foundations::{ballot_authentication::BallotEnvelope, ballot_body};
use setup_aggregate::RetainedAggregatePolynomial;
use supported_profile::{
    Family,
    relation::{PROOF_HEADER_BYTES, ballot_relation},
};
use word_proof::oracles::Witness;

#[derive(Debug)]
pub enum Refusal {
    Context,
    Encoding,
    Proof,
}

/// Verifies a proof, given as its header and the rest of its bytes, over
/// the expanded statement.
fn verify_expanded(
    context: &ballot_encryption::context::BallotComputationContext,
    public: &PublicStatement,
    proof_header: &[u8],
    proof: &[u8],
) -> Result<(), Refusal> {
    let profile = context.profile();
    if proof_header.len() != PROOF_HEADER_BYTES
        || !ballot_body::proof_lengths(profile).contains(&(PROOF_HEADER_BYTES + proof.len()))
    {
        return Err(Refusal::Encoding);
    }
    let role = private_proof_role(context).map_err(|_| Refusal::Context)?;
    let mut verifier = crate::verifier(profile, &role, proof_header).map_err(|_| Refusal::Proof)?;
    verifier
        .push_statement(&public.header)
        .map_err(|_| Refusal::Proof)?;
    for polynomial in &public.polynomials {
        for bytes in polynomial.chunks(crate::CHUNK_LIMIT) {
            verifier.push_statement(bytes).map_err(|_| Refusal::Proof)?;
        }
    }
    verifier.finish_statement().map_err(|_| Refusal::Proof)?;
    for bytes in proof.chunks(crate::CHUNK_LIMIT) {
        verifier.push_proof(bytes).map_err(|_| Refusal::Proof)?;
    }
    if !verifier.finish() {
        return Err(Refusal::Proof);
    }
    Ok(())
}
fn envelope(
    context: &BallotComputationContext,
    ballot_time: u64,
    bytes: &[u8],
) -> Result<BallotEnvelope, Refusal> {
    let profile = context.profile();
    let mut hash = ballot_body::body_hasher(profile, bytes.len()).map_err(|_| Refusal::Encoding)?;
    for bytes in bytes.chunks(crate::CHUNK_LIMIT) {
        hash.push(bytes).map_err(|_| Refusal::Encoding)?;
    }
    BallotEnvelope::new(
        profile,
        context.poll().identity(),
        *context.setup_identity(),
        context.position(),
        ballot_time,
        bytes.len(),
        hash.finish().map_err(|_| Refusal::Encoding)?,
    )
    .map_err(|_| Refusal::Context)
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
) -> Result<(Vec<u8>, BallotEnvelope), Refusal> {
    let encryption = LinkedBallotWitness::create_with_context(context, fhe, scores)
        .map_err(|_| Refusal::Context)?;
    let profile = encryption.context.profile();
    let public = PublicStatement::from_encryption(&encryption).map_err(|_| Refusal::Encoding)?;
    #[cfg(feature = "invalid-ballot")]
    let public = falsify(public);
    let mut columns = columns::from_encryption(&encryption).map_err(|_| Refusal::Encoding)?;
    let witness = Witness::from_columns(
        &ballot_relation(profile),
        public.digest(),
        std::mem::take(&mut *columns),
    )
    .map_err(|_| Refusal::Encoding)?;
    let role = private_proof_role(&encryption.context).map_err(|_| Refusal::Context)?;
    let context = encryption.into_context();
    let proof = prove(&role, &public, witness, FALSE_STATEMENT);
    let mut proof_bytes = Vec::with_capacity(*ballot_body::proof_lengths(profile).end());
    proof.write(&mut proof_bytes);
    drop(proof);
    let (proof_header, proof) = proof_bytes.split_at(PROOF_HEADER_BYTES);
    if !FALSE_STATEMENT {
        verify_expanded(&context, &public, proof_header, proof)?;
    }
    let mut body = ballot_body::header(profile, &public.header, &proof_bytes)
        .map_err(|_| Refusal::Encoding)?;
    body.reserve_exact(ballot_body::body_length(profile, proof_bytes.len()) - body.len());
    for (index, _) in ballot_body::polynomials(profile) {
        body.extend(&public.polynomials[index]);
    }
    body.extend(proof);
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
) -> Result<BallotEnvelope, Refusal> {
    let profile = context.profile();
    let header = body
        .get(..ballot_body::HEADER_BYTES)
        .ok_or(Refusal::Encoding)?;
    let header = ballot_body::parse_header(profile, header).map_err(|_| Refusal::Encoding)?;
    if body.len() != ballot_body::body_length(profile, header.proof_length) {
        return Err(Refusal::Encoding);
    }
    let statement = header.context;
    if statement[4..68] != context.poll().identity()
        || statement[68..132] != *context.setup_identity()
        || u16::from_le_bytes(statement[132..134].try_into().unwrap()) as usize
            != context.position()
        || statement[134] as usize != context.poll().manifest().option_count()
        || u16::from(statement[135]) != context.poll().top_count()
    {
        return Err(Refusal::Context);
    }
    let mut polynomials = Vec::with_capacity(8);
    let mut offset = ballot_body::HEADER_BYTES;
    let (_, common, index) = setup_input(profile);
    if key.index() != index
        || key.setup_identity() != context.setup_identity()
        || key.coefficients().len() != profile.family_degree(Family::Fhe)
    {
        return Err(Refusal::Context);
    }
    for (family, common, public_key) in [
        (
            Family::Fhe,
            setup_witness::contribution::common_records(profile, common)
                .map_err(|_| Refusal::Encoding)?,
            encode_polynomial(key.coefficients(), coefficient_bytes(profile, Family::Fhe))
                .map_err(|_| Refusal::Encoding)?,
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
    verify_expanded(context, &public, header.proof_header, &body[offset..])?;
    envelope(context, ballot_time, body)
}
