use crate::{
    HEADER_LENGTH, Verifier, columns, context::private_proof_role, oracles::Witness,
    proof::BallotProof, statement::PublicStatement,
};
use ballot_encryption::{context::BallotComputationContext, encryption::LinkedBallotWitness};
use registration_credentials::{ballot_authentication::BallotEnvelope, ballot_body};
use setup_aggregate::RetainedAggregatePolynomial;

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
    if proof.len() < HEADER_LENGTH || proof.len() > ballot_body::MAXIMUM_PROOF_BYTES {
        return Err(Error::Encoding);
    }
    let role = private_proof_role(context).map_err(|_| Error::Context)?;
    let mut verifier =
        Verifier::new(&role, public.digest(), &proof[..HEADER_LENGTH]).map_err(|_| Error::Proof)?;
    verifier
        .push_statement(&public.header)
        .map_err(|_| Error::Proof)?;
    for polynomial in &public.polynomials {
        for bytes in polynomial.chunks(crate::CHUNK_LIMIT) {
            verifier.push_statement(bytes).map_err(|_| Error::Proof)?;
        }
    }
    verifier.finish_statement().map_err(|_| Error::Proof)?;
    for bytes in proof[HEADER_LENGTH..].chunks(crate::CHUNK_LIMIT) {
        verifier.push_proof(bytes).map_err(|_| Error::Proof)?;
    }
    if !verifier.finish() {
        return Err(Error::Proof);
    }
    Ok(())
}
fn envelope(context: &BallotComputationContext, bytes: &[u8]) -> Result<BallotEnvelope, Error> {
    let mut hash =
        ballot_body::BallotBodyHasher::for_body_length(bytes.len()).map_err(|_| Error::Encoding)?;
    for bytes in bytes.chunks(crate::CHUNK_LIMIT) {
        hash.push(bytes).map_err(|_| Error::Encoding)?;
    }
    BallotEnvelope::new(
        context.poll().identity(),
        *context.inventory(),
        context.position(),
        bytes.len(),
        hash.finish().map_err(|_| Error::Encoding)?,
    )
    .map_err(|_| Error::Context)
}

/// Executes and checks one private computation under original retained inputs.
/// It returns public bytes and an envelope, never a public setup capability.
pub fn create(
    context: BallotComputationContext,
    fhe: RetainedAggregatePolynomial,
    auxiliary: RetainedAggregatePolynomial,
    scores: &[u8],
) -> Result<(Vec<u8>, BallotEnvelope), Error> {
    let encryption = LinkedBallotWitness::create_with_context(context, fhe, auxiliary, scores)
        .map_err(|_| Error::Context)?;
    let public = PublicStatement::from_encryption(&encryption).map_err(|_| Error::Encoding)?;
    let mut columns = columns::from_encryption(&encryption).map_err(|_| Error::Encoding)?;
    let witness = Witness::from_columns(public.digest(), std::mem::take(&mut *columns))
        .map_err(|_| Error::Encoding)?;
    let role = private_proof_role(&encryption.context).map_err(|_| Error::Context)?;
    let context = encryption.into_context();
    let proof = BallotProof::create(&role, &public, witness, false);
    let mut proof_bytes = Vec::with_capacity(ballot_body::MAXIMUM_PROOF_BYTES);
    proof.write(&mut proof_bytes);
    drop(proof);
    verify_expanded(&context, &public, &proof_bytes)?;
    let mut body =
        ballot_body::header(&public.header, proof_bytes.len()).map_err(|_| Error::Encoding)?;
    body.reserve_exact(ballot_body::CIPHERTEXT_BYTES + proof_bytes.len());
    for index in [2, 3, 6, 7] {
        body.extend(&public.polynomials[index]);
    }
    body.extend(proof_bytes);
    let envelope = envelope(&context, &body)?;
    Ok((body, envelope))
}

/// Verifies a bounded retained body using immutable original input values.
/// The caller must first authenticate its current participant root and records.
pub fn verify(
    context: &BallotComputationContext,
    keys: &[RetainedAggregatePolynomial; 2],
    body: &[u8],
) -> Result<BallotEnvelope, Error> {
    let header = body
        .get(..ballot_body::HEADER_BYTES)
        .ok_or(Error::Encoding)?;
    let proof_length = ballot_body::proof_length(header).map_err(|_| Error::Encoding)?;
    if body.len() != ballot_body::HEADER_BYTES + ballot_body::CIPHERTEXT_BYTES + proof_length {
        return Err(Error::Encoding);
    }
    let statement = &header[12..];
    if statement[4..68] != context.poll().identity()
        || statement[68..132] != *context.inventory()
        || u16::from_le_bytes(statement[132..134].try_into().unwrap()) as usize
            != context.position()
        || statement[134] as usize != context.poll().manifest().option_count()
        || u16::from(statement[135]) != context.poll().top_count()
    {
        return Err(Error::Context);
    }
    let mut polynomials = Vec::with_capacity(8);
    let mut offset = ballot_body::HEADER_BYTES;
    for (family, key) in keys.iter().enumerate() {
        let (common, index, width, degree) = if family == 0 {
            (0, 1, 109, 65536)
        } else {
            (73, 74, 6, 4096)
        };
        if key.index() != index
            || key.inventory() != context.inventory()
            || key.coefficients().len() != degree
        {
            return Err(Error::Context);
        }
        polynomials.push(
            crate::statement::encode_polynomial(
                &setup_witness::contribution::common_polynomial(common)
                    .map_err(|_| Error::Encoding)?,
                width,
            )
            .map_err(|_| Error::Encoding)?,
        );
        polynomials.push(
            crate::statement::encode_polynomial(key.coefficients(), width)
                .map_err(|_| Error::Encoding)?,
        );
        for _ in 0..2 {
            polynomials.push(body[offset..offset + degree * width].to_vec());
            offset += degree * width;
        }
    }
    let public = PublicStatement {
        header: statement.to_vec(),
        polynomials,
    };
    verify_expanded(context, &public, &body[offset..])?;
    envelope(context, body)
}
