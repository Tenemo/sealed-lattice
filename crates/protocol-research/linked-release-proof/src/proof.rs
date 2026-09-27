use crate::{
    combination, field, fri,
    linear::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    statement::PublicStatement,
    transcript::{self, Transcript},
};
use stateful_sha3::Digest;
use std::io::Write;

pub struct ReleaseRelationProof {
    statement_digest: [u8; 64],
    context: [u8; 64],
    witness: Witness,
    first: FirstOracle,
    second: SecondOracle,
    linear: LinearOracle,
    folding: fri::Fri,
    transcript: Transcript,
    inverses: Vec<field::Element>,
}
impl ReleaseRelationProof {
    pub fn from_prepared(
        role: &[u8],
        mut generated: crate::PreparedRelease,
    ) -> (PublicStatement, Self) {
        let relation = release_relation(generated.statement.profile);
        let witness = Witness::from_columns(
            &relation,
            generated.statement.digest(),
            std::mem::take(&mut *generated.columns),
        )
        .unwrap();
        let proof = Self::create(role, &relation, &generated.statement, witness, false);
        (generated.statement, proof)
    }

    fn create(
        role: &[u8],
        relation: &Relation,
        public: &PublicStatement,
        witness: Witness,
        adversarial_affine: bool,
    ) -> Self {
        let statement_digest = public.digest();
        assert_eq!(witness.statement, statement_digest);
        let mut context_hash = transcript::context_hasher(relation, role);
        context_hash.update(&public.header);
        for polynomial in &public.polynomials {
            context_hash.update(polynomial);
        }
        let context = context_hash.finalize().into();
        let mut transcript = Transcript::new(role, context, relation.message_bytes());
        transcript.next();
        let first = FirstOracle::create(role, &witness, false);
        transcript.respond(&[&first.tree.root()]);
        transcript.next();
        let beta = transcript::challenge(&transcript.message, 0, true);
        let inverses = field::batch_inverse(
            &(0..SYSTEMATIC)
                .map(|value| field::subtract(beta, [value as u128, 0, 0]))
                .collect::<Vec<_>>(),
        );
        let second = SecondOracle::create(role, &witness, &inverses);
        transcript.respond(&[&second.tree.root(), &field::encode(second.mask_sum)]);
        transcript.next();
        let alpha = transcript::challenge(&transcript.message, 0, false);
        let mask = transcript::challenge(&transcript.message, 1, false);
        let linear = LinearOracle::create(
            role,
            &witness,
            &first,
            &second,
            public.operator(alpha).unwrap(),
            mask,
            adversarial_affine,
        );
        transcript.respond(&[&linear.tree.root()]);
        transcript.next();
        let coefficients = combination::polynomial(
            &witness,
            &first,
            &second,
            &linear,
            beta,
            &inverses,
            &transcript.message,
        );
        let folding = fri::Fri::create(role, relation.oracles(), coefficients, &mut transcript);
        Self {
            statement_digest,
            context,
            witness,
            first,
            second,
            linear,
            folding,
            transcript,
            inverses,
        }
    }
    pub fn write(&self, output: &mut impl Write) {
        let relation = &self.witness.relation;
        output.write_all(relation.proof_magic).unwrap();
        output.write_all(&self.statement_digest).unwrap();
        output.write_all(&self.context).unwrap();
        for root in [
            self.first.tree.root(),
            self.second.tree.root(),
            self.linear.tree.root(),
        ] {
            output.write_all(&root).unwrap();
        }
        output
            .write_all(&field::encode(self.second.mask_sum))
            .unwrap();
        for salt in &self.transcript.salts {
            output.write_all(salt).unwrap();
        }
        for layer in &self.folding.layers {
            output.write_all(&layer.tree.root()).unwrap();
        }
        output
            .write_all(&field::encode(self.folding.terminal))
            .unwrap();
        let indices = fri::requested(&self.folding.queries, DOMAIN);
        let rows = self.first.opened_rows(&self.witness, &indices);
        let payloads: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
        self.first
            .tree
            .write_multiproof(&indices, &payloads, output);
        drop(rows);
        let rows = self
            .second
            .opened_rows(&self.witness, &self.inverses, &indices);
        let payloads: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
        self.second
            .tree
            .write_multiproof(&indices, &payloads, output);
        drop(rows);
        let rows = self.linear.opened_rows(&indices);
        let payloads: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
        self.linear
            .tree
            .write_multiproof(&indices, &payloads, output);
        for layer in &self.folding.layers {
            let indices = fri::requested(&self.folding.queries, layer.tree.length);
            let payloads: Vec<_> = indices
                .iter()
                .map(|index| field::encode(layer.values[*index]))
                .collect();
            let views: Vec<&[u8]> = payloads.iter().map(|value| value.as_slice()).collect();
            layer.tree.write_multiproof(&indices, &views, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CHUNK_LIMIT, HEADER_LENGTH, Verifier, witness::tests::synthetic_release};
    use supported_profile::Profile;

    fn verify(profile: Profile, role: &[u8], statement: &PublicStatement, proof: &[u8]) -> bool {
        let Ok(mut verifier) =
            Verifier::new(profile, role, statement.digest(), &proof[..HEADER_LENGTH])
        else {
            return false;
        };
        for part in std::iter::once(&statement.header).chain(&statement.polynomials) {
            for chunk in part.chunks(CHUNK_LIMIT) {
                if verifier.push_statement(chunk).is_err() {
                    return false;
                }
            }
        }
        if verifier.finish_statement().is_err() {
            return false;
        }
        for chunk in proof[HEADER_LENGTH..].chunks(CHUNK_LIMIT) {
            if verifier.push_proof(chunk).is_err() {
                return false;
            }
        }
        verifier.finish()
    }

    #[test]
    fn release_proofs_verify_only_for_their_role_and_true_partial() {
        let profile = Profile::new(3, 2).unwrap();
        let role = b"release-proof-test";
        let (prepared, _) = synthetic_release(profile);
        let (statement, proof) = ReleaseRelationProof::from_prepared(role, prepared);
        let mut bytes = Vec::new();
        proof.write(&mut bytes);
        assert!(bytes.len() <= release_relation(profile).maximum_proof_bytes());
        assert!(verify(profile, role, &statement, &bytes));
        assert!(!verify(profile, b"another-role", &statement, &bytes));
        // A proof of a partial decryption one less than the derived value
        // cannot meet the affine relation.
        let (mut prepared, _) = synthetic_release(profile);
        let width = crate::statement::release_coefficient_bytes(profile);
        let coefficient = &mut prepared.statement.polynomials[5][..width];
        let mut magnitude = num_bigint::BigUint::from_bytes_le(&coefficient[1..]);
        let negative = coefficient[0] == 1;
        if negative {
            magnitude += 1u32;
        } else if magnitude == num_bigint::BigUint::from(0u32) {
            magnitude = num_bigint::BigUint::from(1u32);
            coefficient[0] = 1;
        } else {
            magnitude -= 1u32;
        }
        let encoded = magnitude.to_bytes_le();
        coefficient[1..].fill(0);
        coefficient[1..1 + encoded.len()].copy_from_slice(&encoded);
        let relation = release_relation(profile);
        let witness = Witness::from_columns(
            &relation,
            prepared.statement.digest(),
            std::mem::take(&mut *prepared.columns),
        )
        .unwrap();
        let proof =
            ReleaseRelationProof::create(role, &relation, &prepared.statement, witness, true);
        let mut bytes = Vec::new();
        proof.write(&mut bytes);
        assert!(!verify(profile, role, &prepared.statement, &bytes));
    }
}
