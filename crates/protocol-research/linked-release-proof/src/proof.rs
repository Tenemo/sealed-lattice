use crate::{parameters::*, statement::PublicStatement};
use std::io::Write;
use word_proof::{
    combination, field, fri,
    linear_oracle::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    transcript::{self, Transcript},
};

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
        let context = context_hash.finalize();
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
        self.first.tree.write_multiproof(
            &indices,
            |leaves| self.first.opened_rows(&self.witness, leaves),
            output,
        );
        self.second.tree.write_multiproof(
            &indices,
            |leaves| {
                self.second
                    .opened_rows(&self.witness, &self.inverses, leaves)
            },
            output,
        );
        self.linear.tree.write_multiproof(
            &indices,
            |leaves| self.linear.opened_rows(leaves),
            output,
        );
        for layer in &self.folding.layers {
            let indices = fri::requested(&self.folding.queries, layer.tree.length);
            layer
                .tree
                .write_multiproof(&indices, |leaves| layer.rows(leaves), output);
        }
    }
}

#[cfg(test)]
#[path = "proof-tests.rs"]
mod tests;
