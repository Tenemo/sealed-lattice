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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_synthetic_wrong_partial(
        role: &[u8],
        mut generated: crate::PreparedRelease,
    ) -> (PublicStatement, Self) {
        let coefficient = &mut generated.statement.polynomials[5][..25];
        let mut magnitude = num_bigint::BigUint::from_bytes_le(&coefficient[1..]);
        if magnitude == num_bigint::BigUint::from(0u32) {
            magnitude = num_bigint::BigUint::from(1u32);
        } else {
            magnitude -= 1u32;
        }
        let bytes = magnitude.to_bytes_le();
        coefficient[1..].fill(0);
        coefficient[1..1 + bytes.len()].copy_from_slice(&bytes);
        if magnitude == num_bigint::BigUint::from(0u32) {
            coefficient[0] = 0;
        }
        let witness = Witness::from_columns(
            generated.statement.digest(),
            std::mem::take(&mut *generated.columns),
        )
        .unwrap();
        let proof = Self::create(role, &generated.statement, witness, true);
        (generated.statement, proof)
    }
    pub fn from_prepared(
        role: &[u8],
        mut generated: crate::PreparedRelease,
    ) -> (PublicStatement, Self) {
        let witness = Witness::from_columns(
            generated.statement.digest(),
            std::mem::take(&mut *generated.columns),
        )
        .unwrap();
        let proof = Self::create(role, &generated.statement, witness, false);
        (generated.statement, proof)
    }

    fn create(
        role: &[u8],
        public: &PublicStatement,
        witness: Witness,
        adversarial_affine: bool,
    ) -> Self {
        let statement_digest = public.digest();
        assert_eq!(witness.statement, statement_digest);
        let mut context_hash = transcript::context_hasher(role);
        context_hash.update(&public.header);
        for polynomial in &public.polynomials {
            context_hash.update(polynomial);
        }
        let context = context_hash.finalize().into();
        let mut transcript = Transcript::new(role, context);
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
        let folding = fri::Fri::create(role, coefficients, &mut transcript);
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
        output.write_all(b"LRP1").unwrap();
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
        let openings = self.first.openings(&self.witness, &indices);
        let payloads: Vec<&[u8]> = openings
            .iter()
            .map(|value| &value[4..4 + FIRST_WIDTH])
            .collect();
        self.first
            .tree
            .write_multiproof(&indices, &payloads, output);
        drop(openings);
        let openings = self
            .second
            .openings(&self.witness, &self.inverses, &indices);
        let payloads: Vec<&[u8]> = openings
            .iter()
            .map(|value| &value[4..4 + SECOND_WIDTH])
            .collect();
        self.second
            .tree
            .write_multiproof(&indices, &payloads, output);
        drop(openings);
        let openings = self.linear.openings(&indices);
        let payloads: Vec<&[u8]> = openings.iter().map(|value| &value[4..52]).collect();
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
