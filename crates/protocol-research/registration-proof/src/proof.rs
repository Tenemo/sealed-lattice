use crate::{parameters::*, statement};
use parallel_work::Digest;
use setup_witness::registration::RegistrationKey;
use std::io::Write;
use word_proof::{
    combination, field, fri,
    linear_oracle::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    transcript::{self, Transcript},
};

pub struct RegistrationProof {
    // Retained for the original recipient's subsequent authenticated state.
    key: RegistrationKey,
    pub statement_digest: [u8; 64],
    pub context: [u8; 64],
    pub witness: Witness,
    first: FirstOracle,
    second: SecondOracle,
    linear: LinearOracle,
    folding: fri::Fri,
    transcript: Transcript,
    inverses: Vec<field::Element>,
}
impl RegistrationProof {
    pub fn create(role: &[u8], adversarial_affine: bool, excess_degree: bool) -> Self {
        let mut key = RegistrationKey::new();
        let public_key = statement::encode_key(key.public_key()).unwrap();
        let common = statement::common_bytes();
        let statement_digest = statement::digest(common, &public_key);
        let relation = registration_relation();
        let mut context_hash = transcript::context_hasher(&relation, role);
        context_hash.update(statement::header());
        context_hash.update(common);
        context_hash.update(&public_key);
        let context = context_hash.finalize().into();
        let mut witness = Witness::from_columns(
            &relation,
            statement_digest,
            key.take_proof_columns().unwrap(),
        )
        .unwrap();
        if adversarial_affine {
            let previous = witness.columns[2][0];
            let changed = previous ^ 1;
            witness.columns[2][0] = changed;
            for factor in [1usize, 512] {
                witness.counts[usize::from(previous) * factor] -= 1;
                witness.counts[usize::from(changed) * factor] += 1;
            }
        }
        let mut transcript = Transcript::new(role, context, relation.message_bytes());
        transcript.next();
        let first = FirstOracle::create(role, &witness, excess_degree);
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
        let operator = statement::operator(alpha, common, &public_key).unwrap();
        let linear = LinearOracle::create(
            role,
            &witness,
            &first,
            &second,
            operator,
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
            key,
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
    pub fn public_key_bytes(&self) -> Vec<u8> {
        statement::encode_key(self.key.public_key()).unwrap()
    }
    pub fn into_key(self) -> RegistrationKey {
        self.key
    }
    pub fn check_retained_key(&self) -> Result<(), setup_witness::registration::Error> {
        self.key.validate_retained()
    }
    pub fn write(&self, output: &mut impl Write) {
        output.write_all(self.witness.relation.proof_magic).unwrap();
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
