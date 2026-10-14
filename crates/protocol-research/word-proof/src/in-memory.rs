use crate::{
    combination,
    field::{self, Element},
    fri::{self, Fri},
    linear_oracle::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    transcript::{self, Transcript},
};
use statement_stream::affine::Operator;
use std::io::Write;
use supported_profile::relation::*;

/// A proof of one statement that holds every oracle in memory, for the
/// relations whose witness fits a single call.
pub struct InMemoryProof {
    witness: Witness,
    first: FirstOracle,
    second: SecondOracle,
    linear: LinearOracle,
    folding: Fri,
    transcript: Transcript,
    inverses: Vec<Element>,
}
impl InMemoryProof {
    /// Proves the witness's statement, whose digest the witness carries. The
    /// operator function gives the statement's affine operator at the linear
    /// challenge.
    pub fn create(
        role: &[u8],
        witness: Witness,
        operator: impl FnOnce(Element) -> Operator,
        adversarial_affine: bool,
    ) -> Self {
        let relation = &witness.relation;
        let mut transcript = Transcript::new(
            role,
            transcript::context(relation, role, &witness.statement),
            relation.message_bytes(),
        );
        transcript.next();
        let first = FirstOracle::create(role, &witness);
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
            operator(alpha),
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
        let folding = Fri::create(role, relation.oracles(), coefficients, &mut transcript);
        Self {
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
        write_header(
            output,
            &self.witness.statement,
            &self.transcript,
            [
                self.first.tree.root(),
                self.second.tree.root(),
                self.linear.tree.root(),
            ],
            self.second.mask_sum,
            &self.folding,
        );
        let indices = fri::requested(&self.folding.queries, EVALUATION_DOMAIN_SIZE);
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

/// Writes a proof's header: the statement digest, the three oracle roots and
/// the mask sum, every round's salt, and the folding layers' roots with the
/// terminal value.
pub(crate) fn write_header(
    output: &mut impl Write,
    statement: &[u8; 64],
    transcript: &Transcript,
    roots: [[u8; 64]; 3],
    mask_sum: Element,
    folding: &Fri,
) {
    output.write_all(statement).unwrap();
    for root in roots {
        output.write_all(&root).unwrap();
    }
    output.write_all(&field::encode(mask_sum)).unwrap();
    for salt in &transcript.salts {
        output.write_all(salt).unwrap();
    }
    for layer in &folding.layers {
        output.write_all(&layer.tree.root()).unwrap();
    }
    output.write_all(&field::encode(folding.terminal)).unwrap();
}
