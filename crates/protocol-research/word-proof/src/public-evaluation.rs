//! Deterministic public evaluation proofs for a selected committed offer.
//! The aggregate is fixed before the common point and column weights; each
//! offer's claim and every fold then enter the same chained transcript.
use crate::{
    field::{self, Element, Transform, ZERO, base},
    fri::requested,
    public_oracle::{PublicMultiproof, PublicOpenings, PublicOracle, PublicOracleBuilder},
    transcript::{self, Transcript},
};
use std::collections::VecDeque;
use supported_profile::{
    Profile,
    relation::{
        EVALUATION_DOMAIN_SIZE, EVALUATION_FOLDS, EVALUATION_QUERY_COUNT, SYSTEMATIC,
        evaluation_message_bytes,
    },
};

#[derive(Debug)]
pub enum Refusal {
    Shape,
    Phase,
    Binding,
}

fn transcript(
    profile: Profile,
    role: &[u8],
    aggregate: &[u8; 64],
    roots: &[[u8; 64]],
) -> Result<Transcript, Refusal> {
    if role.is_empty() || role.len() > 1000 || roots.len() != profile.setup_contributors() {
        return Err(Refusal::Shape);
    }
    let parameters: Vec<u8> = [
        profile.participants(),
        profile.options(),
        SYSTEMATIC,
        EVALUATION_DOMAIN_SIZE,
        EVALUATION_QUERY_COUNT,
        profile.committed_columns(),
        evaluation_message_bytes(profile),
    ]
    .into_iter()
    .flat_map(|value| (value as u32).to_le_bytes())
    .collect();
    let roots: Vec<u8> = roots.iter().flatten().copied().collect();
    let context = transcript::hash(
        b"committed-key/evaluation-statement",
        &[role, &profile.setup_statement_header(), &parameters, &roots],
    );
    let mut transcript = Transcript::new(role, context, evaluation_message_bytes(profile));
    transcript.next();
    transcript.respond_with_salt(&[aggregate], [0; 128]);
    transcript.next();
    Ok(transcript)
}

pub fn aggregate_challenges(
    profile: Profile,
    role: &[u8],
    aggregate: &[u8; 64],
    roots: &[[u8; 64]],
) -> Result<(Element, Vec<Element>), Refusal> {
    let transcript = transcript(profile, role, aggregate, roots)?;
    Ok((
        transcript::challenge(&transcript.message, 0, true),
        (0..profile.committed_columns())
            .map(|index| transcript::challenge(&transcript.message, index + 1, false))
            .collect(),
    ))
}

fn fold_role(role: &[u8], offer: usize, round: usize) -> Vec<u8> {
    let mut bytes = role.to_vec();
    bytes.extend((offer as u32).to_le_bytes());
    bytes.extend((round as u32).to_le_bytes());
    bytes
}

struct Layer {
    tree: PublicOracle,
    values: Vec<Element>,
}

pub struct EvaluationProver {
    role: Vec<u8>,
    ordinal: usize,
    root: [u8; 64],
    point: Element,
    weights: Vec<Element>,
    transcript: Transcript,
    combined: Vec<Element>,
    next: usize,
    builder: Option<PublicOracleBuilder>,
    tree: Option<PublicOracle>,
    openings: Option<PublicOpenings>,
    rows: VecDeque<(usize, Vec<u8>)>,
    layers: Vec<Layer>,
    queries: Vec<usize>,
    claim: Element,
    terminal: Element,
    output_started: bool,
    group_started: bool,
    stage: usize,
    multiproof: PublicMultiproof,
    ready: bool,
}

impl EvaluationProver {
    pub fn new(
        profile: Profile,
        role: &[u8],
        aggregate: &[u8; 64],
        roots: &[[u8; 64]],
        ordinal: usize,
        contribution_role: &[u8],
    ) -> Result<Self, Refusal> {
        let transcript = transcript(profile, role, aggregate, roots)?;
        let root = *roots.get(ordinal).ok_or(Refusal::Shape)?;
        let point = transcript::challenge(&transcript.message, 0, true);
        let weights = (0..profile.committed_columns())
            .map(|index| transcript::challenge(&transcript.message, index + 1, false))
            .collect();
        Ok(Self {
            role: role.to_vec(),
            ordinal,
            root,
            point,
            weights,
            transcript,
            combined: vec![ZERO; SYSTEMATIC],
            next: 0,
            builder: Some(
                PublicOracleBuilder::new(contribution_role, profile.committed_columns())
                    .map_err(|_| Refusal::Shape)?,
            ),
            tree: None,
            openings: None,
            rows: VecDeque::new(),
            layers: Vec::new(),
            queries: Vec::new(),
            claim: ZERO,
            terminal: ZERO,
            output_started: false,
            group_started: false,
            stage: 0,
            multiproof: PublicMultiproof::default(),
            ready: false,
        })
    }

    pub fn column(&mut self, coefficients: &[u128]) -> Result<(), Refusal> {
        let weight = *self.weights.get(self.next).ok_or(Refusal::Phase)?;
        self.builder
            .as_mut()
            .ok_or(Refusal::Phase)?
            .column(coefficients)
            .map_err(|_| Refusal::Shape)?;
        for (sum, coefficient) in self.combined.iter_mut().zip(coefficients) {
            *sum = field::add(*sum, field::scale(weight, *coefficient));
        }
        self.next += 1;
        Ok(())
    }

    pub fn finish_columns(&mut self) -> Result<(), Refusal> {
        if self.next != self.weights.len() {
            return Err(Refusal::Phase);
        }
        let tree = self
            .builder
            .take()
            .ok_or(Refusal::Phase)?
            .finish()
            .map_err(|_| Refusal::Shape)?;
        if tree.root() != self.root {
            return Err(Refusal::Binding);
        }
        self.tree = Some(tree);
        self.claim = self.combined.iter().rev().fold(ZERO, |sum, value| {
            field::add(field::multiply(sum, self.point), *value)
        });
        self.transcript.respond_with_salt(
            &[
                &(self.ordinal as u32).to_le_bytes(),
                &field::encode(self.claim),
            ],
            [0; 128],
        );
        let mut quotient = ZERO;
        for index in (0..SYSTEMATIC - 1).rev() {
            quotient = field::add(
                self.combined[index + 1],
                field::multiply(self.point, quotient),
            );
            self.combined[index + 1] = quotient;
        }
        self.combined.copy_within(1.., 0);
        self.combined[SYSTEMATIC - 1] = ZERO;
        let mut length = EVALUATION_DOMAIN_SIZE;
        let mut coset = 7;
        for round in 0..EVALUATION_FOLDS {
            self.transcript.next();
            let scalar = transcript::challenge(&self.transcript.message, 0, false);
            for index in 0..self.combined.len() / 2 {
                self.combined[index] = field::add(
                    self.combined[2 * index],
                    field::multiply(scalar, self.combined[2 * index + 1]),
                );
            }
            self.combined.truncate(self.combined.len() / 2);
            length /= 2;
            coset = base::multiply(coset, coset);
            if length == 4 {
                self.terminal = self.combined[0];
                self.transcript
                    .respond_with_salt(&[&field::encode(self.terminal)], [0; 128]);
            } else {
                let mut values = vec![ZERO; length];
                let mut power = 1;
                for (value, coefficient) in values.iter_mut().zip(&self.combined) {
                    *value = field::scale(*coefficient, power);
                    power = base::multiply(power, coset);
                }
                Transform::cached(SYSTEMATIC).extension(&mut values, false);
                let tree =
                    PublicOracle::from_rows(&fold_role(&self.role, self.ordinal, round), &values);
                self.transcript.respond_with_salt(&[&tree.root()], [0; 128]);
                self.layers.push(Layer { tree, values });
            }
        }
        self.combined = Vec::new();
        self.transcript.next();
        self.queries = (0..EVALUATION_QUERY_COUNT)
            .map(|index| {
                u32::from_le_bytes(
                    self.transcript.message[4 * index..4 * (index + 1)]
                        .try_into()
                        .unwrap(),
                ) as usize
                    % (EVALUATION_DOMAIN_SIZE / 2)
            })
            .collect();
        self.openings = Some(
            PublicOpenings::new(
                &requested(&self.queries, EVALUATION_DOMAIN_SIZE),
                self.weights.len(),
            )
            .map_err(|_| Refusal::Shape)?,
        );
        Ok(())
    }

    pub fn opening_column(&mut self, coefficients: &[u128]) -> Result<(), Refusal> {
        self.openings
            .as_mut()
            .ok_or(Refusal::Phase)?
            .column(coefficients)
            .map_err(|_| Refusal::Shape)
    }

    pub fn finish_openings(&mut self) -> Result<(), Refusal> {
        self.rows = self
            .openings
            .take()
            .ok_or(Refusal::Phase)?
            .finish()
            .map_err(|_| Refusal::Shape)?
            .into();
        self.ready = true;
        Ok(())
    }

    /// Writes a bounded header, group count or opening. False ends the proof.
    pub fn next_output(&mut self, output: &mut Vec<u8>) -> Result<bool, Refusal> {
        output.clear();
        if !self.ready {
            return Err(Refusal::Phase);
        }
        if !self.output_started {
            self.output_started = true;
            output.extend(field::encode(self.claim));
            for layer in &self.layers {
                output.extend(layer.tree.root());
            }
            output.extend(field::encode(self.terminal));
            return Ok(true);
        }
        if self.stage > self.layers.len() {
            return Ok(false);
        }
        if !self.group_started {
            if self.stage > 0 {
                let layer = &self.layers[self.stage - 1];
                self.rows = requested(&self.queries, layer.values.len())
                    .into_iter()
                    .map(|index| (index, field::encode(layer.values[index]).to_vec()))
                    .collect();
            }
            output.extend((self.rows.len() as u32).to_le_bytes());
            self.group_started = true;
            return Ok(true);
        }
        let (index, row) = self.rows.pop_front().ok_or(Refusal::Phase)?;
        let tree = if self.stage == 0 {
            self.tree.as_ref().ok_or(Refusal::Phase)?
        } else {
            &self.layers[self.stage - 1].tree
        };
        tree.write_record(&mut self.multiproof, index, &row, output)
            .map_err(|_| Refusal::Binding)?;
        if self.rows.is_empty() {
            self.stage += 1;
            self.group_started = false;
            self.multiproof = PublicMultiproof::default();
        }
        Ok(true)
    }
}
