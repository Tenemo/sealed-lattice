use crate::{
    field::MODULUS,
    plan::Plan,
    relation::Relation,
    statement::{DEGREE, PLAINTEXT},
    transcript::{framed, hash, word},
};

pub struct Tree {
    pub identifier: usize,
    pub domain: usize,
    pub width: usize,
    pub mask: bool,
    pub stage: usize,
    pub mask_offset: Option<usize>,
}
impl Tree {
    fn descriptor(&self) -> Vec<u8> {
        [word(self.identifier), word(self.domain), word(self.width)].concat()
    }
}
pub struct Layout {
    pub plan: Plan,
    pub trees: Vec<Tree>,
    pub mask_length: usize,
    pub mask_domain: usize,
    pub word_bytes: usize,
    pub context: [u8; 64],
    pub evaluations: usize,
    pub maximum_proof_bytes: usize,
}
fn frame_owned(parts: &[Vec<u8>]) -> Vec<u8> {
    framed(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>())
}
fn vector(values: &[usize]) -> Vec<u8> {
    frame_owned(
        &values
            .iter()
            .map(|&value| word(value).to_vec())
            .collect::<Vec<_>>(),
    )
}
impl Layout {
    pub fn new(role: &[u8], public_context: &[u8], statement: &[u8], relation: &Relation) -> Self {
        let plan = Plan::select(&relation.lengths);
        let mask_length = plan.queries + 1;
        let mask_domain = (4 * (mask_length + plan.queries) + 1).next_power_of_two();
        let mut trees = Vec::new();
        let mut add = |domain, width, mask, stage, mask_offset| {
            trees.push(Tree {
                identifier: trees.len(),
                domain,
                width,
                mask,
                stage,
                mask_offset,
            });
        };
        for length in relation.lengths {
            add(
                plan.domains[0],
                length.div_ceil(plan.messages[0]),
                false,
                0,
                None,
            );
        }
        let mut masks = 0;
        for stage in 0..plan.domains.len() {
            add(mask_domain, plan.folds[stage], true, stage, Some(masks));
            masks += plan.folds[stage];
            if stage + 1 < plan.domains.len() {
                add(
                    plan.domains[stage + 1],
                    plan.rows[stage + 1],
                    false,
                    stage + 1,
                    None,
                );
                add(mask_domain, 1, true, stage, Some(masks));
                masks += 1;
            } else {
                add(plan.domains[stage], 1, false, stage, None);
                add(mask_domain, masks, true, stage, None);
            }
        }
        assert_eq!(masks, plan.masks);
        assert!(trees.iter().map(|tree| 2 * tree.domain - 1).sum::<usize>() <= 1 << 23);
        let largest_leaf = trees.iter().map(|tree| tree.width * 48).max().unwrap();
        let word_bytes = [
            128,
            288,
            96 + 4 * plan.queries,
            8 * plan.queries,
            largest_leaf,
        ]
        .into_iter()
        .max()
        .unwrap()
        .next_power_of_two();
        let mut shape = vec![
            word(DEGREE).to_vec(),
            word(PLAINTEXT).to_vec(),
            word(relation.columns.len()).to_vec(),
        ];
        shape.extend(relation.columns.iter().map(|column| {
            framed(&[
                column.name.as_bytes(),
                &word(column.active),
                &word(column.range.unwrap_or(0)),
            ])
        }));
        let mut parameters = vec![
            vector(&relation.lengths),
            vector(&plan.domains),
            vector(&plan.messages),
            word(plan.queries).to_vec(),
            word(word_bytes).to_vec(),
            word(mask_length).to_vec(),
        ];
        parameters.extend(trees.iter().map(Tree::descriptor));
        let public_hash = hash(
            b"compact-proof/public-context",
            &[&framed(&[public_context, statement])],
        );
        let context = hash(
            b"compact-proof/statement",
            &[
                role,
                b"original-field-sources-and-rank-release/v1",
                &frame_owned(&shape),
                &frame_owned(&parameters),
                &MODULUS.to_le_bytes(),
                &7u128.to_le_bytes(),
                &2u128.to_le_bytes(),
                &public_hash,
            ],
        );
        let evaluations =
            relation.columns.len() + relation.families.len() + relation.reciprocals.len() + 4;
        let maximum_proof_bytes = plan.bytes + (evaluations + 1) * 48 + 4 * 128 + 512;
        Self {
            plan,
            trees,
            mask_length,
            mask_domain,
            word_bytes,
            context,
            evaluations,
            maximum_proof_bytes,
        }
    }
}
