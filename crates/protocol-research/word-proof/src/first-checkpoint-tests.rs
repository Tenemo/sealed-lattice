use super::*;
use crate::bridge::ProverStep;

// A setup witness of the relation: zero words, and each sparse
// support's least positions of its stride.
fn columns(relation: &Relation) -> Vec<Vec<u16>> {
    let mut columns = vec![vec![0; SYSTEMATIC]; relation.columns()];
    for pair in 0..relation.support_pairs() {
        let (positive, negative) = relation.zero_product_columns(pair);
        let (stride, half) = relation.support(pair);
        let half = half as usize;
        for position in 0..half {
            columns[positive][stride * position] = 1;
            columns[negative][stride * (half + position)] = 1;
        }
    }
    columns
}
fn step(prover: &mut Prover) {
    prover
        .advance(ProverStep::Step, 0, &[], &mut Vec::new())
        .unwrap();
}
// The first oracle's root once the prover commits its remaining columns.
fn first_root(mut prover: Prover) -> [u8; 64] {
    while prover.phase != Phase::SecondInitialize {
        step(&mut prover);
    }
    prover.first.as_ref().unwrap().tree.root()
}

// A prover restored from the checkpoint of another that committed some
// first-oracle columns, each record sealed from the rows and opened into
// the restored rows in turn, commits the remaining columns to the same
// first oracle. A record that another record's position or an altered
// byte names fails the import for good.
#[test]
fn restored_checkpoints_commit_the_same_first_oracle() {
    let profile = Profile::new(3, 2).unwrap();
    let relation = setup_relation(profile);
    let mut prover = Prover::from_generated(
        profile,
        b"checkpoint-test",
        [7; 64],
        [9; 64],
        profile.setup_statement_header(),
        columns(&relation),
    )
    .unwrap();
    for _ in 0..4 {
        step(&mut prover);
    }
    assert!(prover.phase == Phase::FirstColumn(3));
    let mut export = Export::begin_with_inputs(&mut prover, &[]).unwrap();
    let header = export.header();
    let mut import = Import::begin(&header).unwrap();
    let lengths = record_lengths(&relation);
    let mut records = Vec::new();
    while !export.complete() {
        let record = export.seal(&mut prover).unwrap();
        assert_eq!(record.bytes.len(), lengths[records.len()]);
        import.open(&record.key, &record.bytes).unwrap();
        records.push(record);
    }
    assert_eq!(records.len(), record_count(&relation));
    assert!(import.complete());
    let restored = import.finish().unwrap();
    assert_eq!(first_root(restored), first_root(prover));
    // The second record under its own key fails at the first position.
    let mut altered = records[0].bytes.clone();
    altered[0] ^= 1;
    for (key, hostile) in [
        (&records[1].key, &records[1].bytes),
        (&records[0].key, &altered),
    ] {
        let mut import = Import::begin(&header).unwrap();
        assert!(import.open(key, hostile).is_err());
        assert!(import.open(&records[0].key, &records[0].bytes).is_err());
        assert!(!import.complete());
    }
}
