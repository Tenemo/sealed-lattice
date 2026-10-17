use super::*;

#[test]
fn structural_affine_census_matches_the_constructor() {
    let mut profiles = 0;
    let mut maximum_terms = 0;
    let mut maximum_pairs = 0;
    for participants in Profile::participant_range() {
        for options in Profile::option_range() {
            let profile = Profile::new(participants, options).unwrap();
            let shape = profile.setup_shape();
            let columns = shape.word_columns + shape.boolean_columns;
            let gadgets = profile.gadget_length();
            let limbs = profile.fhe_limbs();
            let sharing = profile.sharing_degree();
            // Each key contributes quotient, error and l-1 carries; three
            // gadget keys also have a direct sparse term. Each recipient has
            // six share terms, a secret term and two per sharing coefficient.
            // Finally every sparse pair contributes its two support terms.
            let expected_terms =
                4 * gadgets * (limbs + 1) + 3 * gadgets + participants * (9 + 2 * sharing) + 4;
            let pair_bound = participants * columns + 6 * gadgets + 2 * participants;
            let mut previous = None;
            for alpha in [ZERO, ONE, [3, 1, 2]] {
                // Degree changes geometry values and shifts, not allocations
                // or term/mapping counts. Sixteen separates all supported
                // roster positions in the original interpolation layout.
                let layout = Layout {
                    profile,
                    degree: 16,
                    fhe_half_support: 1,
                    share_half_support: 1,
                };
                let plan = Accumulator::build(layout, alpha, &[], true).unwrap();
                let affine_rows = (4 * gadgets * limbs + 4 * participants) * layout.degree
                    + 2 * (participants + 2);
                assert_eq!(plan.weight, power(alpha, affine_rows));
                let terms = plan.recorded_terms.unwrap();
                let pairs: usize = terms.iter().map(|term| term.columns.len()).sum();
                let common_pairs: usize = plan
                    .uses
                    .iter()
                    .flatten()
                    .map(|usage| match usage {
                        PublicUse::Common(variable, _) => variable.terms.len(),
                        PublicUse::Value(_) => 0,
                    })
                    .sum();
                assert_eq!(terms.len(), expected_terms);
                assert!(pairs <= pair_bound);
                assert_eq!(common_pairs, 8 * gadgets + 4 * participants);
                assert_eq!(plan.uses.len(), 7 * gadgets + 3 * participants + 1);
                let counts = (terms.len(), pairs, common_pairs);
                if let Some(previous) = previous {
                    assert_eq!(counts, previous);
                }
                previous = Some(counts);
                maximum_terms = maximum_terms.max(terms.len());
                maximum_pairs = maximum_pairs.max(pairs);
            }
            profiles += 1;
        }
    }
    println!(
        "Affine structural census: {profiles} profiles, {maximum_terms} maximum fixed terms, {maximum_pairs} maximum fixed pairs; three challenge classes"
    );
}
