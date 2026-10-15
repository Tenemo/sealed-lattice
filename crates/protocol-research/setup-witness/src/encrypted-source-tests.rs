use super::*;

// The independent source-randomness model test computes the same stream
// prefixes from the source family's frame on Node's SHAKE256.
#[test]
fn private_source_streams_match_the_independent_frame() {
    let profile = Profile::new(3, 2).unwrap();
    for (purpose, expected) in [
        (
            0,
            "b98d123ff68d01b9e491483817f4730d59bfe7f4e0c3324457048ba86412b4db",
        ),
        (
            1,
            "1885cddfe0f23df93986e65b3db6b6c4daa5154ade55d3dcb5e278067d036853",
        ),
    ] {
        let mut bytes = [0; 32];
        private_stream(profile, &[29; 64], &[23; 64], &[3; 64], purpose).read(&mut bytes);
        let actual: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, expected);
    }
}
