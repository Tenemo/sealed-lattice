//! The release body import: slices accumulate up to the envelope's body
//! length, and a refused slice or a failed finish closes the import for good.
use super::{OwnReleaseBody, RELEASE_CHUNK_BYTES};
use protocol_foundations::{
    Error,
    release_signing::{ReleaseEnvelope, body_lengths},
};
use supported_profile::Profile;

// An import of the shortest body the first profile admits, and that length.
fn importing() -> (OwnReleaseBody, usize) {
    let profile = Profile::all().next().unwrap();
    let length = *body_lengths(profile).start();
    let envelope =
        ReleaseEnvelope::new(profile, [1; 64], [2; 64], [3; 64], 0, length, [4; 64]).unwrap();
    (OwnReleaseBody::importing(envelope), length)
}

// Pushes that many body bytes in slices of at most one chunk.
fn push(release: &mut OwnReleaseBody, length: usize) {
    for chunk in vec![0; length].chunks(RELEASE_CHUNK_BYTES) {
        release.push(chunk).unwrap();
    }
}

#[test]
fn a_refused_slice_closes_the_import() {
    for (case, refused) in [
        ("empty slice", vec![]),
        (
            "slice longer than a chunk",
            vec![0; RELEASE_CHUNK_BYTES + 1],
        ),
    ] {
        let (mut release, _) = importing();
        assert!(
            matches!(release.push(&refused), Err(Error::Shape)),
            "{case}"
        );
        assert!(matches!(release.push(&[0]), Err(Error::Shape)), "{case}");
    }
    let (mut release, length) = importing();
    push(&mut release, length - 1);
    assert!(matches!(release.push(&[0, 0]), Err(Error::Shape)));
    assert!(matches!(release.push(&[0]), Err(Error::Shape)));
    assert!(matches!(release.finish(None), Err(Error::Shape)));
}

#[test]
fn an_early_finish_closes_the_import() {
    let (mut release, length) = importing();
    push(&mut release, length - 1);
    assert!(matches!(release.finish(None), Err(Error::Shape)));
    assert!(matches!(release.push(&[0]), Err(Error::Shape)));
}

#[test]
fn a_complete_import_stays_unverified_without_the_release_context() {
    let (mut release, length) = importing();
    push(&mut release, length);
    assert!(matches!(release.finish(None), Err(Error::Context)));
    assert!(matches!(release.finish(None), Err(Error::Shape)));
    assert!(matches!(release.push(&[0]), Err(Error::Shape)));
    assert!(matches!(release.slice(0, 1), Err(Error::Context)));
    let envelope = release.envelope().bytes().to_vec();
    assert!(matches!(release.signable(&envelope), Err(Error::Context)));
}
