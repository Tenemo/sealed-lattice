use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use supported_profile::{Profile, relation::setup_relation};
use word_proof::{
    transcript::{Transcript, challenge},
    tree::Tree,
};
use zeroize::Zeroizing;

const ROLE: &[u8] = b"continuation-transcript-fixture";
const CONTEXT: [u8; 64] = [17; 64];

fn shake(bytes: &[u8], length: usize) -> Vec<u8> {
    let mut hash = Shake256::default();
    hash.update(bytes);
    let mut output = vec![0; length];
    hash.finalize_xof().read(&mut output);
    output
}

// An independent byte encoder, without Transcript or ProtocolHash helpers.
fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in parts {
        output.extend((part.len() as u32).to_le_bytes());
        output.extend_from_slice(part);
    }
    output
}

// A small real salted tree supplies an opaque commitment. This is a
// transcript component test, not a setup proof or checkpoint construction.
fn first_commitment(seed: u8) -> [u8; 64] {
    let mut tree = Tree::with_seed(ROLE, 0, 8, 16, Zeroizing::new([seed; 64]));
    tree.hash_rows(|position, row| row.extend((position as u128).to_le_bytes()));
    tree.root()
}

fn initial(profile: Profile) -> Transcript {
    let mut transcript = Transcript::new(ROLE, CONTEXT, setup_relation(profile).message_bytes());
    transcript.next();
    transcript
}

#[test]
fn the_first_commitment_does_not_determine_the_later_lookup_message() {
    let profile = Profile::new(3, 2).unwrap();
    let root = first_commitment(23);
    let mut first = initial(profile);
    let mut second = initial(profile);
    assert_eq!(first.message, second.message);
    first.respond_with_salt(&[&root], [31; 128]);
    second.respond_with_salt(&[&root], [37; 128]);
    first.next();
    second.next();
    assert_ne!(first.message, second.message);
    assert_ne!(
        challenge(&first.message, 0, true),
        challenge(&second.message, 0, true)
    );
    assert_eq!(first_commitment(23), root);

    let mut replayed = initial(profile);
    replayed.respond_with_salt(&[&root], [31; 128]);
    replayed.next();
    assert_eq!(replayed.message, first.message);
    assert_eq!(replayed.salts, first.salts);

    let mut changed_generation = initial(profile);
    changed_generation.respond_with_salt(&[&first_commitment(29)], [31; 128]);
    changed_generation.next();
    assert_ne!(changed_generation.message, first.message);
}

#[test]
fn the_late_response_matches_the_complete_shake_framing_at_actual_profile_widths() {
    let root = first_commitment(41);
    let salt = [43; 128];
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let mut transcript = initial(profile);
        let length = transcript.message.len();
        let initial_message = shake(
            &framed(&[
                b"bounded-proof/verifier-message",
                ROLE,
                &CONTEXT,
                &vec![0; length],
                &1u32.to_le_bytes(),
            ]),
            length,
        );
        assert_eq!(transcript.message, initial_message);

        let mut root_input = vec![0; 64];
        let domain = b"sealed-lattice/fixed-hash/v1";
        root_input[..domain.len()].copy_from_slice(domain);
        root_input.extend(framed(&[
            b"bounded-proof/message-root",
            ROLE,
            &CONTEXT,
            &1u32.to_le_bytes(),
            &salt,
            &root,
        ]));
        let message_root = shake(&root_input, 64);
        let digest = shake(
            &framed(&[
                b"bounded-proof/chain-state",
                ROLE,
                &CONTEXT,
                &initial_message,
                &message_root,
            ]),
            length,
        );
        let mut state = message_root;
        state.extend_from_slice(&digest[..length - 64]);
        let expected = shake(
            &framed(&[
                b"bounded-proof/verifier-message",
                ROLE,
                &CONTEXT,
                &state,
                &2u32.to_le_bytes(),
            ]),
            length,
        );
        transcript.respond_with_salt(&[&root], salt);
        transcript.next();
        assert_eq!(transcript.message, expected);
        assert_ne!(challenge(&transcript.message, 0, true)[2], 0);
    }
}
