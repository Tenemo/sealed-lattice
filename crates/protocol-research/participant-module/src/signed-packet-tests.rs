//! The signed packet framing: an emitted selection is restored exactly, and a
//! packet of any other length or with a body past the selection bound is
//! refused.
use super::{encode, endorsed_selection, selection};
use protocol_foundations::{
    SIGNATURE_BYTES,
    setup_selection::{ENDORSEMENT_BYTES, MAXIMUM_SELECTION_BYTES},
};

const SIGNATURE: [u8; SIGNATURE_BYTES] = [6; SIGNATURE_BYTES];
const ENDORSEMENT: [u8; ENDORSEMENT_BYTES] = [7; ENDORSEMENT_BYTES];

#[test]
fn an_emitted_selection_is_restored() {
    for body in [vec![], vec![5; 40], vec![5; MAXIMUM_SELECTION_BYTES]] {
        let packet = encode(&body, &SIGNATURE);
        assert_eq!(selection(&packet), Some((&body[..], &SIGNATURE[..])));
        let endorsed = [packet.as_slice(), &ENDORSEMENT].concat();
        assert_eq!(
            endorsed_selection(&endorsed),
            Some((&body[..], &SIGNATURE[..], &ENDORSEMENT[..]))
        );
    }
}

#[test]
fn a_selection_of_another_length_is_refused() {
    let packet = encode(&[5; 40], &SIGNATURE);
    let mut trailing = packet.clone();
    trailing.push(0);
    for (case, bytes) in [
        (
            "missing signature byte",
            packet[..packet.len() - 1].to_vec(),
        ),
        ("trailing byte", trailing),
        (
            "body past the selection bound",
            encode(&[5; MAXIMUM_SELECTION_BYTES + 1], &SIGNATURE),
        ),
        ("no length", packet[..3].to_vec()),
    ] {
        assert!(selection(&bytes).is_none(), "{case}");
        let endorsed = [bytes.as_slice(), &ENDORSEMENT].concat();
        assert!(endorsed_selection(&endorsed).is_none(), "{case}");
    }
    let endorsed = [packet.as_slice(), &ENDORSEMENT].concat();
    for (case, bytes) in [
        (
            "missing endorsement byte",
            endorsed[..endorsed.len() - 1].to_vec(),
        ),
        ("trailing byte", [endorsed.as_slice(), &[0]].concat()),
        ("endorsement alone", ENDORSEMENT.to_vec()),
    ] {
        assert!(endorsed_selection(&bytes).is_none(), "{case}");
    }
}
