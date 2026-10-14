use super::*;

const SIGNATURE: [u8; SIGNATURE_BYTES] = [6; SIGNATURE_BYTES];
const MAXIMUM: usize = 40;

#[test]
fn encodes_the_length_body_and_signature_and_reads_them_back() {
    for body in [vec![], vec![5; 1], vec![5; MAXIMUM]] {
        let packet = encode(&body, &SIGNATURE);
        let expected = [
            &(body.len() as u32).to_le_bytes()[..],
            &body[..],
            &SIGNATURE[..],
        ]
        .concat();
        assert_eq!(packet, expected);
        assert_eq!(split(&packet, MAXIMUM), Some((&body[..], &SIGNATURE[..])));
        let followed = [packet.as_slice(), &[1, 2, 3]].concat();
        assert_eq!(
            leading(&followed, MAXIMUM),
            Some((&body[..], &SIGNATURE[..], &[1, 2, 3][..]))
        );
        assert_eq!(split(&followed, MAXIMUM), None);
    }
}

#[test]
fn refuses_a_short_packet_or_a_body_past_the_bound() {
    let packet = encode(&[5; MAXIMUM], &SIGNATURE);
    for (case, bytes) in [
        ("no length", &packet[..3]),
        ("length alone", &packet[..4]),
        ("missing body byte", &packet[..4 + MAXIMUM - 1]),
        ("missing signature byte", &packet[..packet.len() - 1]),
    ] {
        assert_eq!(leading(bytes, MAXIMUM), None, "{case}");
        assert_eq!(split(bytes, MAXIMUM), None, "{case}");
    }
    assert_eq!(split(&packet, MAXIMUM - 1), None);
    // A length past every bound is refused before any sum of lengths.
    let mut huge = packet.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(leading(&huge, MAXIMUM), None);
}
