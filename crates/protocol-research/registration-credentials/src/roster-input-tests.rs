use super::*;
use crate::registration::CHUNK_LIMIT;
use crate::registration::{KEY_BYTES, session::tests::unproved_record};

// One record is open for each helper, or one without helpers. Each
// candidate opens once, every step names an open record, and no failed
// proof becomes a positive record or poisons other positions.
#[test]
fn records_open_within_the_limit_and_the_roster_waits_for_every_verdict() {
    let (packet, header) = unproved_record([4; 64]);
    let input = [
        packet.identity.as_slice(),
        &[4; 64],
        &3u16.to_le_bytes(),
        &(packet.body.len() as u32).to_le_bytes(),
        &packet.body,
        &packet.signature,
    ]
    .concat();
    // The poll admits at most three participants, so a roster of four
    // is refused before any record opens.
    let above = [&input[..128], &4u16.to_le_bytes(), &input[130..]].concat();
    assert!(matches!(
        RosterInputVerifier::new(&above),
        Err(Error::Context)
    ));
    let mut roster = RosterInputVerifier::new(&input).unwrap();
    let record = |position: u16| {
        [
            position.to_le_bytes().as_slice(),
            &[11; 64],
            &(header.len() as u32).to_le_bytes(),
            &header,
            &[0; 3309],
        ]
        .concat()
    };
    let key = vec![0; KEY_BYTES];
    roster.begin_record(&record(0)).unwrap();
    assert!(matches!(roster.push_key(1, &key[..1]), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
    let opened = open_record_limit().min(3) as u16;
    for position in 1..opened {
        roster.begin_record(&record(position)).unwrap();
    }
    if opened < 3 {
        assert!(matches!(
            roster.begin_record(&record(opened)),
            Err(Error::Shape)
        ));
    }
    for position in 0..3 {
        if position >= opened {
            roster.begin_record(&record(position)).unwrap();
        }
        for part in key.chunks(CHUNK_LIMIT) {
            roster.push_key(position.into(), part).unwrap();
        }
        roster.finish_key(position.into()).unwrap();
        assert!(roster.finish_record(position.into()).is_err());
        assert!(matches!(
            roster.begin_record(&record(position)),
            Err(Error::Shape)
        ));
        assert!(matches!(
            roster.finish_record(position.into()),
            Err(Error::Shape)
        ));
        roster.discard_record(position.into()).unwrap();
        let mut other_identity = record(position);
        other_identity[2] ^= 1;
        assert!(matches!(
            roster.begin_record(&other_identity),
            Err(Error::Context)
        ));
        roster.begin_record(&record(position)).unwrap();
        roster.discard_record(position.into()).unwrap();
    }
    assert!(matches!(roster.begin_record(&record(3)), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
}
