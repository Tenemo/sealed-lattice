use super::*;
fn identity(value: u8) -> [u8; 64] {
    [value; 64]
}
const KNOWN: [(usize, [u8; 64], u64); 8] = [
    (3, [9; 64], 10),
    (0, [5; 64], 11),
    (3, [1; 64], 3),
    (3, [4; 64], 7),
    (1, [2; 64], 12),
    (0, [5; 64], 11),
    (2, [8; 64], 10),
    (4, [6; 64], 9),
];
#[test]
fn honest_listings_keep_on_time_envelopes_and_two_per_slot() {
    let every = [
        identity(9),
        identity(5),
        identity(1),
        identity(4),
        identity(2),
        identity(8),
        identity(6),
    ];
    assert_eq!(
        honest_listing(&known_on_time(5, KNOWN, 10), &every),
        vec![
            (2, identity(8)),
            (3, identity(1)),
            (3, identity(4)),
            (4, identity(6))
        ]
    );
    assert_eq!(
        honest_listing(&known_on_time(5, KNOWN, 12), &every),
        vec![
            (0, identity(5)),
            (1, identity(2)),
            (2, identity(8)),
            (3, identity(1)),
            (3, identity(4)),
            (4, identity(6)),
        ]
    );
    assert!(honest_listing(&known_on_time(5, KNOWN, 2), &every).is_empty());
    assert!(honest_listing(&known_on_time(5, [], u64::MAX), &every).is_empty());
    // Out-of-roster authors are never known.
    assert!(
        known_on_time(2, KNOWN, u64::MAX)
            .iter()
            .all(|slot| slot.len() == 1)
    );
}
#[test]
fn two_known_envelopes_are_listed_without_bodies() {
    // Only slot 2's body is held. Slot 3 knows three on-time envelopes
    // and lists the two smallest; slots 0, 1 and 4 know one unheld
    // envelope each and list nothing.
    let known = known_on_time(5, KNOWN, 12);
    assert_eq!(
        honest_listing(&known, &[identity(8)]),
        vec![(2, identity(8)), (3, identity(1)), (3, identity(4))]
    );
    assert!(
        honest_listing(&known, &[])
            .iter()
            .all(|(author, _)| *author == 3)
    );
    // Both envelopes are on time at close time 7. At 6 the second is
    // late and does not make the slot conflicting.
    assert_eq!(
        honest_listing(&known_on_time(5, KNOWN, 7), &[identity(1)]),
        vec![(3, identity(1)), (3, identity(4))]
    );
    assert_eq!(
        honest_listing(&known_on_time(5, KNOWN, 6), &[identity(1)]),
        vec![(3, identity(1))]
    );
}
#[test]
fn the_organizer_needs_only_single_known_bodies() {
    let known = known_on_time(5, KNOWN, 12);
    let held = [identity(5)];
    // Slot 3 needs no body; slot 0's body is held; slots 1 and 2 are not.
    assert!(ready_listing(
        &known,
        &held,
        &[(0, identity(5)), (3, identity(9))]
    ));
    assert!(ready_listing(
        &known,
        &held,
        &[(3, identity(1)), (3, identity(4))]
    ));
    assert!(!ready_listing(
        &known,
        &held,
        &[(0, identity(5)), (2, identity(8))]
    ));
    assert!(ready_listing(&known, &held, &[]));
    // An entry the organizer does not know, or a late one, is never ready.
    assert!(!ready_listing(&known, &held, &[(0, identity(7))]));
    assert!(!ready_listing(
        &known_on_time(5, KNOWN, 10),
        &held,
        &[(0, identity(5))]
    ));
    assert!(!ready_listing(&known, &held, &[(9, identity(5))]));
    let first = [(0, identity(5)), (1, identity(2)), (3, identity(1))];
    let second = [(1, identity(2)), (2, identity(8)), (3, identity(4))];
    assert_eq!(
        wanted_listing(&known, &held, [&first[..], &second[..]]),
        vec![(1, identity(2)), (2, identity(8))]
    );
    assert!(
        wanted_listing(
            &known,
            &[identity(2), identity(8), identity(5)],
            [&first[..], &second[..]]
        )
        .is_empty()
    );
    // Once a second envelope is known, the first is no longer wanted.
    let later = known_on_time(5, KNOWN.into_iter().chain([(2, identity(7), 1)]), 12);
    assert_eq!(
        wanted_listing(&later, &held, [&first[..], &second[..]]),
        vec![(1, identity(2))]
    );
}
#[test]
fn the_union_separates_absent_usable_and_conflicting_slots() {
    let first = [(0, identity(1)), (2, identity(3)), (2, identity(4))];
    let second = [(0, identity(1)), (1, identity(2))];
    let third = [(2, identity(5))];
    let slots = union(4, [&first[..], &second[..], &third[..]]);
    assert_eq!(slots[0], vec![identity(1)]);
    assert_eq!(slots[1], vec![identity(2)]);
    assert_eq!(slots[2], vec![identity(3), identity(4), identity(5)]);
    assert!(slots[3].is_empty());
    // Only the usable slots need bodies.
    assert_eq!(singletons(&slots), vec![(0, identity(1)), (1, identity(2))]);
    assert!(
        singletons(&union(3, [&first[..]]))
            .iter()
            .all(|(author, _)| *author == 0)
    );
    // One response alone may already make a slot conflicting.
    assert_eq!(union(3, [&first[..]])[2].len(), 2);
    assert!(union(3, []).iter().all(Vec::is_empty));
}
