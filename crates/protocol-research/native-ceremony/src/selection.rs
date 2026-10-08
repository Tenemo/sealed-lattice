use crate::{OriginalEnrollments, aggregate, contribution};
use protocol_foundations::{
    contribution_offer::authenticate_offer,
    poll::VerifiedPoll,
    roster::RetainedContributionContext,
    roster_authentication::AuthenticatedRosterProposal,
    setup_selection::{
        AuthenticatedSelectionCertificate, authenticate_certificate, authenticate_endorsement,
        authenticate_selection, encode_certificate,
    },
};
use setup_aggregate::verified::{
    SetupAggregator, VerifiedSelectionInputs, VerifiedSetupAggregate, build_selection,
};
use std::{fs, path::Path, sync::Arc};

pub struct Prepared {
    pub setup: Arc<VerifiedSetupAggregate>,
    pub certificate: AuthenticatedSelectionCertificate,
}

pub fn run(
    output: &Path,
    poll: &VerifiedPoll,
    roster: Arc<AuthenticatedRosterProposal>,
    enrollments: &mut OriginalEnrollments,
    selected_authors: &[usize],
    mut alternate_endorser: Option<(usize, protocol_foundations::Credential)>,
    selection_fork: bool,
) -> Prepared {
    let profile = roster.proposal().profile();
    for (position, enrollment) in enrollments.iter_mut() {
        let retained = RetainedContributionContext::parse(
            &enrollment.credential,
            &roster.proposal().records()[position],
            poll,
            position,
            roster.proposal().body(),
        )
        .unwrap();
        enrollment.credential.confirm_roster(&retained).unwrap();
        if position >= profile.setup_eligible_contributors() {
            assert!(roster.proposal().contribution_role(position).is_err());
        }
    }
    let mut offers = Vec::new();
    let mut directories = Vec::new();
    let mut headers = Vec::new();
    for (position, enrollment) in enrollments
        .iter_mut()
        .filter(|(position, _)| *position < profile.setup_eligible_contributors())
    {
        let draft = output.join(format!("draft-contribution-{position}"));
        let (signing, header) = contribution::generate(poll, &roster, enrollment, position, &draft);
        let (envelope, signature) = signing.offer().unwrap();
        let author = output.join(format!("contribution-{position}"));
        fs::create_dir(&author).unwrap();
        let identity: String = envelope
            .body_identity()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let directory = author.join(identity);
        assert!(!directory.exists());
        fs::rename(&draft, &directory).unwrap();
        crate::write(directory.join("body-header.bin"), &header);
        crate::write(directory.join("offer.bin"), envelope.bytes());
        crate::write(directory.join("offer-signature.bin"), signature);
        let authenticated =
            Arc::new(authenticate_offer(roster.clone(), envelope.bytes(), signature).unwrap());
        let verified = Arc::new(aggregate::verify_offer(
            authenticated.clone(),
            &directory,
            &header,
        ));
        assert_eq!(verified.envelope().position(), position);
        offers.push((authenticated, verified));
        directories.push(directory);
        headers.push(header);
    }
    aggregate::verify_source_refusals(
        &offers
            .iter()
            .map(|(authenticated, _)| authenticated.clone())
            .collect::<Vec<_>>(),
        &directories,
        &headers,
    );
    let selected = selected_authors
        .iter()
        .map(|position| {
            offers
                .iter()
                .find(|(_, offer)| offer.envelope().position() == *position)
                .unwrap()
                .1
                .clone()
        })
        .collect::<Vec<_>>();
    let selected_directories = selected_authors
        .iter()
        .map(|position| {
            directories[offers
                .iter()
                .position(|(_, offer)| offer.envelope().position() == *position)
                .unwrap()]
            .clone()
        })
        .collect::<Vec<_>>();
    let proposal = build_selection(&roster, &selected).unwrap();
    let mut wrong_order = selected.clone();
    wrong_order.reverse();
    assert!(build_selection(&roster, &wrong_order).is_err());
    let mut duplicate = selected.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(build_selection(&roster, &duplicate).is_err());
    let signature = enrollments[0]
        .credential
        .sign_selection_proposal(&roster, &proposal)
        .unwrap();
    crate::write(output.join("selection.bin"), proposal.body());
    crate::write(output.join("selection-signature.bin"), &signature);
    let proposal =
        Arc::new(authenticate_selection(roster.clone(), proposal.body(), &signature).unwrap());
    // Positive holders are a pool; the signed selection alone fixes order.
    assert!(SetupAggregator::new(proposal.clone(), wrong_order).is_ok());
    assert!(SetupAggregator::new(proposal.clone(), duplicate).is_err());
    if let Some((_, extra)) = offers
        .iter()
        .find(|(_, offer)| !selected_authors.contains(&offer.envelope().position()))
    {
        let mut other = selected.clone();
        *other.last_mut().unwrap() = extra.clone();
        other.sort_by_key(|offer| offer.envelope().position());
        assert!(build_selection(&roster, &other).is_ok());
        assert!(SetupAggregator::new(proposal.clone(), other).is_err());
    }
    let inputs = Arc::new(aggregate::verify(
        proposal.clone(),
        selected,
        &selected_directories,
        &output.join("aggregates"),
    ));
    let selected_indices: Vec<_> = selected_authors
        .iter()
        .map(|position| {
            offers
                .iter()
                .position(|(_, offer)| offer.envelope().position() == *position)
                .unwrap()
        })
        .collect();
    aggregate::verify_streamed_selection(
        proposal.clone(),
        &selected_indices
            .iter()
            .map(|index| offers[*index].0.clone())
            .collect::<Vec<_>>(),
        &selected_directories,
        &selected_indices
            .iter()
            .map(|index| headers[*index].clone())
            .collect::<Vec<_>>(),
        &inputs,
        &output.join("aggregates"),
    );
    let retained = inputs.retain(&enrollments[0].credential, poll).unwrap();
    let restored = VerifiedSelectionInputs::restore(
        &enrollments[0].credential,
        poll,
        proposal.clone(),
        &retained,
    )
    .unwrap();
    assert_eq!(restored.identity(), inputs.identity());
    assert_eq!(restored.polynomials().len(), inputs.polynomials().len());
    for (left, right) in restored.polynomials().iter().zip(inputs.polynomials()) {
        assert_eq!(
            (left.index(), left.bytes(), left.digest()),
            (right.index(), right.bytes(), right.digest())
        );
    }
    for offset in [4, retained.len() - 1] {
        let mut changed = retained.clone();
        changed[offset] ^= 1;
        assert!(
            VerifiedSelectionInputs::restore(
                &enrollments[0].credential,
                poll,
                proposal.clone(),
                &changed
            )
            .is_err()
        );
    }
    assert!(
        VerifiedSelectionInputs::restore(
            &enrollments[enrollments.positions()[1]].credential,
            poll,
            proposal.clone(),
            &retained
        )
        .is_err()
    );
    let losing_inputs = if selection_fork {
        let (position, organizer) = alternate_endorser.as_mut().unwrap();
        assert_eq!(*position, 0);
        let losing_offers = offers
            .iter()
            .filter(|(_, offer)| [0, 1].contains(&offer.envelope().position()))
            .map(|(_, offer)| offer.clone())
            .collect::<Vec<_>>();
        let losing_directories = offers
            .iter()
            .zip(&directories)
            .filter(|((_, offer), _)| [0, 1].contains(&offer.envelope().position()))
            .map(|(_, directory)| directory.clone())
            .collect::<Vec<_>>();
        let losing = build_selection(&roster, &losing_offers).unwrap();
        assert_ne!(losing.identity(), inputs.identity());
        let signature = organizer.sign_selection_proposal(&roster, &losing).unwrap();
        crate::write(output.join("losing-selection.bin"), losing.body());
        crate::write(output.join("losing-selection-signature.bin"), &signature);
        let losing =
            Arc::new(authenticate_selection(roster.clone(), losing.body(), &signature).unwrap());
        let losing_inputs = Arc::new(aggregate::verify(
            losing.clone(),
            losing_offers,
            &losing_directories,
            &output.join("losing-aggregates"),
        ));
        let packet = enrollments[1]
            .credential
            .endorse_selection(&roster, losing_inputs.selection().selection(), 1)
            .unwrap();
        authenticate_endorsement(&roster, losing.selection(), &packet).unwrap();
        crate::write(output.join("losing-selection-endorsement-1.bin"), &packet);
        let retained_loser = losing_inputs
            .retain(&enrollments[1].credential, poll)
            .unwrap();
        assert!(
            VerifiedSelectionInputs::restore(
                &enrollments[1].credential,
                poll,
                proposal.clone(),
                &retained_loser
            )
            .is_err()
        );
        assert!(
            enrollments[1]
                .credential
                .endorse_selection(&roster, proposal.selection(), 1)
                .is_err()
        );
        Some(losing_inputs)
    } else {
        None
    };
    let mut endorsements = Vec::new();
    for (position, enrollment) in enrollments.iter_mut() {
        if selection_fork && position == 1 {
            continue;
        }
        let packet = enrollment
            .credential
            .endorse_selection(&roster, inputs.selection().selection(), position)
            .unwrap();
        let endorsement = authenticate_endorsement(&roster, proposal.selection(), &packet).unwrap();
        crate::write(
            output.join(format!("selection-endorsement-{position}.bin")),
            &packet,
        );
        endorsements.push(endorsement);
    }
    let quorum = profile.inventory_threshold();
    let carrier = encode_certificate(&proposal, &endorsements[..quorum]).unwrap();
    let certificate = authenticate_certificate(roster.clone(), &carrier).unwrap();
    let setup = Arc::new(inputs.certify(&certificate).unwrap());
    if let Some(losing) = losing_inputs {
        assert!(losing.certify(&certificate).is_err());
        let winner = participant_module::ballot::retained_setup_reference(
            &enrollments[1].credential,
            poll,
            &setup,
        )
        .unwrap();
        let accepted = VerifiedSetupAggregate::restore(
            &enrollments[1].credential,
            poll,
            &certificate,
            &winner,
        )
        .unwrap();
        assert_eq!(accepted.identity(), setup.identity());
        assert!(
            enrollments[1]
                .credential
                .endorse_selection(&roster, proposal.selection(), 1)
                .is_err()
        );
    }
    let alternative = if endorsements.len() > quorum {
        Some(encode_certificate(&proposal, &endorsements[endorsements.len() - quorum..]).unwrap())
    } else if let Some((position, mut credential)) = alternate_endorser {
        // Only the declared corrupt participant forks its own signing state.
        // The same q positions carry another valid signature realization.
        let packet = credential
            .endorse_selection(&roster, proposal.selection(), position)
            .unwrap();
        let mut alternative = endorsements[..quorum].to_vec();
        let slot = alternative
            .iter()
            .position(|endorsement| endorsement.position() == position)
            .unwrap();
        alternative[slot] =
            authenticate_endorsement(&roster, proposal.selection(), &packet).unwrap();
        Some(encode_certificate(&proposal, &alternative).unwrap())
    } else {
        None
    };
    if let Some(alternative) = alternative {
        assert_ne!(alternative, carrier);
        let alternative = authenticate_certificate(roster, &alternative).unwrap();
        let same = inputs.certify(&alternative).unwrap();
        assert_eq!(same.identity(), setup.identity());
        for (left, right) in same.polynomials().iter().zip(setup.polynomials()) {
            assert_eq!(
                (left.index(), left.bytes(), left.digest()),
                (right.index(), right.bytes(), right.digest())
            );
        }
        crate::write(
            output.join("setup-certificate-alternative.bin"),
            alternative.bytes(),
        );
    }
    crate::write(output.join("setup-certificate.bin"), &carrier);
    crate::write(output.join("setup-identity.bin"), &setup.identity());
    Prepared { setup, certificate }
}
