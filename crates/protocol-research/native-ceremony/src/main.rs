mod aggregate;
mod ballots;
mod close;
#[path = "committed-offer.rs"]
mod committed_offer;
mod completion;
mod contribution;
mod enrollment;
#[path = "no-result-close.rs"]
mod no_result_close;
mod participants;
#[path = "public-output.rs"]
mod public_output;
mod scenario;
#[path = "selected-setup-completion.rs"]
mod selected_setup_completion;
mod selection;
use participant_module::finality_work::OwnBallotInclusion;
use participants::OriginalEnrollments;
use protocol_foundations::{
    roster::RosterProposal, roster_authentication::authenticate_roster_proposal,
};
use scenario::Scenario;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use supported_profile::Profile;

// Every participant of this ceremony creates honest ballots; a corrupt
// participant's build of the ballot proof never reaches it.
const _: () = assert!(!ballot_proof::private_ballot::FALSE_STATEMENT);

fn write(path: impl AsRef<Path>, bytes: &[u8]) {
    let mut output = public_output::PublicOutput::create(path).unwrap();
    output.write_all(bytes).unwrap();
    output.finish().unwrap();
}
/// Arguments: the new output directory, the runtime identity file, the
/// scratch directory, the participant and option counts, and optionally
/// `empty` or `invalid-only` for a no-result case, or `setup-departure` or
/// `selection-fork` for a four-participant setup case.
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        arguments.len() == 5
            || (arguments.len() == 6
                && matches!(
                    arguments[5].as_str(),
                    "empty"
                        | "invalid-only"
                        | "setup-departure"
                        | "selection-fork"
                        | "committed-offer"
                ))
    );
    let scratch = PathBuf::from(&arguments[2]);
    assert!(scratch.is_dir());
    let profile =
        Profile::new(arguments[3].parse().unwrap(), arguments[4].parse().unwrap()).unwrap();
    if arguments
        .get(5)
        .is_some_and(|mode| mode == "committed-offer")
    {
        assert_eq!(profile, Profile::new(3, 2).unwrap());
    }
    let scenario = if arguments
        .get(5)
        .is_some_and(|mode| mode == "setup-departure")
    {
        assert_eq!(profile, Profile::new(4, 2).unwrap());
        Scenario::setup_departure()
    } else if arguments
        .get(5)
        .is_some_and(|mode| mode == "selection-fork")
    {
        assert_eq!(profile, Profile::new(4, 2).unwrap());
        Scenario::selection_fork()
    } else {
        Scenario::new(profile)
    };
    let count = profile.participants();
    let output = PathBuf::from(&arguments[0]);
    fs::create_dir(&output).unwrap();
    let runtime_bytes = fs::read(&arguments[1]).unwrap();
    let runtime: [u8; 64] = runtime_bytes.try_into().unwrap();
    let enrollment::Enrolled {
        packet,
        poll,
        mut enrollments,
        records,
        organizer,
        corrupt,
    } = enrollment::run(&output, runtime, &scenario);
    let proposal = RosterProposal::new(&poll, records).unwrap();
    assert_eq!(proposal.profile(), profile);
    let proposal_signature = enrollments[0]
        .credential
        .sign_roster_proposal(&proposal)
        .unwrap();
    write(output.join("proposal.bin"), proposal.body());
    write(output.join("proposal-signature.bin"), &proposal_signature);
    let roster = Arc::new(authenticate_roster_proposal(proposal, &proposal_signature).unwrap());
    println!("Verified original enrollment roster");
    let mut enrollments = OriginalEnrollments::new(enrollments);
    if arguments
        .get(5)
        .is_some_and(|mode| mode == "committed-offer")
    {
        let authors: Vec<_> = (0..profile.setup_contributors()).collect();
        selection::run(
            &output,
            &poll,
            roster,
            &mut enrollments,
            &authors,
            None,
            false,
        );
        println!("Verified the committed setup and its complete certificate");
        return;
    }
    if let Some(position) = scenario.departed {
        // No future message or private operation can access this authority.
        enrollments.depart(position);
        assert_eq!(enrollments.positions(), [0, 2, 3]);
    }
    let selected_authors: Vec<_> = if scenario.departed.is_some() || scenario.selection_fork {
        vec![0, 2]
    } else {
        (0..profile.setup_contributors()).collect()
    };
    let alternate_endorser = (scenario.departed.is_some() || scenario.selection_fork).then(|| {
        let position = if scenario.selection_fork { 0 } else { 2 };
        let signer = if position == 0 {
            &organizer
        } else {
            corrupt.as_ref().unwrap()
        };
        let mut credential = signer.open(&poll, roster.proposal(), position);
        credential
            .unlock_unused_purposes(
                protocol_foundations::SigningPurpose::SelectionEndorsement.mask()
                    | protocol_foundations::SigningPurpose::SelectionProposal.mask(),
            )
            .unwrap();
        (position, credential)
    });
    let prepared = selection::run(
        &output,
        &poll,
        roster,
        &mut enrollments,
        &selected_authors,
        alternate_endorser,
        scenario.selection_fork,
    );
    let setup = prepared.setup;
    let certificate = prepared.certificate;
    for (_, enrollment) in enrollments.iter_mut() {
        enrollment.retire_sources();
        enrollment.credential.retire_preparation();
        assert!(enrollment.sources_retired());
        assert!(enrollment.contribution_source(&poll, profile).is_err());
        assert!(
            enrollment
                .contribution_coordinate_hash(&poll, profile)
                .is_err()
        );
    }
    if scenario.departed.is_some() || scenario.selection_fork {
        selected_setup_completion::run(
            &output,
            &scratch,
            poll,
            setup,
            &packet,
            &mut enrollments,
            &scenario,
        );
        return;
    }
    if let Some(mode) = arguments.get(5) {
        let invalid_only = mode == "invalid-only";
        let barrier = no_result_close::run(
            &output,
            poll.clone(),
            setup.clone(),
            &mut enrollments,
            invalid_only,
            &scenario,
        );
        let statuses = (0..enrollments.len())
            .map(|position| {
                (
                    position,
                    if invalid_only && position == 0 {
                        OwnBallotInclusion::Included
                    } else {
                        OwnBallotInclusion::NotCast
                    },
                )
            })
            .collect();
        completion::run(
            &output,
            &scratch,
            barrier,
            &mut enrollments,
            completion::Finality {
                signers: (0..count).collect(),
                statuses,
                forks: Vec::new(),
            },
            &scenario,
        );
        return;
    }
    let final_keys = aggregate::final_keys(&output, profile);
    let ballot_directory = output.join("ballot");
    fs::create_dir(&ballot_directory).unwrap();
    let submissions = ballots::run(
        &ballots::BallotInputs {
            poll: &poll,
            setup: &setup,
            definition: &packet,
            final_keys: &final_keys,
            directory: &ballot_directory,
            scenario: &scenario,
        },
        &certificate,
        &mut enrollments,
        &organizer,
    );
    let equivocator = scenario.equivocator.map(|position| {
        let corrupt = corrupt.as_ref().unwrap();
        let restore = || corrupt.restored(&poll, setup.roster().proposal(), position);
        // A corrupt participant's own root may unlock any purpose on its
        // forks.
        close::Equivocator {
            forks: std::array::from_fn(|_| {
                let mut fork = restore();
                fork.unlock_unused_purposes(protocol_foundations::SigningPurpose::Ballot.mask())
                    .unwrap();
                fork
            }),
            restored: restore(),
        }
    });
    let restored = close::Restored {
        equivocator,
        organizer: organizer.restored(&poll, setup.roster().proposal(), 0),
    };
    let (barrier, late_fork) = close::run(
        &output,
        poll,
        setup,
        &mut enrollments,
        &submissions,
        restored,
        &scenario,
    );
    // Every corrupt participant withholds its target signature, so the
    // certificate needs every honest participant, including the omitted
    // voter.
    let statuses = (0..count)
        .map(|position| {
            let status = if scenario.usable().contains(&position) {
                OwnBallotInclusion::Included
            } else if Some(position) == scenario.omitted {
                OwnBallotInclusion::Omitted
            } else {
                OwnBallotInclusion::NotCast
            };
            (position, status)
        })
        .collect();
    completion::run(
        &output,
        &scratch,
        barrier,
        &mut enrollments,
        completion::Finality {
            signers: scenario.honest(),
            statuses,
            forks: late_fork
                .map(|fork| {
                    (
                        scenario.equivocator.unwrap(),
                        fork,
                        OwnBallotInclusion::Late,
                    )
                })
                .into_iter()
                .collect(),
        },
        &scenario,
    );
    println!(
        "Fresh original setup, linked proof, signed ballot and quorum close evidence verified"
    );
}
