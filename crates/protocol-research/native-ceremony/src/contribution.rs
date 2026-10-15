use crate::public_output::PublicOutput;
use participant_module::{
    Enrollment,
    contribution_session::{ContributionSession, ProverOperation},
    offer_signing::OfferSigning,
};
use protocol_foundations::roster::RetainedContributionContext;
use protocol_foundations::roster_authentication::AuthenticatedRosterProposal;
use setup_aggregate::contribution_family;
use std::{
    cell::RefCell,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};
use supported_profile::Profile;

// The session's proof phases: one hundred plus the prover's.
const POLYNOMIALS_PHASE: u32 = 107;
const OUTPUT_PHASE: u32 = 110;
const DONE_PHASE: u32 = 111;

/// Publishes each contribution body polynomial the session emits under its
/// final name once the next object begins or generation ends. Object zero is
/// the statement header and object i + 1 setup polynomial i.
struct BodyFiles {
    profile: Profile,
    directory: PathBuf,
    open: Option<PublicOutput>,
}
impl BodyFiles {
    fn receive(&mut self, object: usize, offset: usize, bytes: &[u8]) {
        if offset == 0 {
            self.finish();
            if let Some(index) = object.checked_sub(1).filter(|index| {
                contribution_family(self.profile, *index).is_some()
                    || (self.profile.setup_polynomials()
                        ..self.profile.setup_polynomials()
                            + supported_profile::source_linked::SOURCE_POLYNOMIALS)
                        .contains(index)
            }) {
                let name = format!("polynomial-{index:02}.bin");
                self.open = Some(PublicOutput::create(self.directory.join(name)).unwrap());
            }
        }
        if let Some(file) = self.open.as_mut() {
            file.write_all(bytes).unwrap();
        }
    }
    fn finish(&mut self) {
        if let Some(file) = self.open.take() {
            file.finish().unwrap();
        }
    }
}

/// Generates and proves the contribution through the participant module's
/// contribution session, in the browser worker's command order, then signs
/// the offer over the published body and proof.
pub fn generate(
    poll: &protocol_foundations::poll::VerifiedPoll,
    roster: &Arc<AuthenticatedRosterProposal>,
    enrollment: &mut Enrollment,
    position: usize,
    registration_sources: &Path,
    directory: &Path,
) -> (OfferSigning, Vec<u8>) {
    std::fs::create_dir(directory).unwrap();
    let profile = roster.proposal().profile();
    let source_range = roster.proposal().source_ciphertext_range();
    let mut registered_sources = File::open(registration_sources).unwrap();
    registered_sources
        .seek(SeekFrom::Start(source_range.start as u64))
        .unwrap();
    let mut selected_source =
        PublicOutput::create(directory.join("source-ciphertexts.bin")).unwrap();
    let copied = std::io::copy(
        &mut registered_sources.take(source_range.len() as u64),
        &mut selected_source,
    )
    .unwrap();
    assert_eq!(copied, source_range.len() as u64);
    selected_source.finish().unwrap();
    let files = Rc::new(RefCell::new(BodyFiles {
        profile,
        directory: directory.to_owned(),
        open: None,
    }));
    let receiver = Rc::clone(&files);
    let mut session = ContributionSession::new(Box::new(move |object, offset, bytes| {
        receiver.borrow_mut().receive(object, offset, bytes);
    }));
    let source = enrollment.contribution_source(poll, profile).unwrap();
    let source = enrollment
        .credential
        .source_contribution(roster, position, source)
        .unwrap();
    session
        .begin_verified(roster.proposal(), position, source)
        .unwrap();
    while session.phase() < 100 {
        session.advance(ProverOperation::Generate, 0, 0).unwrap();
    }
    files.borrow_mut().finish();
    while session.phase() != POLYNOMIALS_PHASE {
        session.advance(ProverOperation::Step, 0, 0).unwrap();
    }
    // The prover takes the published body polynomials back from the host
    // and recomputes the roster keys and common polynomials itself.
    for index in
        0..profile.setup_polynomials() + supported_profile::source_linked::SOURCE_POLYNOMIALS
    {
        if index < profile.setup_polynomials() && contribution_family(profile, index).is_none() {
            session
                .advance(ProverOperation::ConsumePredecessor, index, 0)
                .unwrap();
            continue;
        }
        session
            .advance(ProverOperation::BeginPolynomial, index, 0)
            .unwrap();
        let mut file = File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
        loop {
            let length = file.read(&mut session.input()[..1 << 20]).unwrap();
            if length == 0 {
                break;
            }
            session
                .advance(ProverOperation::PushPolynomial, 0, length)
                .unwrap();
        }
        session
            .advance(ProverOperation::FinishPolynomial, 0, 0)
            .unwrap();
    }
    // The linear oracle, then the folded combination.
    session.advance(ProverOperation::Step, 0, 0).unwrap();
    session.advance(ProverOperation::Step, 0, 0).unwrap();
    for phase in [112, 113] {
        assert_eq!(session.phase(), phase);
        for index in profile.committed_polynomials() {
            session
                .advance(ProverOperation::BeginPolynomial, index, 0)
                .unwrap();
            let mut file =
                File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
            loop {
                let length = file.read(&mut session.input()[..1 << 20]).unwrap();
                if length == 0 {
                    break;
                }
                session
                    .advance(ProverOperation::PushPolynomial, 0, length)
                    .unwrap();
            }
            session
                .advance(ProverOperation::FinishPolynomial, 0, 0)
                .unwrap();
        }
    }
    let proof_path = directory.join("proof.bin");
    let mut file = PublicOutput::create(&proof_path).unwrap();
    while session.phase() == OUTPUT_PHASE {
        session.advance(ProverOperation::NextOutput, 0, 0).unwrap();
        file.write_all(session.output()).unwrap();
    }
    assert_eq!(session.phase(), DONE_PHASE);
    file.finish().unwrap();
    drop(session);
    let body_header = protocol_foundations::contribution_body::body_header(
        profile,
        std::fs::metadata(&proof_path).unwrap().len() as usize,
    )
    .unwrap();
    let context = RetainedContributionContext::parse(
        &enrollment.credential,
        &roster.proposal().records()[position],
        poll,
        position,
        roster.proposal().body(),
    )
    .unwrap();
    let mut signing = OfferSigning::default();
    signing
        .begin_body(
            &enrollment.credential,
            context,
            &body_header,
            enrollment
                .contribution_coordinate_hash(poll, profile)
                .unwrap(),
        )
        .unwrap();
    let mut buffer = vec![0; 1 << 20];
    for index in profile.streamed_contribution_polynomials() {
        let mut file = File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            signing
                .polynomial(index, offset, &buffer[..length])
                .unwrap();
            offset += length;
        }
    }
    let mut proof = File::open(&proof_path).unwrap();
    let mut offset = 0;
    loop {
        let length = proof.read(&mut buffer).unwrap();
        if length == 0 {
            break;
        }
        signing.proof(offset, &buffer[..length]).unwrap();
        offset += length;
    }
    signing.finish_body().unwrap();
    signing.sign(&mut enrollment.credential).unwrap();
    (signing, body_header.to_vec())
}
