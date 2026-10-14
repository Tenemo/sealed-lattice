use ballot_proof::submission::{
    AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
    authenticate_envelope,
};
use protocol_foundations::{SIGNATURE_BYTES, ballot_authentication::BallotEnvelope, signed_packet};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

/// One signed submission and its public body file.
#[derive(Clone)]
pub struct Submission {
    pub envelope: BallotEnvelope,
    pub signature: [u8; SIGNATURE_BYTES],
    pub body: PathBuf,
}

pub(super) fn read_chunks(path: &Path, mut consume: impl FnMut(&[u8])) -> usize {
    let mut file = File::open(path).unwrap();
    let mut buffer = vec![0; 1 << 20];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        consume(&buffer[..count]);
        total += count;
    }
    total
}

/// The owning envelope authentication, without the body.
pub fn envelope(
    setup: &VerifiedSetupAggregate,
    submission: &Submission,
) -> AuthenticatedBallotEnvelope {
    authenticate_envelope(setup, submission.envelope.bytes(), &submission.signature).unwrap()
}

/// Streams the complete body through the owning envelope and body checks.
pub fn authenticate(
    setup: &VerifiedSetupAggregate,
    submission: &Submission,
    hashed: &mut usize,
) -> AuthenticatedBallotBody {
    let authentication =
        authenticate_envelope(setup, submission.envelope.bytes(), &submission.signature).unwrap();
    let mut body = BallotBodyAuthentication::new(authentication).unwrap();
    *hashed += read_chunks(&submission.body, |bytes| body.push(bytes).unwrap());
    body.finish().unwrap()
}

/// The body and signature of a packet the ceremony produced.
pub fn split(packet: &[u8]) -> (&[u8], &[u8]) {
    signed_packet::split(packet, packet.len()).expect("A ceremony packet is well formed.")
}

pub(super) fn control(submission: &Submission) -> Vec<u8> {
    [
        submission.envelope.bytes().as_slice(),
        &submission.signature,
    ]
    .concat()
}

/// Writes the public close records and the index of every listed submission.
pub fn write_records<'a>(
    directory: &Path,
    output: &Path,
    intent: &[u8],
    responses: impl IntoIterator<Item = (usize, &'a Vec<u8>)>,
    proposal: &[u8],
    listed: &[&Submission],
) {
    std::fs::create_dir(directory).unwrap();
    crate::write(directory.join("intent.bin"), intent);
    for (position, response) in responses {
        crate::write(directory.join(format!("response-{position}.bin")), response);
    }
    crate::write(directory.join("proposal.bin"), proposal);
    let mut index = String::new();
    for (ordinal, submission) in listed.iter().enumerate() {
        let name = format!("submission-{ordinal}.bin");
        crate::write(
            directory.join(&name),
            &[
                submission.envelope.bytes().as_slice(),
                &submission.signature,
            ]
            .concat(),
        );
        let body = submission.body.strip_prefix(output).unwrap();
        index.push_str(&format!(
            "{name} {}\n",
            body.to_str().unwrap().replace('\\', "/")
        ));
    }
    crate::write(directory.join("submissions.txt"), index.as_bytes());
}

pub(super) fn wanted_bytes(submissions: &[&Submission]) -> Vec<u8> {
    submissions
        .iter()
        .flat_map(|submission| {
            (submission.envelope.position() as u16)
                .to_le_bytes()
                .into_iter()
                .chain(submission.envelope.identity())
        })
        .collect()
}
