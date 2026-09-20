use super::{Work, bounded, end, polynomial_name, refusal};
use evaluation_target::{
    certification::CertificateCollector,
    release::ReleaseContext,
    release_body::ReleaseBodyVerifier,
    target::VerifiedEvaluationTarget,
    terminal::{ReleaseCollector, verify_no_result},
};
use registration_credentials::release_signing::{
    RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES,
};
use setup_aggregate::{CHUNK_BYTES, ModulusKind, VerifiedAggregatePolynomial};
use std::{fs::File, io, path::Path, sync::Arc};

#[derive(Clone, Copy, PartialEq)]
pub enum Stage {
    Certificate,
    Terminal,
}

fn read_operand(
    target: &VerifiedEvaluationTarget,
    directory: &Path,
    index: usize,
    work: &mut Work,
) -> io::Result<VerifiedAggregatePolynomial> {
    let setup = target.inventory().setup();
    let kind =
        ModulusKind::for_contribution_polynomial(index).ok_or_else(|| refusal("key index"))?;
    let length = kind.degree() * kind.coefficient_bytes();
    let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
    let mut file = File::open(directory.join(polynomial_name(index)))?;
    if file.metadata()?.len() != length as u64 {
        return Err(refusal("release operand length"));
    }
    let mut verifier = setup.read_polynomial(index).map_err(refusal)?;
    let mut buffer = vec![0; capacity];
    let mut offset = 0;
    while offset < length {
        let count = capacity.min(length - offset);
        work.read(&mut file, &mut buffer[..count])?;
        verifier.push(offset, &buffer[..count]).map_err(refusal)?;
        offset += count;
    }
    end(&mut file)?;
    verifier.finish().map_err(refusal)
}

pub fn verify(
    target: Arc<VerifiedEvaluationTarget>,
    directory: &Path,
    aggregate: &Path,
    certificate_records: &Path,
    work: &mut Work,
    stage: Stage,
) -> io::Result<String> {
    if bounded(directory.join("target.bin"), 2048, work)? != target.body() {
        return Err(refusal("published target differs from recomputation"));
    }
    let count = target.inventory().setup().inventory().confirmations().len();
    let mut votes = CertificateCollector::new(target.clone());
    let mut unavailable_votes = Vec::new();
    let mut invalid_votes = Vec::new();
    for position in 0..count {
        if votes.accepted() >= votes.threshold() {
            break;
        }
        let packet = match bounded(
            directory.join(format!("target-vote-{position}.bin")),
            3375,
            work,
        ) {
            Ok(packet) => packet,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                unavailable_votes.push(position);
                continue;
            }
            Err(_) => {
                invalid_votes.push(position);
                continue;
            }
        };
        let accepted_before = votes.accepted();
        if votes.insert(&packet).is_err() {
            invalid_votes.push(position);
            assert_eq!(votes.accepted(), accepted_before);
            continue;
        }
        assert!(!votes.insert(&packet).map_err(refusal)?);
    }
    let certificate = Arc::new(votes.certificate().map_err(|_| {
        io::Error::new(io::ErrorKind::WouldBlock, "Insufficient valid target votes")
    })?);
    let certificate_authors: Vec<_> = certificate
        .votes()
        .iter()
        .map(|vote| vote.position())
        .collect();
    // A transport position need not equal the authenticated author. Retain
    // the exact accepted packets instead of locating them again by filename.
    std::fs::create_dir(certificate_records)?;
    for vote in certificate.votes() {
        work.save(
            &certificate_records.join(format!("target-vote-{}.bin", vote.position())),
            &vote.encode(),
        )?;
    }
    if stage == Stage::Certificate {
        let encrypted = target.ciphertext().is_some();
        if !encrypted {
            verify_no_result(certificate).map_err(refusal)?;
        }
        return Ok(format!(
            "{{\"kind\":\"certified-target\",\"encrypted\":{encrypted},\"certificateAuthors\":{certificate_authors:?},\"unavailableVotes\":{unavailable_votes:?},\"invalidVotes\":{invalid_votes:?}}}"
        ));
    }
    if target.ciphertext().is_none() {
        assert!(ReleaseCollector::new(certificate.clone()).is_err());
        verify_no_result(certificate).map_err(refusal)?;
        return Ok(format!(
            "{{\"kind\":\"no-result\",\"certificateAuthors\":{certificate_authors:?},\"unavailableVotes\":{unavailable_votes:?},\"invalidVotes\":{invalid_votes:?}}}"
        ));
    }
    assert!(verify_no_result(certificate.clone()).is_err());
    let mut collector = ReleaseCollector::new(certificate.clone()).map_err(refusal)?;
    let mut unavailable_releases = Vec::new();
    let mut invalid_releases = Vec::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    for position in 0..count {
        let packet = match bounded(
            directory.join(format!("release-envelope-{position}.bin")),
            RELEASE_ENVELOPE_BYTES + 3309,
            work,
        ) {
            Ok(packet) => packet,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                unavailable_releases.push(position);
                continue;
            }
            Err(_) => {
                invalid_releases.push(position);
                continue;
            }
        };
        let context = Arc::new(
            ReleaseContext::new(
                certificate.clone(),
                position,
                read_operand(&target, aggregate, 44 + 3 * position, work)?,
                read_operand(&target, aggregate, 45 + 3 * position, work)?,
            )
            .map_err(refusal)?,
        );
        let authentication = match context.authenticate(&packet) {
            Ok(value) => value,
            Err(_) => {
                invalid_releases.push(position);
                continue;
            }
        };
        let mut wrong = packet.clone();
        wrong[132] ^= 1;
        assert!(context.authenticate(&wrong).is_err());
        let mut file = match File::open(directory.join(format!("release-{position}.bin"))) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                unavailable_releases.push(position);
                continue;
            }
            Err(_) => {
                invalid_releases.push(position);
                continue;
            }
        };
        let verified = (|| {
            if file.metadata()?.len() != authentication.envelope().body_length() as u64 {
                return Err(refusal("published release body length differs"));
            }
            let mut header = [0; RELEASE_BODY_HEADER_BYTES];
            work.read(&mut file, &mut header)?;
            let mut verifier =
                ReleaseBodyVerifier::new(context.clone(), &header).map_err(refusal)?;
            let mut hostile = if position == 0 {
                let incomplete =
                    ReleaseBodyVerifier::new(context.clone(), &header).map_err(refusal)?;
                assert!(incomplete.finish().is_err());
                let mut changed = header;
                changed[144] ^= 1;
                assert!(ReleaseBodyVerifier::new(context.clone(), &changed).is_err());
                Some(ReleaseBodyVerifier::new(context.clone(), &header).map_err(refusal)?)
            } else {
                None
            };
            let mut received = header.len();
            let expected_length = authentication.envelope().body_length();
            while received < expected_length {
                let count = buffer.len().min(expected_length - received);
                work.read(&mut file, &mut buffer[..count])?;
                received += count;
                verifier.push(&buffer[..count]).map_err(refusal)?;
                if let Some(mut negative) = hostile.take() {
                    if received == expected_length {
                        buffer[count - 1] ^= 1;
                        let result = negative.push(&buffer[..count]);
                        assert!(result.is_err() || negative.finish().is_err());
                    } else {
                        negative.push(&buffer[..count]).map_err(refusal)?;
                        hostile = Some(negative);
                    }
                }
            }
            end(&mut file)?;
            Ok(Arc::new(
                verifier
                    .finish()
                    .map_err(refusal)?
                    .authenticate(authentication)
                    .map_err(refusal)?,
            ))
        })();
        let share = match verified {
            Ok(share) => share,
            Err(error) => {
                invalid_releases.push(position);
                eprintln!("Ignored invalid public release at position {position}: {error}");
                continue;
            }
        };
        assert!(collector.insert(share.clone()).map_err(refusal)?);
        assert!(!collector.insert(share.clone()).map_err(refusal)?);
        match collector.result() {
            Ok(result) => {
                return Ok(format!(
                    "{{\"kind\":\"result\",\"identifiers\":{:?},\"certificateAuthors\":{certificate_authors:?},\"releaseAuthors\":{:?},\"unavailableVotes\":{unavailable_votes:?},\"invalidVotes\":{invalid_votes:?},\"unavailableReleases\":{unavailable_releases:?},\"invalidReleases\":{invalid_releases:?}}}",
                    result.identifiers(),
                    result.participants(),
                ));
            }
            Err(evaluation_target::release::Error::Incomplete) => {}
            Err(error) => return Err(refusal(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "Insufficient valid release shares",
    ))
}
