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
    work: &mut Work,
) -> io::Result<String> {
    if bounded(directory.join("target.bin"), 2048, work)? != target.body() {
        return Err(refusal("published target differs from recomputation"));
    }
    let count = target.inventory().setup().inventory().confirmations().len();
    let mut votes = CertificateCollector::new(target.clone());
    for position in 0..count {
        let packet = bounded(
            directory.join(format!("target-vote-{position}.bin")),
            3375,
            work,
        )?;
        if position == 0 {
            if packet.len() != 3375 {
                return Err(refusal("vote framing"));
            }
            let mut corrupt = packet.clone();
            corrupt[100] ^= 1;
            assert!(votes.insert(&corrupt).is_err());
            assert!(votes.certificate().is_err());
        }
        assert!(votes.insert(&packet).map_err(refusal)?);
        assert!(!votes.insert(&packet).map_err(refusal)?);
        if position + 1 < votes.threshold() {
            assert!(votes.certificate().is_err());
        }
    }
    let certificate = Arc::new(votes.certificate().map_err(refusal)?);
    if target.ciphertext().is_none() {
        assert!(ReleaseCollector::new(certificate.clone()).is_err());
        verify_no_result(certificate).map_err(refusal)?;
        return Ok("{\"kind\":\"no-result\"}".to_owned());
    }
    assert!(verify_no_result(certificate.clone()).is_err());
    let mut collector = ReleaseCollector::new(certificate.clone()).map_err(refusal)?;
    let mut shares = Vec::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    for position in 0..count {
        let context = Arc::new(
            ReleaseContext::new(
                certificate.clone(),
                position,
                read_operand(&target, aggregate, 44 + 3 * position, work)?,
                read_operand(&target, aggregate, 45 + 3 * position, work)?,
            )
            .map_err(refusal)?,
        );
        let packet = bounded(
            directory.join(format!("release-envelope-{position}.bin")),
            RELEASE_ENVELOPE_BYTES + 3309,
            work,
        )?;
        let authentication = context.authenticate(&packet).map_err(refusal)?;
        let mut wrong = packet.clone();
        wrong[132] ^= 1;
        assert!(context.authenticate(&wrong).is_err());
        let mut file = File::open(directory.join(format!("release-{position}.bin")))?;
        if file.metadata()?.len() != authentication.envelope().body_length() as u64 {
            return Err(refusal("published release body length differs"));
        }
        let mut header = [0; RELEASE_BODY_HEADER_BYTES];
        work.read(&mut file, &mut header)?;
        let mut verifier = ReleaseBodyVerifier::new(context.clone(), &header).map_err(refusal)?;
        let mut hostile = if position == 0 {
            let incomplete = ReleaseBodyVerifier::new(context.clone(), &header).map_err(refusal)?;
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
        let share = Arc::new(
            verifier
                .finish()
                .map_err(refusal)?
                .authenticate(authentication)
                .map_err(refusal)?,
        );
        assert!(collector.insert(share.clone()).map_err(refusal)?);
        assert!(!collector.insert(share.clone()).map_err(refusal)?);
        shares.push(share);
        if position < 3 {
            assert!(collector.result().is_err());
        }
    }
    let result = collector.result().map_err(refusal)?;
    // The independent process has only public files. Exercise a later retriever
    // using four survivors after the original generator and author are absent.
    let mut survivors = ReleaseCollector::new(certificate).map_err(refusal)?;
    for position in [6, 7, 8, 9] {
        survivors
            .insert(shares[position].clone())
            .map_err(refusal)?;
    }
    assert_eq!(
        survivors.result().map_err(refusal)?.identifiers(),
        result.identifiers()
    );
    Ok(format!(
        "{{\"kind\":\"result\",\"identifiers\":{:?},\"releaseAuthors\":{},\"survivingAuthors\":[6,7,8,9]}}",
        result.identifiers(),
        shares.len()
    ))
}
