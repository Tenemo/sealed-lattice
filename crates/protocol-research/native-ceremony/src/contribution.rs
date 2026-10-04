use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use parallel_work::ProtocolHash;
use registration_credentials::roster_authentication::OrganizerSignedRoster;
use registration_enrollment::{Enrollment, contribution_signing::ContributionSigning};
use setup_aggregate::contribution_family;
use setup_witness::{
    PolynomialOutput,
    contribution::{Contribution, common_polynomial},
};

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use supported_profile::{Profile, relation::setup_relation};
use word_proof::{bridge::Prover, transcript};

struct PublicOutput {
    profile: Profile,
    directory: PathBuf,
    next: usize,
    hash: ProtocolHash,
    context: ProtocolHash,
}
impl PolynomialOutput for PublicOutput {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        let family = self.profile.setup_family(self.next).unwrap();
        assert_eq!(
            (values.len(), width),
            (
                self.profile.family_degree(family),
                self.profile.family_magnitude_bytes(family)
            )
        );
        let half = modulus >> 1usize;
        // Only contribution body polynomials are published; the others are
        // recomputed common polynomials and roster keys.
        let mut file = contribution_family(self.profile, self.next).map(|_| {
            crate::public_output::PublicOutput::create(
                self.directory
                    .join(format!("polynomial-{:02}.bin", self.next)),
            )
            .unwrap()
        });
        let mut buffer = Vec::with_capacity(1 << 20);
        let mut encoded = vec![0u8; 1 + width];
        for value in values {
            assert!(value.abs() <= half);
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            encoded.fill(0);
            encoded[0] = u8::from(sign == Sign::Minus);
            encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            buffer.extend(&encoded);
            if buffer.len() + encoded.len() > 1 << 20 {
                self.hash.update(&buffer);
                self.context.update(&buffer);
                if let Some(file) = file.as_mut() {
                    file.write_all(&buffer).unwrap();
                }
                buffer.clear();
            }
        }
        if !buffer.is_empty() {
            self.hash.update(&buffer);
            self.context.update(&buffer);
            if let Some(file) = file.as_mut() {
                file.write_all(&buffer).unwrap();
            }
        }
        if let Some(file) = file {
            file.finish().unwrap();
        }
        self.next += 1;
    }
}
fn public_bytes(values: &[BigInt], width: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(values.len() * (width + 1));
    for value in values {
        let (sign, magnitude) = value.to_bytes_le();
        assert!(magnitude.len() <= width);
        output.push(u8::from(sign == Sign::Minus));
        output.extend(&magnitude);
        output.resize(output.len() + width - magnitude.len(), 0);
    }
    output
}
/// A setup statement polynomial: a published body polynomial, a roster
/// member's registration key or a recomputed common polynomial.
fn polynomial_bytes(roster: &OrganizerSignedRoster, directory: &Path, index: usize) -> Vec<u8> {
    let profile = roster.proposal().profile();
    if contribution_family(profile, index).is_some() {
        return std::fs::read(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
    }
    let records = roster.proposal().records();
    if let Some(recipient) =
        (0..records.len()).find(|recipient| profile.recipient_key_polynomial(*recipient) == index)
    {
        return records[recipient].public_key().to_vec();
    }
    let family = profile.setup_family(index).unwrap();
    public_bytes(
        &common_polynomial(profile, index).unwrap(),
        profile.family_magnitude_bytes(family),
    )
}
pub fn generate(
    roster: &Arc<OrganizerSignedRoster>,
    enrollment: &mut Enrollment,
    position: usize,
    directory: &Path,
    salt: &[u8; 64],
) -> (ContributionSigning, Vec<u8>) {
    std::fs::create_dir(directory).unwrap();
    let profile = roster.proposal().profile();
    let role = roster.proposal().contribution_role(position).unwrap();
    let header = profile.setup_statement_header();
    let mut output = PublicOutput {
        profile,
        directory: directory.to_owned(),
        next: 0,
        hash: ProtocolHash::new(),
        context: transcript::context_hasher(&setup_relation(profile), &role),
    };
    output.hash.update(&header);
    output.context.update(&header);
    let source = enrollment.contribution_source(profile).unwrap();
    let mut generator = Contribution::from_source(profile, source).unwrap();
    for gadget in 0..profile.gadget_length() {
        generator.gadget(gadget, &mut output).unwrap();
    }
    generator.begin_shares(&mut output).unwrap();
    let width = 1 + supported_profile::share_modulus().len();
    for (recipient, record) in roster.proposal().records().iter().enumerate() {
        let values = record
            .public_key()
            .chunks_exact(width)
            .map(|bytes| {
                let magnitude = BigInt::from_bytes_le(Sign::Plus, &bytes[1..]);
                if bytes[0] == 1 { -magnitude } else { magnitude }
            })
            .collect::<Vec<_>>();
        generator.share(recipient, &values, &mut output).unwrap();
    }
    generator.finish(&mut output).unwrap();
    assert_eq!(output.next, profile.setup_polynomials());
    let columns = generator.into_columns().unwrap();
    let mut prover = Prover::from_generated(
        profile,
        &role,
        output.hash.finalize(),
        output.context.finalize(),
        header,
        columns,
    )
    .unwrap();
    let mut unused = Vec::new();
    loop {
        match prover.phase_code() {
            3..=6 | 8..=9 => prover.advance(7, 0, &[], &mut unused).unwrap(),
            7 => {
                for index in 0..profile.setup_polynomials() {
                    prover.advance(8, index, &[], &mut unused).unwrap();
                    let bytes = polynomial_bytes(roster, directory, index);
                    for chunk in bytes.chunks(1 << 20) {
                        prover.advance(9, 0, chunk, &mut unused).unwrap();
                    }
                    prover.advance(10, 0, &[], &mut unused).unwrap();
                }
            }
            10 => break,
            phase => panic!("Unexpected setup proof phase {phase}"),
        }
    }
    let proof_path = directory.join("proof.bin");
    let mut file = crate::public_output::PublicOutput::create(&proof_path).unwrap();
    while prover.phase_code() != 11 {
        let mut bytes = Vec::new();
        prover.advance(11, 0, &[], &mut bytes).unwrap();
        assert!(bytes.len() <= 1 << 20);
        file.write_all(&bytes).unwrap();
    }
    file.finish().unwrap();
    drop(prover);
    let body_header = enrollment
        .contribution_header(
            profile,
            std::fs::metadata(&proof_path).unwrap().len() as usize,
        )
        .unwrap();
    let mut signing = ContributionSigning::default();
    signing
        .begin_body(
            &enrollment.credential,
            roster.clone(),
            position,
            salt,
            &body_header,
        )
        .unwrap();
    let mut buffer = vec![0; 1 << 20];
    for index in profile.contribution_body_polynomials() {
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
    let commitment = *signing.commitment().unwrap();
    signing
        .sign_confirmation(
            &mut enrollment.credential,
            &commitment,
            *crate::random::<32>(),
        )
        .unwrap();
    (signing, body_header.to_vec())
}
