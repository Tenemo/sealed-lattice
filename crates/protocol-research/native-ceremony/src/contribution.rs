use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use registration_credentials::{
    contribution_commitment::{
        ComputedContributionCommitment, ContributionCommitmentHasher, body_header,
    },
    roster_authentication::OrganizerSignedRoster,
};
use setup_aggregate::ModulusKind;
use setup_witness::{
    PolynomialOutput,
    contribution::{Contribution, common_polynomial, statement_header},
};
use stateful_sha3::{Digest, Sha3_512};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use word_proof::{bridge::Prover, transcript};

struct PublicOutput {
    directory: PathBuf,
    next: usize,
    hash: Sha3_512,
    context: Sha3_512,
}
impl PolynomialOutput for PublicOutput {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        assert!(self.next < 75);
        let expected = if self.next < 42 {
            (65536, 108)
        } else if self.next < 73 {
            (65536, 20)
        } else {
            (4096, 5)
        };
        assert_eq!((values.len(), width), expected);
        let half = modulus >> 1usize;
        let mut file = ModulusKind::for_contribution_polynomial(self.next).map(|_| {
            crate::public_output::PublicOutput::create(
                self.directory
                    .join(format!("polynomial-{:02}.bin", self.next)),
            )
            .unwrap()
        });
        let mut buffer = Vec::with_capacity(1 << 20);
        for value in values {
            assert!(value.abs() <= half);
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            let mut bytes = [0u8; 109];
            bytes[0] = u8::from(sign == Sign::Minus);
            bytes[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            buffer.extend(&bytes[..width + 1]);
            if buffer.len() + width + 1 > 1 << 20 {
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
fn polynomial_bytes(roster: &OrganizerSignedRoster, directory: &Path, index: usize) -> Vec<u8> {
    if ModulusKind::for_contribution_polynomial(index).is_some() {
        return std::fs::read(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
    }
    if (43..73).contains(&index) {
        return roster.proposal().records()[(index - 43) / 3]
            .public_key()
            .to_vec();
    }
    public_bytes(
        &common_polynomial(index).unwrap(),
        if index < 42 {
            108
        } else if index == 42 {
            20
        } else {
            5
        },
    )
}
pub fn generate(
    roster: &OrganizerSignedRoster,
    position: usize,
    directory: &Path,
    salt: &[u8; 64],
) -> (ComputedContributionCommitment, Vec<u8>) {
    std::fs::create_dir(directory).unwrap();
    let role = roster.proposal().contribution_role(position).unwrap();
    let header = statement_header();
    let mut output = PublicOutput {
        directory: directory.to_owned(),
        next: 0,
        hash: Sha3_512::new(),
        context: transcript::context_hasher(&role),
    };
    output.hash.update(&header);
    output.context.update(&header);
    let mut generator = Contribution::new();
    for gadget in 0..6 {
        generator.gadget(gadget, &mut output).unwrap();
    }
    generator.begin_shares(&mut output).unwrap();
    for (recipient, record) in roster.proposal().records().iter().enumerate() {
        let values = record
            .public_key()
            .chunks_exact(21)
            .map(|bytes| {
                let magnitude = BigInt::from_bytes_le(Sign::Plus, &bytes[1..]);
                if bytes[0] == 1 { -magnitude } else { magnitude }
            })
            .collect::<Vec<_>>();
        generator.share(recipient, &values, &mut output).unwrap();
    }
    generator.finish(&mut output).unwrap();
    assert_eq!(output.next, 75);
    let witness = generator.into_witness().unwrap();
    let mut prover = Prover::from_generated(
        &role,
        output.hash.finalize().into(),
        output.context.finalize().into(),
        header,
        witness.into_columns(),
    )
    .unwrap();
    let mut unused = Vec::new();
    loop {
        match prover.phase_code() {
            3..=6 | 8..=9 => prover.advance(7, 0, &[], &mut unused).unwrap(),
            7 => {
                for index in 0..75 {
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
    let body_header = body_header(std::fs::metadata(&proof_path).unwrap().len() as usize).unwrap();
    let mut hash =
        ContributionCommitmentHasher::new(roster.proposal(), position, salt, &body_header).unwrap();
    let mut buffer = vec![0; 1 << 20];
    while let Some((index, _)) = hash.next_polynomial() {
        let mut file = File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            hash.push_polynomial(index, offset, &buffer[..length])
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
        hash.push_proof(offset, &buffer[..length]).unwrap();
        offset += length;
    }
    (hash.finish().unwrap(), body_header.to_vec())
}
