use linked_release_proof::{CHUNK_LIMIT, HEADER_LENGTH, Verifier};
use sha3::{Digest, Sha3_512};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(1..=2).contains(&arguments.len()) {
        return Err(io::Error::other(
            "Supply a public statement/proof directory and optional public role file.",
        ));
    }
    let directory = PathBuf::from(&arguments[0]);
    let role = if let Some(file) = arguments.get(1) {
        let mut bytes = Vec::new();
        File::open(file)?.take(1025).read_to_end(&mut bytes)?;
        if !(1..=1024).contains(&bytes.len()) {
            return Err(io::Error::other("Public proof role length differs."));
        }
        bytes
    } else {
        b"sealed-lattice/linked-release-workload/1".to_vec()
    };
    let mut statement = File::open(directory.join("statement.bin"))?;
    if statement.metadata()?.len() != linked_release_proof::parameters::STATEMENT_BYTES as u64 {
        return Err(io::Error::other("Statement length differs."));
    }
    let mut hash = Sha3_512::new();
    let mut buffer = vec![0; CHUNK_LIMIT];
    loop {
        let count = statement.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let mut proof = File::open(directory.join("proof.bin"))?;
    if proof.metadata()?.len() > linked_release_proof::parameters::MAXIMUM_PROOF_BYTES as u64 {
        return Err(io::Error::other("Proof exceeds its bound."));
    }
    let mut header = vec![0; HEADER_LENGTH];
    proof.read_exact(&mut header)?;
    let mut verifier = Verifier::new(&role, hash.finalize().into(), &header)
        .map_err(|_| io::Error::other("Proof header refused."))?;
    let mut statement = File::open(directory.join("statement.bin"))?;
    loop {
        let count = statement.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        verifier
            .push_statement(&buffer[..count])
            .map_err(|_| io::Error::other("Statement refused."))?;
    }
    verifier
        .finish_statement()
        .map_err(|_| io::Error::other("Statement completion refused."))?;
    loop {
        let count = proof.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        verifier
            .push_proof(&buffer[..count])
            .map_err(|_| io::Error::other("Proof refused."))?;
    }
    if !verifier.finish() {
        return Err(io::Error::other("Numeric release relation refused."));
    }
    println!("Verified the numeric linked-release relation");
    Ok(())
}
