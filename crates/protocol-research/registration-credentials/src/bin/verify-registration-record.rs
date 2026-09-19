use registration_credentials::{poll::verify_poll, registration::RegistrationVerifier};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

fn bounded(path: impl AsRef<Path>, maximum: usize) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    if fs::metadata(path)?.len() > maximum as u64 {
        return Err(io::Error::other("Public record exceeds its bound"));
    }
    fs::read(path)
}
fn failure(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("Registration verification refused: {error:?}"))
}
fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err(io::Error::other(
            "Supply the public record directory, expected context and optional poll directory",
        ));
    }
    let directory = Path::new(&arguments[0]);
    let poll_directory = arguments.get(2).map_or(directory, |value| Path::new(value));
    let context = bounded(&arguments[1], 128)?;
    if context.len() != 128 {
        return Err(io::Error::other("Wrong public context length"));
    }
    let poll = verify_poll(
        context[..64].try_into().unwrap(),
        context[64..].try_into().unwrap(),
        &bounded(poll_directory.join("poll-definition.bin"), 1 << 20)?,
        &bounded(poll_directory.join("poll-signature.bin"), 3309)?,
    )
    .map_err(failure)?;
    let mut verifier = RegistrationVerifier::new(
        &poll,
        &bounded(directory.join("registration-header.bin"), 4096)?,
        &bounded(directory.join("signature.bin"), 3309)?,
    )
    .map_err(failure)?;
    let mut buffer = vec![0; 1 << 20];
    for (name, key) in [("polynomial-01.bin", true), ("proof.bin", false)] {
        let mut file = File::open(directory.join(name))?;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if key {
                verifier.push_key(&buffer[..count])
            } else {
                verifier.push_proof(&buffer[..count])
            }
            .map_err(failure)?;
        }
        if key {
            verifier.finish_key().map_err(failure)?;
        }
    }
    verifier.finish().map_err(failure)?;
    println!("true");
    Ok(())
}
