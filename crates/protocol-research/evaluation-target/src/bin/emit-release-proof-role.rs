use evaluation_target::release::encode_release_proof_role;
use std::{
    fs::OpenOptions,
    io::{self, Write},
};

fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 1 {
        return Err(io::Error::other(
            "Supply the synthetic public role output file.",
        ));
    }
    // Public fixture identities exercise the real encoder without claiming
    // that this numerical workload possesses a certificate or participant.
    let role = encode_release_proof_role([1; 64], [2; 64], [3; 64], [4; 64], 0)
        .map_err(|_| io::Error::other("Synthetic public role refused."))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments[0])?;
    output.write_all(&role)?;
    println!("{}", role.len());
    Ok(())
}
