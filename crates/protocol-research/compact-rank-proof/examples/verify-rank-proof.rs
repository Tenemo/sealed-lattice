use std::{
    error::Error,
    io::{self, Read},
    process::ExitCode,
};

fn run() -> Result<(), Box<dyn Error>> {
    if std::env::args().len() != 1 {
        return Err("The screen reads one framed fixture from stdin".into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(parallel_work::MAXIMUM_JOB_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    match compact_rank_proof::screen::verify_framed(&bytes) {
        Ok(()) => println!("{{\"accepted\":true}}"),
        Err(error) => println!("{{\"accepted\":false,\"refusal\":\"{error:?}\"}}"),
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
