use std::{env, fs};

fn main() {
    let path = env::args()
        .nth(1)
        .expect("a command JSON file path is required");
    let input = fs::read(path).expect("command JSON should read");
    let output = sealed_lattice_kernel::run_transcript_core_command(&input);
    println!("{}", String::from_utf8_lossy(&output));
}
