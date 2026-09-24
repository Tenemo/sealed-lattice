use evaluation_target::program::{Error, RankingProgram};
use std::{fs, path::PathBuf, time::Instant};

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(
        arguments.len(),
        2,
        "Supply the reference program and new output file."
    );
    let reference = fs::read(&arguments[0]).expect("read the previously measured public program");
    let started = Instant::now();
    let program = RankingProgram::for_profile(10, 10, 10).expect("supported exact construction");
    assert_eq!(program.bytes(), reference);
    let mut refusals = 0;
    for participants in 3..=20 {
        for options in 2..=20 {
            for top_count in 1..=options {
                if (participants, options) == (10, 10) {
                    let selected = RankingProgram::for_profile(participants, options, top_count)
                        .expect("supported requested result length");
                    assert_eq!(selected.bytes().len(), reference.len());
                    assert!(
                        rns_arithmetic_probe::ranking::Engine::new(
                            selected.bytes(),
                            *selected.identity()
                        )
                        .is_ok()
                    );
                    continue;
                }
                assert!(matches!(
                    RankingProgram::for_profile(participants, options, top_count),
                    Err(Error::UnsupportedProfile)
                ));
                refusals += 1;
            }
        }
    }
    let output = PathBuf::from(&arguments[1]);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .expect("new program output");
    std::io::Write::write_all(&mut file, program.bytes()).expect("write public program");
    file.sync_all().expect("sync public program");
    println!(
        "{{\"programBytes\":{},\"profileRefusals\":{},\"milliseconds\":{},\"identity\":\"{}\"}}",
        program.bytes().len(),
        refusals,
        started.elapsed().as_secs_f64() * 1000.0,
        program
            .identity()
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>()
    );
}
