use rns_arithmetic_probe::ranking::requested_output_probe;
use std::{fs, io, io::Write, path::PathBuf, time::Instant};

fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 1 {
        return Err(io::Error::other("Supply a new numerical output directory."));
    }
    let directory = PathBuf::from(&arguments[0]);
    fs::create_dir(&directory)?;
    let mut cases = Vec::new();
    for top_count in [10, 3] {
        let started = Instant::now();
        let result = requested_output_probe(top_count)
            .map_err(|error| io::Error::other(format!("Encrypted prefix refused: {error:?}")))?;
        cases.push(format!(
            "{{\"milliseconds\":{},\"result\":{result}}}",
            started.elapsed().as_secs_f64() * 1000.0
        ));
    }
    let report = format!(
        "{{\"kind\":\"requested-output\",\"cases\":[{}]}}",
        cases.join(",")
    );
    if report.len() > 16_384 {
        return Err(io::Error::other("Numerical report exceeds its bound."));
    }
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("result.json"))?;
    output.write_all(report.as_bytes())?;
    output.sync_all()?;
    println!("{report}");
    Ok(())
}
