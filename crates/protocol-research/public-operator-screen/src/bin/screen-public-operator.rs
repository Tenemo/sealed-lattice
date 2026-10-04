use public_operator_screen::{Case, Screen};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Arguments {
    case: Case,
    output: PathBuf,
    gates: Option<(PathBuf, PathBuf)>,
}
fn absent_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("Expected a file path"))?;
    let resolved = parent.canonicalize()?.join(name);
    match fs::symlink_metadata(&resolved) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(resolved),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("Output or guard gate already exists")),
    }
}
fn arguments(arguments: Vec<OsString>) -> io::Result<Arguments> {
    if arguments.len() != 2 && arguments.len() != 6 {
        return Err(io::Error::other(
            "Usage: screen-public-operator <0|1> <new-report-path> [--guard-start <path> --guard-finish <path>]",
        ));
    }
    let case = match arguments[0].to_str() {
        Some("0") => Case::Seed,
        Some("1") => Case::Opening,
        _ => return Err(io::Error::other("Unknown operator case")),
    };
    let output = absent_path(Path::new(&arguments[1]))?;
    let gates = if arguments.len() == 6 {
        if arguments[2] != "--guard-start" || arguments[4] != "--guard-finish" {
            return Err(io::Error::other("Expected paired guard gates"));
        }
        let start = absent_path(Path::new(&arguments[3]))?;
        let finish = absent_path(Path::new(&arguments[5]))?;
        let same = |left: &Path, right: &Path| {
            left == right
                || (cfg!(windows)
                    && left
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&right.to_string_lossy()))
        };
        if same(&start, &finish) || same(&output, &start) || same(&output, &finish) {
            return Err(io::Error::other("Output and guard paths must be distinct"));
        }
        Some((start, finish))
    } else {
        None
    };
    Ok(Arguments {
        case,
        output,
        gates,
    })
}
fn wait_gate(path: &Path) -> io::Result<()> {
    let started = Instant::now();
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => return Ok(()),
            Ok(_) => return Err(io::Error::other("Guard gate must be an empty regular file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if started.elapsed() >= Duration::from_secs(60) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Guard gate timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    println!("{{\"event\":\"native-operator-ready\"}}");
    io::stdout().flush()?;
    if let Some((start, _)) = &arguments.gates {
        wait_gate(start)?;
    }
    let started = Instant::now();
    let call = Instant::now();
    let mut screen = Screen::new(arguments.case)?;
    println!(
        "{{\"event\":\"operator-call\",\"operation\":\"begin\",\"phase\":0,\"milliseconds\":{}}}",
        call.elapsed().as_secs_f64() * 1000.0
    );
    let mut output = File::create_new(&arguments.output)?;
    let mut bytes = 0;
    while screen.phase() != 13 {
        let phase = screen.phase();
        let operation = if phase == 12 { "next_output" } else { "step" };
        let call = Instant::now();
        if phase == 12 {
            screen.next_output()?;
        } else {
            screen.step()?;
        }
        println!(
            "{{\"event\":\"operator-call\",\"operation\":\"{operation}\",\"phase\":{phase},\"milliseconds\":{}}}",
            call.elapsed().as_secs_f64() * 1000.0
        );
        if !screen.output().is_empty() {
            let call = Instant::now();
            output.write_all(screen.output())?;
            output.flush()?;
            bytes += screen.output().len();
            println!(
                "{{\"event\":\"operator-call\",\"operation\":\"write_output\",\"phase\":12,\"milliseconds\":{}}}",
                call.elapsed().as_secs_f64() * 1000.0
            );
            let call = Instant::now();
            screen.acknowledge_output()?;
            println!(
                "{{\"event\":\"operator-call\",\"operation\":\"ack_output\",\"phase\":12,\"milliseconds\":{}}}",
                call.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
    output.sync_all()?;
    let milliseconds = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{{\"event\":\"native-operator-completed\",\"operationMilliseconds\":{milliseconds}}}"
    );
    io::stdout().flush()?;
    if let Some((_, finish)) = &arguments.gates {
        wait_gate(finish)?;
    }
    println!(
        "{{\"kind\":\"public-operator-screen\",\"case\":\"{}\",\"reportBytes\":{bytes}}}",
        arguments.case.name()
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(arguments(std::env::args_os().skip(1).collect())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_commands_do_not_create_output_or_start_computation() {
        for values in [
            vec![],
            vec!["0"],
            vec!["2", "unused.bin"],
            vec!["0", "unused.bin", "--guard-start"],
        ] {
            assert!(arguments(values.into_iter().map(OsString::from).collect()).is_err());
        }
    }
}
