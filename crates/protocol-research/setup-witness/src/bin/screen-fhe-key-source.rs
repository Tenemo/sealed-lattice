use setup_witness::fhe_key_source_screen::Screen;
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Arguments {
    output: PathBuf,
    gates: Option<(PathBuf, PathBuf)>,
}
fn absent_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
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
    if arguments.len() != 1 && arguments.len() != 5 {
        return Err(io::Error::other(
            "Usage: screen-fhe-key-source <new-report-path> [--guard-start <path> --guard-finish <path>]",
        ));
    }
    let output = absent_path(Path::new(&arguments[0]))?;
    let gates = if arguments.len() == 5 {
        if arguments[1] != "--guard-start" || arguments[3] != "--guard-finish" {
            return Err(io::Error::other("Expected paired guard gates"));
        }
        let start = absent_path(Path::new(&arguments[2]))?;
        let finish = absent_path(Path::new(&arguments[4]))?;
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
    Ok(Arguments { output, gates })
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
                "Native operation guard did not acknowledge",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments(std::env::args_os().skip(1).collect())?;
    if let Some((start, _)) = &arguments.gates {
        println!("{{\"event\":\"native-operator-ready\"}}");
        io::stdout().flush()?;
        wait_gate(start)?;
    }
    let started = Instant::now();
    let mut screen = Screen::new();
    let mut output = File::create_new(&arguments.output)?;
    let mut bytes = 0;
    while screen.phase() != 13 {
        let phase = screen.phase();
        let call = Instant::now();
        if phase == 12 {
            screen.next_output()?;
            if !screen.output().is_empty() {
                output.write_all(screen.output())?;
                output.flush()?;
                bytes += screen.output().len();
                screen.acknowledge_output()?;
            }
        } else {
            screen.step()?;
        }
        println!(
            "{{\"event\":\"operator-call\",\"operation\":\"{}\",\"phase\":{phase},\"milliseconds\":{}}}",
            if phase == 12 { "output" } else { "step" },
            call.elapsed().as_secs_f64() * 1000.0
        );
    }
    output.sync_all()?;
    println!(
        "{{\"event\":\"native-operator-completed\",\"operationMilliseconds\":{}}}",
        started.elapsed().as_secs_f64() * 1000.0
    );
    io::stdout().flush()?;
    if let Some((_, finish)) = &arguments.gates {
        wait_gate(finish)?;
    }
    println!("{{\"kind\":\"fhe-key-source-screen\",\"reportBytes\":{bytes}}}");
    Ok(())
}

#[cfg(test)]
#[path = "screen-fhe-key-source-tests.rs"]
mod tests;
