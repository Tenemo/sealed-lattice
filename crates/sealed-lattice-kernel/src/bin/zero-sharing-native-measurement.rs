fn main() {
    match sealed_lattice_kernel::run_completion_zero_sharing_native_measurement_json() {
        Ok(result) => println!("{result}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
