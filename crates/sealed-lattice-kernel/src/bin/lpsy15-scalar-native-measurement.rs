fn main() {
    match sealed_lattice_kernel::run_lpsy15_scalar_native_measurement_json() {
        Ok(result) => println!("{result}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
