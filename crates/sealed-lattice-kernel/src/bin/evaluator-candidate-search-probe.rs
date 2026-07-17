fn main() {
    let axis = std::env::args()
        .nth(1)
        .expect("probe axis argument is required");
    println!(
        "{}",
        sealed_lattice_kernel::evaluator_candidate_search_probe(&axis)
    );
}
