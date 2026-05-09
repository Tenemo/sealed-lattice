use sealed_lattice_kernel::{TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION, fixtures, verifier};

fn main() {
    if std::env::args().any(|argument| argument == "--emit-transcript-core-fixtures") {
        let fixtures = fixtures::canonical_fixture_set()
            .expect("canonical transcript-core fixtures should build");
        println!(
            "{}",
            serde_json::to_string_pretty(&fixtures)
                .expect("canonical transcript-core fixtures should serialize")
        );
        return;
    }

    println!(
        "sealed-lattice kernel verifier future implementation ({TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION})"
    );
    println!("{}", verifier::future_implementation_summary());
}
