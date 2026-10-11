use super::*;
#[test]
fn incomplete_commands_refuse_before_output_or_private_work() {
    for values in [
        vec![],
        vec!["unused.bin", "extra"],
        vec!["unused.bin", "--guard-start", "start"],
    ] {
        assert!(arguments(values.into_iter().map(OsString::from).collect()).is_err());
    }
}
