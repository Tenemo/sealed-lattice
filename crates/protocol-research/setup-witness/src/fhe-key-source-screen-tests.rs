use super::*;
#[test]
fn out_of_order_controls_preserve_the_unstarted_source_stage() {
    let mut screen = Screen::new();
    assert!(screen.next_output().is_err());
    assert!(screen.acknowledge_output().is_err());
    assert_eq!(screen.phase(), 1);
    assert!(screen.output().is_empty());
    assert!(screen.source.is_none());
}
