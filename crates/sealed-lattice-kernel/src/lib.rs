#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_placeholder_value() -> u32 {
    7
}

#[cfg(test)]
mod tests {
    use super::sealed_lattice_placeholder_value;

    #[test]
    fn returns_the_expected_placeholder_value() {
        assert_eq!(sealed_lattice_placeholder_value(), 7);
    }
}
