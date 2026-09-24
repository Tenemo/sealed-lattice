#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use num_bigint::Sign;
    use setup_witness::contribution::{common_polynomial, statement_header};
    use std::{fs::OpenOptions, io::Write, path::PathBuf};
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(
        arguments.len(),
        1,
        "Supply the public input output directory."
    );
    let directory = PathBuf::from(&arguments[0]);
    std::fs::create_dir(&directory).unwrap();
    let write = |name: &str| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .unwrap()
    };
    write("expected-header.bin")
        .write_all(&statement_header())
        .unwrap();
    let indices = (0..6)
        .flat_map(|gadget| [7 * gadget, 7 * gadget + 3, 7 * gadget + 5])
        .chain([42, 73]);
    for index in indices {
        let width = if index < 42 {
            108
        } else if index == 42 {
            20
        } else {
            5
        };
        let values = common_polynomial(index).unwrap();
        let mut file = write(&format!("polynomial-{index:02}.bin"));
        let mut buffer = Vec::with_capacity(1 << 20);
        for value in values {
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            let mut bytes = [0; 109];
            bytes[0] = u8::from(sign == Sign::Minus);
            bytes[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            for part in bytes[..width + 1].chunks(1 << 20) {
                if buffer.len() + part.len() > 1 << 20 {
                    file.write_all(&buffer).unwrap();
                    buffer.clear();
                }
                buffer.extend(part);
            }
        }
        file.write_all(&buffer).unwrap();
    }
    println!("{}", directory.display());
}
