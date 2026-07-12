# Foundation parser fuzzing

The `foundation-schema-object` target drives the public byte-oriented kernel
command boundary with both raw hostile bytes and mutations of representative
valid canonical objects. A panic, sanitizer finding, or process abort is a
failure; ordinary typed refusal responses are expected.

`cargo-fuzz` requires a nightly Rust toolchain, LLVM sanitizer support, and a
C++ compiler on a supported Unix-like host. Run the target from this directory:

```bash
cargo +nightly fuzz run foundation-schema-object
```

Retain minimized reproductions as reviewed regression vectors. A deterministic
mutation unit test or a successful build of this target is not a substitute for
a recorded coverage-guided campaign.
