# Foundation parser fuzzing

The `foundation-schema-object` target drives the public byte-oriented kernel
command boundary with both raw hostile bytes and mutations of representative
valid canonical objects. A panic, sanitizer finding, or process abort is a
failure; ordinary typed refusal responses are expected.

This lane requires the exact `nightly-2026-06-15` Rust toolchain,
`cargo-fuzz 0.13.2`, LLVM sanitizer support, and a C++ compiler on a supported
Unix-like host. Tool installation is deliberately manual:

```bash
rustup toolchain install nightly-2026-06-15 --profile minimal
cargo +nightly-2026-06-15 install cargo-fuzz --version 0.13.2 --locked
```

The runner refuses a missing or different tool version and verifies the nested
fuzz workspace through its committed lockfile before starting. Run the
canonical root command for a bounded 60-second campaign:

```bash
pnpm run test:fuzz:foundation-schema-object
```

Pass one positive duration in seconds for a longer manual campaign, for example
`pnpm run test:fuzz:foundation-schema-object -- 3600`.

Each campaign creates a run directory under `logs/` before checking the pinned
toolchain. Its basename begins with the full Windows-safe UTC ISO timestamp so
ordinary filename sorting is chronological. It records preflight failures,
elapsed campaign time, the latest execution, coverage, corpus, and throughput
counters reported by LibFuzzer, and the complete command output. The campaign
start record includes the source artifact directory and reproduction-command
template, so an abrupt failure still points to LibFuzzer's output. A newly
created crash, timeout, leak, or out-of-memory reproducer is copied into that
run's `attachments/fuzz/` directory with its SHA-256 digest and exact
reproduction command.

Retain minimized reproductions as reviewed regression vectors. A deterministic
mutation unit test or a successful build of this target is not a substitute for
a recorded coverage-guided campaign.
