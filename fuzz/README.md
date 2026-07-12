# Foundation parser fuzzing

The `foundation-schema-object` target drives the public byte-oriented kernel
command boundary with both raw hostile bytes and mutations of representative
valid canonical objects. A panic, sanitizer finding, or process abort is a
failure; ordinary typed refusal responses are expected.

`cargo-fuzz` requires a nightly Rust toolchain, LLVM sanitizer support, and a
C++ compiler on a supported Unix-like host. Run the canonical root command for
a bounded 60-second campaign:

```bash
pnpm run test:fuzz:foundation-schema-object
```

Pass one positive duration in seconds for a longer manual campaign, for example
`pnpm run test:fuzz:foundation-schema-object -- 3600`.

Retain minimized reproductions as reviewed regression vectors. A deterministic
mutation unit test or a successful build of this target is not a substitute for
a recorded coverage-guided campaign.
