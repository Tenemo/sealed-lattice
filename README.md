# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly research prototype for fixed-roster threshold homomorphic polling. It explores how a small group can verify a public poll transcript and release an agreed result without revealing individual scores or trusting a tally server.

The project is for synthetic data only. It has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the current [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` owns cryptographic objects, protocol verification, and the participant-side workflow. A separate host application, currently planned as `sealed-vote`, owns identity vetting, enrollment, reusable invitations, organizer workflow, interface copy, notifications, and visit cadence.

The host designates exactly one organizer, who must be a member of the frozen roster. The organizer is otherwise an ordinary roster participant and eligible voter. They may submit no ballot or the same kind of ballot as anyone else, including an all-ones ballot. The organizer designation is not sent to or verified by `sealed-lattice` and grants no special key, proof bypass, quorum weight, finality power, or decryption authority.

## How it works

The intended ceremony is:

1. The host supplies a poll definition and an externally vetted, public, frozen roster.
2. Every roster participant contributes to collective setup and verifies the resulting public and private setup material in their own browser.
3. Any roster participant may submit one ballot or none. A submitted ballot contains one score from `1` through `10` for every option. There is no cryptographic skip value; a host interface may map an omitted score to `1`.
4. Participant clients verify the submitted ballots and derive a canonical aggregate from a nonempty selected subset. If nobody submits a usable ballot, there is no aggregate or result.
5. Clients replay the bounded homomorphic evaluator over that aggregate.
6. Available roster participants establish finality for exactly one result target and release target-bound decryption shares. The organizer cannot select a privileged helper group.
7. Any valid reconstruction threshold reveals only the approved result.

The only permitted public result is the ordered list of the selected `topCount` option identifiers, or the complete ordering when all options are selected. Exact sums, margins, individual scores, aggregate shares, comparison bits, selection bits, ranks, and evaluator intermediates are not public outputs.

The protocol provides ballot secrecy, not voter anonymity. The frozen roster and accepted ballot authorship are public.

No phase requires simultaneous presence. The protocol must support a schedule in which one participant at a time opens the application, verifies all available data, performs every authorized action, publishes signed messages, and leaves. If too few participants return, the ceremony waits or remains unresolved; it never lowers a threshold or uses an unsafe fallback.

## Supported scope

Schemas, formulas, validators, and deterministic compilers cover:

- `3 <= n <= 20` frozen roster participants;
- `2 <= optionCount <= 20` ordered options;
- scores in `1..10`; and
- `1 <= topCount <= optionCount`.

The sole cryptographic-completion, integration, performance, and supported-phone evidence target is currently `n = 10`, `optionCount = 10`. Other admitted sizes are not qualified.

The active cryptographic target is an **80-bit reduced-assurance mobile research prototype**. Every load-bearing cryptographic component and the composed protocol must meet a minimum 80-bit post-quantum security level under the stated models and assumptions. The implementation has not yet established that target end to end, and the target is not a production rating or certification.

Every participant-facing setup, proof, verification, aggregation, evaluation, finality, and release operation must retain a scalar-capable mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. They never prove, verify, tally, finalize, or decrypt.

The sole browser qualification target is Chrome on the selected physical phone for the exact frozen build. Desktop Chromium, Node.js, native Rust, and emulated devices provide development evidence only.

## Current status

The complete ceremony is not implemented or certified.

- **Foundation and public SDK:** Canonical poll validation, manifest construction, foundation decoding, typed bindings, and reproducible Rust/WebAssembly package bytes exist. Downstream ceremony capabilities remain incomplete and are not yet public APIs.
- **Proof system:** One reference development prototype for the collective public-key proof passes canonical decoding and full algebraic verification. Native evidence independently reconstructs its public inputs, refuses a false statement, restores an authenticated checkpoint in a separate process, and reconstructs the complete compiler-derived direct SHAKE256 verifier-message graph. A guarded Node.js development run also generates one canonical proof through the scalar release WebAssembly artifact and has a fresh scalar instance accept the same proof and public-input bytes; malformed framing refuses. This covers one proof family only and is not browser, lifecycle, source-correspondence, or phone evidence. It does not establish a concrete SHAKE or complete Fiat--Shamir security reduction. Production-derived evaluator-key quotient witnesses exceed the common-proof scratch ceiling, so the monolithic compact lowering is rejected. The attempted compact packet redesign also fails its pre-implementation gate: one global shared lookup consumes the scratch ceiling before the remaining proof state, while smaller local lookups lack the required shared-witness proof relation and multiply full-dimension work. No production proof system is selected; bounded replacement-backend research must precede further family or browser qualification work. The lower-level scalar CFW/WHIR implementation remains development material, and the rejected previous implementation cannot act as a fallback or evidence source.
- **Browser runtime and custody:** A scalar WebAssembly build, one matched reference generation-and-verification path, typed worker foundations, authenticated checkpoint primitives, and browser-storage groundwork exist. Phase instrumentation localizes the guarded Node.js run's long uninterrupted interval to synchronous production-source construction before pollable proof generation begins; relation-catalog loading is not its owner. The file-backed development adapter still has severe whole-object copy-on-write amplification. Browser custody already chunks large proof objects, but capacity accounting still scans namespace metadata, and physical reclamation remains incomplete. Browser execution, checkpointed worker-loss restoration, the remaining proof paths, incremental accounting, repair, persistence, quota, eviction, and rollback evidence remain incomplete.
- **Ceremony workflow:** Setup, ballot, aggregation, evaluation, finality, and release are not yet connected end to end through participant-owned browser capabilities.
- **Phone and product evidence:** No physical-phone Chrome qualification or connected ten-participant host-application rehearsal exists.

Cryptographic completion and supported-phone qualification are independent results for the same exact suite and build bytes. Phone size, memory, storage, transfer, and runtime goals are planning targets, not verifier inputs. A reasonable overage is reported; an unexplained orders-of-magnitude overage requires redesign without making otherwise valid cryptographic bytes invalid.

## Install

Node.js 24.14.1 or later is required.

```bash
npm install sealed-lattice
```

or:

```bash
pnpm add sealed-lattice
```

## Usage

The public validator admits `2..20` options. This example uses the sole ten-option evidence target; structural admission does not qualify a profile.

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 10 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
    topOptionCount: 5,
});

if (!pollValidation.isValid) {
    throw new Error(
        pollValidation.errors[0]?.message ?? "Invalid poll specification.",
    );
}

const manifest = await createCanonicalManifest(pollValidation.normalized);
console.log(manifest.manifestHash, manifest.canonicalBytes);
```

`validatePollSpec` handles pre-protocol user input only. Protocol identity starts with the canonical manifest bytes and hash produced by the Rust/WebAssembly kernel. In that pre-protocol input, `topOptionCount` names the desired result length. The canonical action binds the same concept as `topCount`; the manifest itself contains only the ordered option definitions. Import public APIs from the package root; workspace packages, test fixtures, and internal source paths are not public API.

## Development

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` when browser-facing code changes and `pnpm run smoke:pack:npm` when public package behavior changes. Specialized proof and measurement runners are manual evidence lanes and are intentionally excluded from routine checks.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
