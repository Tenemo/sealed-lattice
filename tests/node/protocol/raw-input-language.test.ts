import { createHash } from 'node:crypto';
import { readdir } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { ballotEnvelopeBytes } from '#tests/ballot-body-model.js';
import {
    readRustSource,
    rustEnumCodes,
    rustFunctionBody,
    rustIntegerConstant,
    rustStringConstant,
} from '#tests/node/rust-source.js';
import { participantReleaseEnvelopeBytes } from '#tests/participant-release-custody-model.js';
import {
    reductionConstructorDimensions,
    reductionConstructorOperands,
} from '#tests/security-margin/constructor-operands.js';

// The designated raw SHAKE input languages of the security argument, rebuilt
// from the literals and layouts in their Rust sources. Every raw SHAKE input
// is a query of one ideal function, so a programmed input or an input that
// carries a hidden label must not also belong to another designated
// language.

const research = 'crates/protocol-research';
const ascii = (text: string) => new TextEncoder().encode(text);
const word = (value: number, bytes: number) => {
    const output = new Uint8Array(bytes);
    for (let index = 0; index < bytes; index++)
        output[index] = Math.floor(value / 256 ** index) % 256;
    return output;
};
const concatenate = (...parts: Uint8Array[]) =>
    Uint8Array.from(parts.flatMap((part) => [...part]));
// Whitespace-normalized text, so layout checks ignore formatting.
const normalized = (text: string) => text.replace(/\s+/gu, ' ');
const containsStatements = (body: string, statements: string) =>
    expect(normalized(body)).toContain(normalized(statements));

// The production Rust files of every crate, without test modules kept in
// their own files.
const productionRustFiles = async () => {
    const crates = await readdir(
        new URL(`../../../${research}`, import.meta.url),
        {
            withFileTypes: true,
        },
    );
    const files: string[] = [];
    for (const crate of crates.filter((entry) => entry.isDirectory()))
        if (crate.name !== 'target') {
            const source = `${research}/${crate.name}/src`;
            const entries = await readdir(
                new URL(`../../../${source}`, import.meta.url),
                { recursive: true, withFileTypes: true },
            ).catch(() => []);
            for (const entry of entries)
                if (
                    entry.isFile() &&
                    entry.name.endsWith('.rs') &&
                    !entry.name.endsWith('-tests.rs')
                ) {
                    const directory = entry.parentPath
                        .replace(/\\/gu, '/')
                        .split(`/${source}`)[1];
                    files.push(`${source}${directory}/${entry.name}`);
                }
        }
    return files.sort();
};

// A grammar's fixed bytes by position: a byte array is fixed, a number is
// that many free bytes, and `open` ends the positional layout.
type Part = Uint8Array | number | 'open';
const fixedBytes = (parts: readonly Part[]) => {
    const fixed = new Map<number, number>();
    let offset = 0;
    for (const part of parts) {
        if (part === 'open') break;
        if (typeof part === 'number') offset += part;
        else {
            part.forEach((byte, index) => fixed.set(offset + index, byte));
            offset += part.length;
        }
    }
    return fixed;
};
const separatingPosition = (
    left: ReadonlyMap<number, number>,
    right: ReadonlyMap<number, number>,
) =>
    [...left.keys()]
        .sort((first, second) => first - second)
        .find(
            (position) =>
                right.has(position) &&
                right.get(position) !== left.get(position),
        );

const readLanguages = async () => {
    const [
        protocolHash,
        signature,
        foundations,
        authentication,
        common,
        encryptedSource,
        operation,
        identity,
        tupleValue,
        tupleSchema,
        proofTranscript,
        verifierTranscript,
        proofTree,
    ] = await Promise.all(
        [
            'parallel-work/src/protocol-hash.rs',
            'purpose-signature/src/lib.rs',
            'protocol-foundations/src/lib.rs',
            'protocol-foundations/src/authentication.rs',
            'setup-witness/src/common-polynomial.rs',
            'setup-witness/src/encrypted-source.rs',
            'participant-module/src/operation-random.rs',
            'protocol-foundations/src/identity.rs',
            'protocol-foundations/src/foundation/canonical-tuple/value.rs',
            'protocol-foundations/src/foundation/canonical-tuple.rs',
            'word-proof/src/transcript.rs',
            'word-verifier/src/proof-transcript.rs',
            'word-proof/src/tree.rs',
        ].map((path) => readRustSource(`${research}/${path}`)),
    );

    // The protocol hash absorbs its domain padded with zeros to the prefix
    // length before the caller's input.
    const prefixBytes = Number(
        rustIntegerConstant(protocolHash, 'PREFIX_BYTES'),
    );
    const protocolDomain = rustStringConstant(protocolHash, 'DOMAIN');
    containsStatements(
        rustFunctionBody(protocolHash, 'new'),
        'let mut prefix = [0; PREFIX_BYTES]; prefix[..DOMAIN.len()].copy_from_slice(DOMAIN); hash.absorb(&prefix);',
    );
    const protocolPrefix = concatenate(
        ascii(protocolDomain),
        new Uint8Array(prefixBytes - protocolDomain.length),
    );

    // A purpose-signature chain start hashes its domain, the credential seed,
    // the purpose and the chain index after the prefix.
    containsStatements(
        rustFunctionBody(signature, 'hash'),
        'let mut value = ProtocolHash::new(); value.update(domain); for part in parts { value.update(part); } value.finalize()',
    );
    expect(signature).toMatch(/\btype\s+Digest\s*=\s*\[u8;\s*64\];/u);
    expect(normalized(signature)).toContain(
        'fn start(seed: &Digest, purpose: u8, chain: usize) -> Digest',
    );
    const start =
        /^\{\s*hash\(\s*b"([^"]+)",\s*&\[seed,\s*&\[purpose\],\s*&\(chain as u16\)\.to_le_bytes\(\)\],?\s*\)\s*\}$/u.exec(
            rustFunctionBody(signature, 'start'),
        );
    expect(start).not.toBeNull();
    const signatureStartDomain = ascii(start![1]);
    // A chain-function step hashes its domain and the 64-byte chain value
    // after the prefix.
    expect(normalized(signature)).toContain(
        'fn step(value: &Digest) -> Digest',
    );
    const step = /^\{\s*hash\(\s*b"([^"]+)",\s*&\[value\],?\s*\)\s*\}$/u.exec(
        rustFunctionBody(signature, 'step'),
    );
    expect(step).not.toBeNull();
    const signatureChainDomain = ascii(step![1]);

    // A retained tag frames its label by a 64-bit length before the
    // credential's signing seed.
    containsStatements(
        rustFunctionBody(foundations, 'retained_tag'),
        'let mut hash = ProtocolHash::new(); hash.update((label.len() as u64).to_le_bytes()); hash.update(label); hash.update(self.signing_seed.as_slice());',
    );
    expect(normalized(foundations)).toContain(
        'signing_seed: Zeroizing<[u8; authentication::SEED_BYTES]>',
    );
    expect(rustIntegerConstant(authentication, 'SEED_BYTES')).toBe(64n);

    // The common readers and the source private stream.
    const synthetic =
        /let mut state = Shake256::default\(\);\s*Update::update\(&mut state, b"([^"]+)"\);/u.exec(
            rustFunctionBody(common, 'public_reader'),
        );
    expect(synthetic).not.toBeNull();
    const sourceCommon =
        /let mut state = Shake256::default\(\);\s*state\.update\(b"([^"]+)"\);\s*state\.update\(&\[component as u8\]\);/u.exec(
            rustFunctionBody(encryptedSource, 'common_polynomials'),
        );
    expect(sourceCommon).not.toBeNull();
    const privateStream = rustFunctionBody(encryptedSource, 'private_stream');
    const sourcePrivate =
        /let mut state = Shake256::default\(\);\s*state\.update\(b"([^"]+)"\);\s*state\.update\(&\[purpose\]\);\s*state\.update\(seed\);/u.exec(
            privateStream,
        );
    expect(sourcePrivate).not.toBeNull();
    expect(normalized(encryptedSource)).toMatch(
        /fn private_stream\( profile: Profile, poll: &\[u8; 64\], owner: &\[u8; 64\], seed: &\[u8; 64\], purpose: u8, \)/u,
    );

    // An operation stream absorbs the canonical tuple of its domain and one
    // raw seed item.
    const operationSeedBytes = Number(
        rustIntegerConstant(operation, 'SEED_BYTES'),
    );
    containsStatements(
        rustFunctionBody(operation, 'stream'),
        'hasher.update( &framing(domain, &[], Trailing::Variable(SEED_BYTES))',
    );
    containsStatements(
        rustFunctionBody(operation, 'stream'),
        'hasher.update(seed);',
    );
    const operationDomains = [
        ...rustFunctionBody(operation, 'domains').matchAll(/"([^"]+)"/gu),
    ].map((match) => match[1]);
    const framing = rustFunctionBody(identity, 'framing');
    for (const statement of [
        'items.push(CanonicalItem::nonempty_ascii(domain).map_err(|_| Refusal::Shape)?);',
        'let count = word(items.len() + 1)?;',
        'framing[2..6].copy_from_slice(&count.to_le_bytes());',
        'framing.extend_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());',
        'let item_length = length.checked_add(4).ok_or(Refusal::Shape)?; framing.extend_from_slice(&word(item_length)?.to_le_bytes()); framing.extend_from_slice(&word(length)?.to_le_bytes());',
    ])
        containsStatements(framing, statement);
    containsStatements(
        rustFunctionBody(tupleValue, 'encode'),
        'output.extend_from_slice(&self.schema_identifier.to_le_bytes()); output.extend_from_slice(&item_count.to_le_bytes()); for item in &self.items { output.extend_from_slice(&item.item_type.canonical_code().to_le_bytes());',
    );
    containsStatements(
        rustFunctionBody(tupleValue, 'ascii'),
        'canonical_bytes.extend_from_slice(&byte_length.to_le_bytes()); canonical_bytes.extend_from_slice(bytes);',
    );
    const itemCodes = rustEnumCodes(tupleValue, 'CanonicalItemType');
    const schema = Number(
        rustIntegerConstant(tupleSchema, 'CANONICAL_TUPLE_SCHEMA_IDENTIFIER'),
    );
    const operationFraming = (domain: string) =>
        concatenate(
            word(schema, 2),
            word(2, 4),
            word(itemCodes.Ascii, 2),
            word(domain.length + 4, 4),
            word(domain.length, 4),
            ascii(domain),
            word(itemCodes.RawBytes, 2),
            word(operationSeedBytes + 4, 4),
            word(operationSeedBytes, 4),
        );

    // The length-framed proof languages.
    for (const transcript of [proofTranscript, verifierTranscript])
        expect(normalized(rustFunctionBody(transcript, 'wide'))).toMatch(
            /let mut (\w+) = Shake256::default\(\); Update::update\(&mut \1, &\(domain\.len\(\) as u32\)\.to_le_bytes\(\)\); Update::update\(&mut \1, domain\);/u,
        );
    // Every call of the transcript framing passes one of two literal domains.
    const transcriptDomains = new Set<string>();
    for (const path of await productionRustFiles())
        for (const call of (await readRustSource(path)).matchAll(
            /(?<!fn )(?<![\w.])wide\(\s*([^,]*),/gu,
        ))
            if (!call[1].startsWith('domain:')) {
                expect(call[1], path).toMatch(/^b"[^"]+"$/u);
                transcriptDomains.add(call[1].slice(2, -1));
            }
    const [chainState, verifierMessage] = [...transcriptDomains].sort();
    expect([chainState, verifierMessage]).toEqual([
        'bounded-proof/chain-state',
        'bounded-proof/verifier-message',
    ]);
    expect(transcriptDomains.size).toBe(2);
    const compactTranscript = await readRustSource(
        `${research}/compact-rank-proof/src/transcript.rs`,
    );
    containsStatements(
        rustFunctionBody(compactTranscript, 'shake'),
        'for part in parts { state.update(&word(part.len())); state.update(part); }',
    );
    expect(normalized(rustFunctionBody(compactTranscript, 'word'))).toMatch(
        /u32::try_from\(value\).*\.to_le_bytes\(\)/u,
    );
    const compactDomains = [
        ...compactTranscript.matchAll(/(?<!fn )\bshake\(\s*&\[\s*b"([^"]+)"/gu),
    ]
        .map((match) => match[1])
        .sort();
    expect(compactTranscript.match(/(?<!fn )\bshake\(/gu)).toHaveLength(
        compactDomains.length,
    );
    expect(compactDomains).toEqual([
        'compact-proof/chain-state',
        'compact-proof/verifier-message',
    ]);
    const saltDomain = rustStringConstant(proofTree, 'SALT_DOMAIN');
    const saltSeedBytes = Number(
        rustIntegerConstant(proofTree, 'SALT_SEED_BYTES'),
    );
    // The tree also has a salt method, which calls this free function.
    const freeSalt = proofTree.indexOf('pub fn salt(seed');
    const saltMethod = proofTree.indexOf('pub fn salt(&self');
    expect(freeSalt).toBeGreaterThanOrEqual(0);
    expect(saltMethod).toBeGreaterThan(freeSalt);
    containsStatements(
        rustFunctionBody(proofTree.slice(freeSalt, saltMethod), 'salt'),
        'let mut state = Shake256::default(); for bytes in [SALT_DOMAIN, seed.as_slice(), &(index as u32).to_le_bytes()] { Update::update(&mut state, &(bytes.len() as u32).to_le_bytes()); Update::update(&mut state, bytes); }',
    );

    return {
        protocolPrefix,
        signatureStartDomain,
        signatureChainDomain,
        chainState: ascii(chainState),
        verifierMessage: ascii(verifierMessage),
        compactDomains,
        synthetic: ascii(synthetic![1]),
        sourceCommon: ascii(sourceCommon![1]),
        sourcePrivate: ascii(sourcePrivate![1]),
        operationDomains,
        operationFraming,
        operationSeedBytes,
        saltDomain: ascii(saltDomain),
        saltSeedBytes,
    };
};

describe('raw-input language separation', () => {
    it('classifies every raw SHAKE construction in the production crates', async () => {
        const counts: Record<string, number> = {};
        for (const path of await productionRustFiles()) {
            const source = await readRustSource(path);
            const constructions =
                (source.match(/\bShake256::default\(\)/gu)?.length ?? 0) +
                (source.match(/\bkeccak::f1600\(/gu)?.length ?? 0) +
                (source.match(/\bShake128\b|\bSha3_\d+\b/gu)?.length ?? 0);
            if (constructions > 0)
                counts[path.slice(research.length + 1)] = constructions;
        }
        // Each site belongs to one language of the separation lemma: the
        // protocol hash, a canonical tuple, a common reader, the source
        // private stream, a length-framed proof language, or the fixed input
        // of the public source screen.
        expect(counts).toEqual({
            'compact-rank-proof/src/transcript.rs': 1,
            'parallel-work/src/protocol-hash.rs': 2,
            'parallel-work/src/stream.rs': 1,
            'participant-module/src/operation-random.rs': 1,
            'protocol-foundations/src/foundation/hash.rs': 1,
            'setup-witness/src/common-polynomial.rs': 1,
            'setup-witness/src/encrypted-source.rs': 2,
            'setup-witness/src/fhe-key-source-screen.rs': 1,
            'word-proof/src/transcript.rs': 1,
            'word-proof/src/tree.rs': 1,
            'word-verifier/src/proof-transcript.rs': 1,
        });
        // The identity stream sponge serves canonical-tuple identities only.
        const sponges = new Set<string>();
        for (const path of await productionRustFiles())
            for (const match of (await readRustSource(path)).matchAll(
                /HashStream::(?:new|local)\(Sponge::(\w+)\)/gu,
            ))
                if (match[1] === 'Shake256') sponges.add(path);
        expect(sponges).toEqual(
            new Set([`${research}/protocol-foundations/src/identity.rs`]),
        );
        // The public source screen absorbs one fixed public input.
        const screen = await readRustSource(
            `${research}/setup-witness/src/fhe-key-source-screen.rs`,
        );
        containsStatements(
            rustFunctionBody(screen, 'source_reader'),
            'let mut hash = Shake256::default(); hash.update(b"fhe-key-source-screen"); hash.update(&[0x67; 64]); hash.finalize_xof()',
        );
    });

    it('pins the designated literals, their field offsets and the stream framing', async () => {
        const languages = await readLanguages();
        expect(
            new TextDecoder().decode(languages.protocolPrefix.subarray(0, 25)),
        ).toBe('sealed-lattice/fixed-hash');
        expect(languages.protocolPrefix).toHaveLength(64);
        expect(
            languages.protocolPrefix.subarray(25).every((byte) => byte === 0),
        ).toBe(true);
        // The credential seed of a chain start lies at bytes 86 to 149 of a
        // 153-byte input, after the 22-byte domain.
        const seedStart = 64 + languages.signatureStartDomain.length;
        expect([seedStart, seedStart + 63, seedStart + 64 + 1 + 2]).toEqual([
            86, 149, 153,
        ]);
        // The chain value of a chain-function input lies at bytes 85 to 148 of
        // a 149-byte input, after the 21-byte domain.
        const valueStart = 64 + languages.signatureChainDomain.length;
        expect([valueStart, valueStart + 63, valueStart + 64]).toEqual([
            85, 148, 149,
        ]);
        // The registration-source seed of the private stream lies at bytes 33
        // to 96, after the domain and the purpose byte.
        expect(languages.sourcePrivate.length + 1).toBe(33);
        // The proof-tree seed of a leaf salt lies after the framed domain and
        // its own length word.
        expect(4 + languages.saltDomain.length + 4).toBe(26);
        expect(languages.saltSeedBytes).toBe(64);
        // Five distinct operation domains, each used by no other production or
        // test source, so no canonical-tuple identity shares their framing.
        expect(new Set(languages.operationDomains).size).toBe(5);
        expect(languages.operationSeedBytes).toBe(64);
        const users = new Map<string, string[]>();
        const sources = (await productionRustFiles()).concat(
            `${research}/participant-module/src/operation-random-tests.rs`,
        );
        for (const path of sources) {
            const source = await readRustSource(path);
            for (const domain of languages.operationDomains)
                if (source.includes(`"${domain}"`))
                    users.set(domain, [...(users.get(domain) ?? []), path]);
        }
        for (const domain of languages.operationDomains)
            expect(users.get(domain)).toEqual([
                `${research}/participant-module/src/operation-random.rs`,
                `${research}/participant-module/src/operation-random-tests.rs`,
            ]);
        // The framing rebuilt here reproduces the stream prefixes that the
        // native known-answer test pins for the seed 3 + 29i.
        const knownAnswers = [
            ...(
                await readRustSource(
                    `${research}/participant-module/src/operation-random-tests.rs`,
                )
            ).matchAll(
                /\(\s*"(sealed-lattice\/[a-z-]+-randomness)",\s*"([0-9a-f]{64})",?\s*\)/gu,
            ),
        ];
        expect(knownAnswers.map((match) => match[1]).sort()).toEqual(
            [...languages.operationDomains].sort(),
        );
        const seed = Uint8Array.from(
            { length: 64 },
            (_, index) => (3 + 29 * index) % 256,
        );
        for (const [, domain, prefix] of knownAnswers)
            expect(
                createHash('shake256', { outputLength: 32 })
                    .update(
                        concatenate(languages.operationFraming(domain), seed),
                    )
                    .digest('hex'),
            ).toBe(prefix);
        // The raw seed item follows the framed domain at byte 26 plus the
        // domain length.
        for (const domain of languages.operationDomains)
            expect(languages.operationFraming(domain)).toHaveLength(
                26 + domain.length,
            );
    });

    it('fits every common-record raw input within the priced 512 bits', async () => {
        const [common, contribution, auxiliary, encryptedSource] =
            await Promise.all(
                [
                    'setup-witness/src/common-polynomial.rs',
                    'setup-witness/src/contribution.rs',
                    'setup-witness/src/fixed-auxiliary.rs',
                    'setup-witness/src/encrypted-source.rs',
                ].map((path) => readRustSource(`${research}/${path}`)),
            );
        // The synthetic reader absorbs its domain and the label framed by a
        // 32-bit length; the source reader its domain, the component byte and
        // a 32-bit block index.
        containsStatements(
            rustFunctionBody(common, 'public_reader'),
            'Update::update(&mut state, b"synthetic-full-setup-witness"); Update::update(&mut state, &(label.len() as u32).to_le_bytes()); Update::update(&mut state, label.as_bytes()); state.finalize_xof()',
        );
        containsStatements(
            rustFunctionBody(encryptedSource, 'common_polynomials'),
            'state.update(b"sealed-lattice/source-common/v1"); state.update(&[component as u8]); state.update(&(block as u32).to_le_bytes()); let mut reader = state.finalize_xof();',
        );
        // FHE labels name a component letter and a gadget index below the
        // priced gadget count, which the ledger checks for every profile.
        const names = [
            ...rustFunctionBody(contribution, 'common_source').matchAll(
                /\d+ => "([a-z]+)",/gu,
            ),
        ].map((match) => match[1]);
        expect(names).toEqual(['a', 'u', 'k']);
        const largestGadget = String(
            reductionConstructorDimensions.gadgets - 1n,
        );
        const labels = [contribution, auxiliary].flatMap((source) =>
            [...source.matchAll(/"(common-[a-z{}-]+)"/gu)].map((match) =>
                match[1]
                    .replace('{name}', names[0])
                    .replace('{gadget}', largestGadget),
            ),
        );
        expect(new Set(labels)).toEqual(
            new Set([
                'common-share',
                `common-fhe-a-${largestGadget}`,
                'common-auxiliary',
                'common-auxiliary-key',
            ]),
        );
        const rawInputs = [
            ...labels.map(
                (label) =>
                    'synthetic-full-setup-witness'.length + 4 + label.length,
            ),
            'sealed-lattice/source-common/v1'.length + 1 + 4,
        ];
        for (const bytes of rawInputs)
            expect(8 * bytes).toBeLessThanOrEqual(512);
    });

    it('fits every purpose-signature raw input within its priced frame', async () => {
        const [protocolHash, signature, authentication, foundations] =
            await Promise.all(
                [
                    'parallel-work/src/protocol-hash.rs',
                    'purpose-signature/src/lib.rs',
                    'protocol-foundations/src/authentication.rs',
                    'protocol-foundations/src/lib.rs',
                ].map((path) => readRustSource(`${research}/${path}`)),
            );
        const sources = new Map<string, string>();
        for (const path of await productionRustFiles())
            sources.set(
                path.slice(research.length + 1),
                await readRustSource(path),
            );
        const callers = (pattern: RegExp) =>
            [...sources].flatMap(([path, source]) =>
                [...normalized(source).matchAll(pattern)].map((match) =>
                    match[1] === undefined ? path : `${path} ${match[1]}`,
                ),
            );
        // Honest signing has one path: a credential derives its key pair and
        // signs only inside its deterministic signer, and its other
        // derivations drop the signing key.
        expect(callers(/(?<!fn )\bkeypair_from_seed\(/gu)).toEqual([
            'protocol-foundations/src/lib.rs',
            'protocol-foundations/src/lib.rs',
            'protocol-foundations/src/lib.rs',
        ]);
        for (const name of ['from_seed', 'check_retained'])
            containsStatements(
                rustFunctionBody(foundations, name),
                'drop(private);',
            );
        containsStatements(
            rustFunctionBody(foundations, 'sign_deterministically'),
            'let (_, mut private) = crate::authentication::keypair_from_seed(&self.signing_seed); private.sign(message, context).map_err(|_| Refusal::Crypto)',
        );
        containsStatements(
            rustFunctionBody(authentication, 'sign'),
            'self.0 .sign_context(context, message)?',
        );
        expect(
            callers(/\.sign_context\(/gu).filter(
                (caller) => !caller.startsWith('purpose-signature/'),
            ),
        ).toEqual(['protocol-foundations/src/authentication.rs']);
        // Each signed message is a fixed-length ballot or release envelope or
        // a 64-byte identity or digest. A new call site fails this list.
        const envelopes = new Map([
            [
                'protocol-foundations/src/ballot-authentication.rs envelope.bytes()',
                ballotEnvelopeBytes,
            ],
            [
                'protocol-foundations/src/release-signing.rs envelope.bytes()',
                participantReleaseEnvelopeBytes,
            ],
        ]);
        const signed = callers(
            /(?<!fn )\bsign_deterministically\( ?([^,]+),/gu,
        );
        expect([...signed].sort()).toEqual([
            'protocol-foundations/src/ballot-authentication.rs envelope.bytes()',
            'protocol-foundations/src/close-signing.rs identity',
            'protocol-foundations/src/contribution-offer.rs &envelope.identity()',
            'protocol-foundations/src/lib.rs &body.digest',
            'protocol-foundations/src/poll.rs &identity',
            'protocol-foundations/src/release-signing.rs envelope.bytes()',
            'protocol-foundations/src/roster-authentication.rs &proposal.identity()',
            'protocol-foundations/src/setup-selection.rs &digest',
            'protocol-foundations/src/setup-selection.rs &selection.identity()',
            'protocol-foundations/src/target-signing.rs message.identity()',
        ]);
        const longestMessage = signed
            .map((call) => envelopes.get(call) ?? 64n)
            .reduce((left, right) => (left > right ? left : right));

        // Every frame hashes the protocol prefix, its domain and its parts.
        containsStatements(
            rustFunctionBody(signature, 'hash'),
            'let mut value = ProtocolHash::new(); value.update(domain); for part in parts { value.update(part); } value.finalize()',
        );
        expect(signature).toMatch(/\btype\s+Digest\s*=\s*\[u8;\s*64\];/u);
        const prefixBytes = rustIntegerConstant(protocolHash, 'PREFIX_BYTES');
        const chains = rustIntegerConstant(signature, 'CHAINS');
        for (const statement of [
            'fn step(value: &Digest) -> Digest',
            'fn start(seed: &Digest, purpose: u8, chain: usize) -> Digest',
            'fn digits(message: &Digest) -> [u8; CHAINS]',
            'fn message_digest(root: &Digest, purpose: u8, message: &[u8]) -> Digest',
            'fn leaf(purpose: u8, public_key: &[u8]) -> Digest',
            'fn parent(level: u8, left: &Digest, right: &Digest) -> Digest',
        ])
            expect(normalized(signature)).toContain(statement);
        // Both leaf inputs hold one 64-byte chain end per chain.
        containsStatements(
            rustFunctionBody(signature, 'new'),
            'let mut public_key = Vec::with_capacity(CHAINS * 64); for chain in 0..CHAINS { let mut value = Zeroizing::new(start(&seed, purpose as u8, chain)); for _ in 0..15 { *value = step(&value); } public_key.extend_from_slice(&*value); } tree[PURPOSES + purpose] = leaf(purpose as u8, &public_key);',
        );
        containsStatements(
            rustFunctionBody(signature, 'verify'),
            'let encoded = digits(&message_digest(root, expected_purpose, message)); let mut public_key = Vec::with_capacity(CHAINS * 64); for (chain, count) in encoded.into_iter().enumerate() { let mut value: Digest = signature[2 + chain * 64..2 + (chain + 1) * 64] .try_into() .unwrap(); for _ in count..15 { value = step(&value); } public_key.extend_from_slice(&value); } let mut node = leaf(expected_purpose, &public_key);',
        );
        const frames = [
            [
                'secret',
                'hash( b"purpose-wots/secret/v1", &[seed, &[purpose], &(chain as u16).to_le_bytes()], )',
                64n + 1n + 2n,
            ],
            ['chain', 'hash(b"purpose-wots/chain/v1", &[value])', 64n],
            [
                'leaf',
                'hash(b"purpose-wots/leaf/v1", &[&[purpose], public_key])',
                1n + 64n * chains,
            ],
            [
                'unused',
                'hash(b"purpose-wots/unused/v1", &[&[purpose as u8]])',
                1n,
            ],
            [
                'node',
                'hash(b"purpose-wots/node/v1", &[&[level], left, right])',
                1n + 64n + 64n,
            ],
            [
                'message',
                'hash( b"purpose-wots/message/v1", &[ root, &[purpose], &(message.len() as u64).to_le_bytes(), message, ], )',
                64n + 1n + 8n + longestMessage,
            ],
        ] as const;
        // These are all the hash calls of the primitive.
        const production = normalized(signature).split('#[cfg(test)]')[0];
        expect(production.match(/(?<!fn )\bhash\(/gu)).toHaveLength(
            frames.length,
        );
        const priced = reductionConstructorOperands.authentication.frames;
        for (const [name, call, payloadBytes] of frames) {
            expect(production, name).toContain(call);
            const domain = /b"([^"]+)"/u.exec(call)![1];
            expect(
                8n * (prefixBytes + BigInt(domain.length) + payloadBytes),
                name,
            ).toBeLessThanOrEqual(priced[name].inputBits);
        }
    });

    it('keeps every retained-tag label shorter than 2^8 bytes', async () => {
        const sources = new Map<string, string>();
        for (const path of await productionRustFiles())
            sources.set(path, await readRustSource(path));
        // A label constant may be defined in another file of its crate, but
        // only once in the production crates.
        const labelConstant = (name: string) => {
            const definitions = [...sources.values()].flatMap((source) =>
                [
                    ...source.matchAll(
                        new RegExp(
                            `\\bconst\\s+${name}\\s*:\\s*&\\[u8\\]\\s*=\\s*b"([^"\\\\]*)";`,
                            'gu',
                        ),
                    ),
                ].map((match) => match[1]),
            );
            expect(definitions, name).toHaveLength(1);
            return definitions[0];
        };
        const labels: string[] = [];
        const forwarders: string[] = [];
        for (const [path, source] of sources)
            for (const call of source.matchAll(
                /\b(?:check_)?retained_tag\(\s*(b"[^"]*"|[A-Z_]+|label)\s*,/gu,
            ))
                if (call[1] === 'label') forwarders.push(path);
                else
                    labels.push(
                        call[1].startsWith('b"')
                            ? call[1].slice(2, -1)
                            : labelConstant(call[1]),
                    );
        // Only the checking wrapper forwards its own label.
        expect(forwarders).toEqual([
            `${research}/protocol-foundations/src/lib.rs`,
        ]);
        expect(new Set(labels)).toEqual(
            new Set([
                'sealed-lattice/aggregate-data',
                'sealed-lattice/collected-offers',
                'sealed-lattice/retained-evaluation-target',
                'sealed-lattice/retained-selection-inputs',
                'sealed-lattice/retained-setup-reference',
            ]),
        );
        for (const label of labels) {
            expect(label.length).toBeGreaterThan(0);
            expect(label.length).toBeLessThan(256);
        }
    });

    it('separates every pair of designated languages by a fixed byte', async () => {
        const languages = await readLanguages();
        const grammars: Record<string, readonly Part[]> = {
            'purpose-signature chain start': [
                languages.protocolPrefix,
                languages.signatureStartDomain,
                'open',
            ],
            'purpose-signature chain function': [
                languages.protocolPrefix,
                languages.signatureChainDomain,
                'open',
            ],
            // The label length is below 2^8, so only its first byte is free.
            'retained tag': [
                languages.protocolPrefix,
                1,
                new Uint8Array(7),
                'open',
            ],
            'synthetic common reader': [languages.synthetic, 'open'],
            'source common reader': [languages.sourceCommon, 'open'],
            'source private stream': [languages.sourcePrivate, 'open'],
            ...Object.fromEntries(
                languages.operationDomains.map((domain) => [
                    `operation stream ${domain}`,
                    [languages.operationFraming(domain), 'open'],
                ]),
            ),
            'verifier message': [
                word(languages.verifierMessage.length, 4),
                languages.verifierMessage,
                'open',
            ],
            'chain state': [
                word(languages.chainState.length, 4),
                languages.chainState,
                'open',
            ],
            ...Object.fromEntries(
                languages.compactDomains.map((domain) => [
                    domain,
                    [word(domain.length, 4), ascii(domain), 'open'],
                ]),
            ),
            'leaf salt': [
                word(languages.saltDomain.length, 4),
                languages.saltDomain,
                word(languages.saltSeedBytes, 4),
                'open',
            ],
        };
        const fixed = Object.entries(grammars).map(
            ([name, parts]) => [name, fixedBytes(parts)] as const,
        );
        for (const [index, [leftName, left]] of fixed.entries())
            for (const [rightName, right] of fixed.slice(index + 1))
                expect(
                    separatingPosition(left, right),
                    `${leftName} against ${rightName}`,
                ).toBeDefined();
        // The positions the lemma names: byte 0 splits the families, byte 1
        // the synthetic reader, byte 15 the protocol prefix from the source
        // languages, byte 22 the two source languages, byte 65 the chain
        // start and chain function from a retained tag, and byte 77 the chain
        // function from the chain start.
        const byte = (name: string, position: number) =>
            fixedBytes(grammars[name]).get(position);
        const signatureGrammars = [
            'purpose-signature chain start',
            'purpose-signature chain function',
        ];
        expect(
            [
                ...signatureGrammars,
                'synthetic common reader',
                'source common reader',
                'source private stream',
            ].map((name) => byte(name, 0)),
        ).toEqual(Array(5).fill(0x73));
        for (const domain of languages.operationDomains)
            expect(byte(`operation stream ${domain}`, 0)).toBe(0x01);
        expect(
            ['leaf salt', 'chain state', 'verifier message'].map((name) => [
                byte(name, 0),
                byte(name, 1),
                byte(name, 2),
                byte(name, 3),
            ]),
        ).toEqual([
            [0x12, 0, 0, 0],
            [0x19, 0, 0, 0],
            [0x1e, 0, 0, 0],
        ]);
        expect(byte('synthetic common reader', 1)).toBe(0x79);
        for (const name of [
            ...signatureGrammars,
            'source common reader',
            'source private stream',
        ])
            expect(byte(name, 1)).not.toBe(0x79);
        expect(
            [
                ...signatureGrammars,
                'source common reader',
                'source private stream',
            ].map((name) => byte(name, 15)),
        ).toEqual([0x66, 0x66, 0x73, 0x73]);
        expect(
            ['source common reader', 'source private stream'].map((name) =>
                byte(name, 22),
            ),
        ).toEqual([0x63, 0x70]);
        expect(
            [...signatureGrammars, 'retained tag'].map((name) =>
                byte(name, 65),
            ),
        ).toEqual([0x75, 0x75, 0]);
        expect(signatureGrammars.map((name) => byte(name, 77))).toEqual([
            0x73, 0x63,
        ]);
        // A label of 2^8 bytes or more would put a nonzero byte at offset 65.
        expect(word(0x7500, 8)[1]).toBe(0x75);
    });
});
