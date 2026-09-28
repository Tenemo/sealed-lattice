import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { participantSourceManifest } from '#tools/ci/build-participant-module.js';

describe('participant source identity', () => {
    it('binds the page controller, shared Rust decoders and dependency pins as well as worker sources', async () => {
        const manifest = JSON.parse(
            await participantSourceManifest({
                compiler: 'fixture compiler',
                flags: [],
                module: Buffer.alloc(0),
            }),
        ) as { files: { file: string; sha512: string; bytes: number }[] };
        // These are concrete dependencies outside the worker directory:
        // the page starts and terminates helpers, the credential crate's
        // foundation.rs imports these Rust files, and builders use both
        // lockfiles. A stale build must notice any of them changing.
        for (const file of [
            'packages/sdk/src/participant/participant.ts',
            'crates/sealed-lattice-kernel/src/foundation/hash.rs',
            'crates/sealed-lattice-kernel/src/foundation/canonical_tuple/decoding.rs',
            'Cargo.lock',
            'pnpm-lock.yaml',
            'tools/ci/build-wasm-kernel.ts',
            'tools/ci/sdk-package-tsdown.config.ts',
        ]) {
            const source = await readFile(file);
            expect(
                manifest.files.find((entry) => entry.file === file),
                file,
            ).toEqual({
                file,
                sha512: createHash('sha512').update(source).digest('hex'),
                bytes: source.length,
            });
        }
    });
});
