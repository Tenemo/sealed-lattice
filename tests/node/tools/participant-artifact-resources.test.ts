import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import { readParticipantArtifactResources } from '#tools/ci/participant-artifact-resources.js';

const fixture = () => {
    const source = Buffer.from('fixture source');
    const manifest = Buffer.from(
        JSON.stringify({
            files: [
                {
                    file: 'packages/sdk/src/fixture.ts',
                    bytes: source.length,
                    sha512: createHash('sha512').update(source).digest('hex'),
                },
            ],
        }),
    );
    const module = Buffer.from('fixture module'),
        worker = Buffer.from('fixture worker');
    const identity = participantRuntimeIdentity(manifest, module, worker);
    const files = new Map([
        ['packages/sdk/src/fixture.ts', source],
        ['packages/sdk/dist/participant-source-manifest.json', manifest],
        ['packages/sdk/dist/participant.wasm', module],
        ['packages/sdk/dist/participant-worker.js', worker],
        ['packages/sdk/dist/index.js', Buffer.from(JSON.stringify(identity))],
    ]);
    return {
        files,
        read: (file: string) => {
            const value = files.get(file);
            if (value === undefined) throw new Error('missing');
            return value;
        },
        identity,
    };
};

describe('built participant resource operands', () => {
    it('identifies actual artifact lengths without executing or building them', () => {
        const value = fixture();
        const result = readParticipantArtifactResources(value.read);
        expect(result.identity).toEqual(value.identity);
        expect(result.moduleBytes).toBe(
            BigInt(Buffer.byteLength('fixture module')),
        );
        expect(result.workerBytes).toBe(
            BigInt(Buffer.byteLength('fixture worker')),
        );
    });
    it('refuses absent artifacts, changed sources and mixed build outputs', () => {
        const missing = fixture();
        missing.files.delete('packages/sdk/dist/participant.wasm');
        expect(() => readParticipantArtifactResources(missing.read)).toThrow(
            'Missing',
        );
        const stale = fixture();
        stale.files.set(
            'packages/sdk/src/fixture.ts',
            Buffer.from('changed source'),
        );
        expect(() => readParticipantArtifactResources(stale.read)).toThrow(
            'Stale',
        );
        const mixed = fixture();
        mixed.files.set(
            'packages/sdk/dist/participant-worker.js',
            Buffer.from('other worker'),
        );
        expect(() => readParticipantArtifactResources(mixed.read)).toThrow(
            'different builds',
        );
    });
});
