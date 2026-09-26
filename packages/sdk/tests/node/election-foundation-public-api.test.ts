import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';
import {
    createMaximumAcceptedPollSpec,
    maximumCanonicalManifestFixtureByteLength,
} from '../maximum-manifest-fixture.js';

type CreateCanonicalManifest = (input: {
    readonly options: readonly string[];
    readonly question: string;
}) => Promise<{
    readonly canonicalBytes: Uint8Array;
    readonly manifestHash: string;
}>;
type VerifyCanonicalManifest = (canonicalBytes: Uint8Array) => Promise<
    | Readonly<{
          readonly isValid: true;
          readonly value: Readonly<{ readonly manifestHash: string }>;
      }>
    | Readonly<{ readonly isValid: false; readonly refusalReason: string }>
>;
type OpenParticipant = (options: {
    readonly namespace: string;
    readonly relay: string;
    readonly archive?: {
        readonly faultBound: number;
        readonly replicas: readonly {
            readonly baseUrl: string;
            readonly verificationKey: Uint8Array;
        }[];
    };
}) => { readonly run: unknown };
const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const createCanonicalManifest =
    publicApiRuntimeRecord.createCanonicalManifest as CreateCanonicalManifest;
const verifyCanonicalManifest =
    publicApiRuntimeRecord.verifyCanonicalManifest as VerifyCanonicalManifest;
const openParticipant =
    publicApiRuntimeRecord.openParticipant as OpenParticipant;
const expectedPublicRuntimeExportNames = [
    'createCanonicalActionDefinition',
    'createCanonicalBoardPolicy',
    'createCanonicalManifest',
    'createPublicArchive',
    'openParticipant',
    'validatePollSpec',
    'verifyCanonicalActionContext',
    'verifyCanonicalActionDefinition',
    'verifyCanonicalBoardPolicy',
    'verifyCanonicalCeremonyContext',
    'verifyCanonicalManifest',
] as const;
const expectedPublicWasmExportNames = [
    '__data_end',
    '__heap_base',
    'memory',
    'sealed_lattice_allocate',
    'sealed_lattice_deallocate',
    'sealed_lattice_foundation_command_with_length',
] as const;

describe('election foundation public package API in Node', () => {
    it('exposes safe runtime functions and keeps runtime exports callable', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(expectedPublicRuntimeExportNames);
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('ships a foundation-only WebAssembly export inventory', () => {
        const module = new WebAssembly.Module(
            readFileSync(
                new URL(
                    '../../dist/sealed-lattice-kernel.wasm',
                    import.meta.url,
                ),
            ),
        );
        const exportNames = WebAssembly.Module.exports(module)
            .map((entry) => entry.name)
            .sort();

        expect(exportNames).toEqual(expectedPublicWasmExportNames);
    });

    it('creates and verifies canonical manifest bytes through one packaged kernel instance', async () => {
        const instantiate = vi.spyOn(WebAssembly, 'instantiate');
        try {
            const manifest = await createCanonicalManifest({
                options: Array.from(
                    { length: 10 },
                    (_value, optionIndex) => `Option ${String(optionIndex)}`,
                ),
                question: 'Choose priorities',
            });

            expect(manifest.canonicalBytes.byteLength).toBeGreaterThan(0);
            expect(
                await verifyCanonicalManifest(manifest.canonicalBytes),
            ).toEqual({
                isValid: true,
                value: { manifestHash: manifest.manifestHash },
            });
            expect(instantiate).toHaveBeenCalledTimes(1);
        } finally {
            instantiate.mockRestore();
        }
    });

    it('creates and verifies the largest manifest admitted by poll validation', async () => {
        const manifest = await createCanonicalManifest(
            createMaximumAcceptedPollSpec(),
        );

        expect(manifest.canonicalBytes).toHaveLength(
            maximumCanonicalManifestFixtureByteLength,
        );
        expect(await verifyCanonicalManifest(manifest.canonicalBytes)).toEqual({
            isValid: true,
            value: { manifestHash: manifest.manifestHash },
        });
    });

    it('opens a participant only for a well-formed namespace and relay', () => {
        const relay = 'https://relay.example/polls/';
        for (const namespace of [
            '',
            'Poll',
            '-poll',
            'poll-',
            'poll/one',
            'poll one',
            'a'.repeat(65),
        ])
            expect(() => openParticipant({ namespace, relay })).toThrow(
                TypeError,
            );
        for (const malformed of [
            'relay.example/polls/',
            '/polls/',
            'ftp://relay.example/polls/',
            'https://relay.example/polls/?poll=1',
            'https://relay.example/polls/#poll',
            'https://user@relay.example/polls/',
        ])
            expect(() =>
                openParticipant({ namespace: 'poll', relay: malformed }),
            ).toThrow(TypeError);
        for (const namespace of ['a', '0-poll-9', 'a'.repeat(64)])
            expect(typeof openParticipant({ namespace, relay }).run).toBe(
                'function',
            );
        expect(
            typeof openParticipant({
                namespace: 'poll',
                relay: 'http://127.0.0.1:8080/polls',
            }).run,
        ).toBe('function');
    });

    it('opens a participant only with a well-formed archive', () => {
        const relay = 'https://relay.example/polls/';
        const replica = (
            position: number,
            baseUrl = `https://replica-${String(position)}.example/archive/`,
            keyBytes = 1952,
        ) => ({
            baseUrl,
            verificationKey: new Uint8Array(keyBytes).fill(position + 1),
        });
        const replicas = [0, 1, 2].map((position) => replica(position));
        for (const archive of [
            { faultBound: 1, replicas },
            {
                faultBound: 0,
                replicas: [replica(0, 'http://127.0.0.1:9000/archive')],
            },
            {
                faultBound: 0,
                replicas: Array.from({ length: 32 }, (_unused, position) =>
                    replica(position),
                ),
            },
        ])
            expect(
                typeof openParticipant({ namespace: 'poll', relay, archive })
                    .run,
            ).toBe('function');
        for (const archive of [
            { faultBound: 1, replicas: replicas.slice(0, 2) },
            { faultBound: -1, replicas },
            { faultBound: 0.5, replicas },
            { faultBound: 0, replicas: [] },
            {
                faultBound: 1,
                replicas: [replicas[0], replica(0), replicas[2]],
            },
            {
                faultBound: 1,
                replicas: [
                    replica(0, 'http://replica.example/archive/'),
                    ...replicas.slice(1),
                ],
            },
            {
                faultBound: 1,
                replicas: [
                    replica(0, 'ftp://replica.example/archive/'),
                    ...replicas.slice(1),
                ],
            },
            {
                faultBound: 1,
                replicas: [
                    replica(0, 'https://replica.example/archive/#poll'),
                    ...replicas.slice(1),
                ],
            },
            {
                faultBound: 1,
                replicas: [
                    replica(0, 'https://replica.example/archive/?poll=1'),
                    ...replicas.slice(1),
                ],
            },
            {
                faultBound: 1,
                replicas: [
                    replica(0, 'https://user@replica.example/archive/'),
                    ...replicas.slice(1),
                ],
            },
            {
                faultBound: 1,
                replicas: [replica(0, undefined, 1951), ...replicas.slice(1)],
            },
            {
                faultBound: 0,
                replicas: Array.from({ length: 33 }, (_unused, position) =>
                    replica(position),
                ),
            },
        ])
            expect(() =>
                openParticipant({ namespace: 'poll', relay, archive }),
            ).toThrow(TypeError);
    });

    it('emits declarations for the foundation verification result', () => {
        const declarations = readFileSync(
            new URL('../../dist/index.d.ts', import.meta.url),
            'utf8',
        );

        expect(declarations).toContain(
            'declare const verifyCanonicalManifest:',
        );
        expect(declarations).toContain(
            'Promise<FoundationManifestVerification>',
        );
    });
});
