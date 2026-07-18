import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
type DeriveCollectiveBgvSetupRosterHash = (
    entries: readonly Readonly<{
        readonly rosterPosition: number;
        readonly trusteeIdentity: string;
        readonly signingPublicKeyHash: string;
    }>[],
) => string;
type CreateCanonicalManifest = (input: {
    readonly options: readonly string[];
    readonly pollId: string;
    readonly question: string;
    readonly topOptionCount: number;
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
const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveCollectiveBgvSetupRosterHash =
    publicApiRuntimeRecord.deriveCollectiveBgvSetupRosterHash as DeriveCollectiveBgvSetupRosterHash;
const createCanonicalManifest =
    publicApiRuntimeRecord.createCanonicalManifest as CreateCanonicalManifest;
const verifyCanonicalManifest =
    publicApiRuntimeRecord.verifyCanonicalManifest as VerifyCanonicalManifest;
const expectedPublicRuntimeExportNames = [
    'createCanonicalActionDefinition',
    'createCanonicalBoardPolicy',
    'createCanonicalManifest',
    'deriveCollectiveBgvSetupRosterHash',
    'validatePollSpec',
    'verifyCanonicalActionContext',
    'verifyCanonicalActionDefinition',
    'verifyCanonicalBoardPolicy',
    'verifyCanonicalCeremonyContext',
    'verifyCanonicalManifest',
    'verifyCanonicalSuiteRecord',
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

    it('derives the setup roster hash used by setup package verification', () => {
        const expectedSetupRosterHash = deriveCanonicalObjectHash({
            objectType: 'CollectiveBgvSetupRoster',
            rosterEntries: [
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
            ],
        });

        expect(
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toBe(expectedSetupRosterHash);
    });

    it('creates and verifies canonical manifest bytes through the packaged kernel', async () => {
        const manifest = await createCanonicalManifest({
            options: Array.from(
                { length: 20 },
                (_value, optionIndex) => `Option ${String(optionIndex)}`,
            ),
            pollId: 'public-api-ceremony',
            question: 'Choose priorities',
            topOptionCount: 5,
        });

        expect(manifest.canonicalBytes.byteLength).toBeGreaterThan(0);
        expect(await verifyCanonicalManifest(manifest.canonicalBytes)).toEqual({
            isValid: true,
            value: { manifestHash: manifest.manifestHash },
        });
    });

    it('publishes setup verification as a result-only operation', () => {
        const declarations = readFileSync(
            new URL('../../dist/index.d.ts', import.meta.url),
            'utf8',
        );

        expect(declarations).not.toContain('derivePollSpecHash');
        expect(declarations).toContain(
            'declare const createCanonicalManifest:',
        );
    });
});
