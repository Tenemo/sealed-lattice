import { describe, expect, it } from 'vitest';

import {
    createDesktopBrowserProofTransportArtifact,
    createDesktopBrowserProofTransportManifest,
    encodeDesktopBrowserProofTransportBytesAsBase64,
    encodeDesktopBrowserProofTransportManifest,
    parseDesktopBrowserProofDeterministicParityBinding,
    parseDesktopBrowserProofEvidenceWorkerStartMessage,
    parseDesktopBrowserProofTransportManifest,
    parseDesktopBrowserProofTransportManifestAuthenticationBindings,
    readDesktopBrowserProofTransportArtifact,
    readDesktopBrowserProofTransportManifest,
    resolveDesktopBrowserProofTransportArtifactPath,
    serializeDesktopBrowserProofTransportManifestAuthenticationBindings,
    summarizeDesktopBrowserProofTransportBytes,
    validateDesktopBrowserProofTransportArtifactBytes,
} from '../support/selected-proof-runtime-evidence-transport.js';

import {
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole,
    desktopBrowserProofTransportGenerationCaseIdentifiers,
} from '#tests/support/desktop-browser-proof-evidence-catalog';

const wasmSha256Hex = '12'.repeat(32);
const suiteId = '34'.repeat(64);
const manifestSha512Hex = '56'.repeat(64);
const transportDirectoryPath = 'C:\\repo\\logs\\run\\transport';

const createProofBytes = (caseIndex: number): Uint8Array<ArrayBuffer> =>
    Uint8Array.from([caseIndex + 1, 255 - caseIndex, (caseIndex * 37) % 256]);

const createExactArtifacts = () =>
    desktopBrowserProofTransportGenerationCaseIdentifiers.map(
        (generationCaseIdentifier, caseIndex) =>
            createDesktopBrowserProofTransportArtifact({
                generationCaseIdentifier,
                generationSessionIdentifier: 'chromium-generation',
                proofBytes: createProofBytes(caseIndex),
                runOrdinal: 1,
            }),
    );

const createExactManifest = () =>
    createDesktopBrowserProofTransportManifest({
        artifacts: createExactArtifacts(),
        generationSessionIdentifier: 'chromium-generation',
        suiteId,
        wasmSha256Hex,
    });

describe('Selected proof runtime evidence transport', () => {
    it('requires exact native and WebAssembly deterministic proof parity', () => {
        const binding = {
            deterministicCoinBindingSha512Hex: '11'.repeat(64),
            nativeProofByteLength: 5_242_880,
            nativeProofSha512Hex: '22'.repeat(64),
            wasmProofByteLength: 5_242_880,
            wasmProofSha512Hex: '22'.repeat(64),
        };
        expect(
            parseDesktopBrowserProofDeterministicParityBinding(binding),
        ).toEqual(binding);
        expect(() =>
            parseDesktopBrowserProofDeterministicParityBinding({
                ...binding,
                wasmProofByteLength: binding.wasmProofByteLength - 1,
            }),
        ).toThrow(/not identical/u);
        expect(() =>
            parseDesktopBrowserProofDeterministicParityBinding({
                ...binding,
                wasmProofSha512Hex: '23'.repeat(64),
            }),
        ).toThrow(/not identical/u);
        const {
            deterministicCoinBindingSha512Hex: _omitted,
            ...incompleteBinding
        } = binding;
        expect(() =>
            parseDesktopBrowserProofDeterministicParityBinding(
                incompleteBinding,
            ),
        ).toThrow(/malformed/u);
    });

    it('confines canonical manifest and artifact paths to the run directory', () => {
        const artifact = createExactArtifacts()[0];
        expect(artifact).toBeDefined();
        expect(
            resolveDesktopBrowserProofTransportArtifactPath(
                transportDirectoryPath,
                artifact,
                'chromium-generation',
            ),
        ).toBe(
            `${transportDirectoryPath}\\chromium-generation-aggregate-threshold-share-generation-run-1.proof`,
        );

        for (const unsafeDirectoryPath of [
            'relative\\transport',
            'C:\\repo\\logs\\..\\outside',
            'C:\\repo\\logs\\run\\transport\\',
            '/repo/logs//transport',
            '/repo/logs/../outside',
        ]) {
            expect(() =>
                resolveDesktopBrowserProofTransportArtifactPath(
                    unsafeDirectoryPath,
                    artifact,
                    'chromium-generation',
                ),
            ).toThrow(/normalized absolute|must be absolute/u);
        }

        expect(() =>
            resolveDesktopBrowserProofTransportArtifactPath(
                transportDirectoryPath,
                {
                    ...artifact,
                    fileName: '..\\outside.proof',
                },
                'chromium-generation',
            ),
        ).toThrow(/file name is not canonical/u);
        expect(() =>
            resolveDesktopBrowserProofTransportArtifactPath(
                transportDirectoryPath,
                {
                    ...artifact,
                    fileName: '/outside.proof',
                },
                'chromium-generation',
            ),
        ).toThrow(/file name is not canonical/u);
    });

    it('accepts only the exact canonical manifest and authenticated binding', async () => {
        const manifestText = encodeDesktopBrowserProofTransportManifest(
            createExactManifest(),
        );
        expect(
            encodeDesktopBrowserProofTransportManifest(
                parseDesktopBrowserProofTransportManifest(manifestText),
            ),
        ).toBe(manifestText);
        const actualManifestSha512Hex =
            summarizeDesktopBrowserProofTransportBytes(
                new TextEncoder().encode(manifestText),
            ).sha512Hex;
        await expect(
            readDesktopBrowserProofTransportManifest({
                expectedManifestSha512Hex: actualManifestSha512Hex,
                expectedSuiteId: suiteId,
                expectedWasmSha256Hex: wasmSha256Hex,
                generationSessionIdentifier: 'chromium-generation',
                readFile: () => Promise.resolve(manifestText),
                transportDirectoryPath,
            }),
        ).resolves.toMatchObject({
            manifestSha512Hex: actualManifestSha512Hex,
        });
        expect(() =>
            parseDesktopBrowserProofTransportManifest(
                JSON.stringify(JSON.parse(manifestText), undefined, 2),
            ),
        ).toThrow(/not canonically encoded/u);
        expect(() =>
            parseDesktopBrowserProofTransportManifest('{"artifacts":[]}'),
        ).toThrow(/malformed or has an unsupported schema/u);

        const authentication =
            serializeDesktopBrowserProofTransportManifestAuthenticationBindings(
                {
                    'chromium-generation': manifestSha512Hex,
                    'firefox-generation': '78'.repeat(64),
                },
            );
        expect(
            parseDesktopBrowserProofTransportManifestAuthenticationBindings(
                authentication,
            ),
        ).toEqual({
            'chromium-generation': manifestSha512Hex,
            'firefox-generation': '78'.repeat(64),
        });
        expect(() =>
            parseDesktopBrowserProofTransportManifestAuthenticationBindings(
                '{"firefox-generation":"' +
                    '78'.repeat(64) +
                    '","chromium-generation":"' +
                    manifestSha512Hex +
                    '"}',
            ),
        ).toThrow(/not canonical/u);

        await expect(
            readDesktopBrowserProofTransportManifest({
                generationSessionIdentifier: 'chromium-generation',
                readFile: () => Promise.reject(new Error('missing')),
                transportDirectoryPath,
            }),
        ).rejects.toThrow(/missing or unreadable/u);
        await expect(
            readDesktopBrowserProofTransportManifest({
                expectedManifestSha512Hex: manifestSha512Hex,
                generationSessionIdentifier: 'chromium-generation',
                readFile: () => Promise.resolve(manifestText),
                transportDirectoryPath,
            }),
        ).rejects.toThrow(/failed its authenticated SHA-512 binding/u);
    });

    it('rejects missing artifacts and every length or digest mismatch', async () => {
        const artifact = createExactArtifacts()[0];
        expect(artifact).toBeDefined();
        const exactArtifact = artifact;
        const proofBytes = createProofBytes(0);
        expect(() =>
            validateDesktopBrowserProofTransportArtifactBytes(
                exactArtifact,
                proofBytes,
            ),
        ).not.toThrow();
        expect(() =>
            validateDesktopBrowserProofTransportArtifactBytes(
                { ...exactArtifact, canonicalProofByteLength: 4 },
                proofBytes,
            ),
        ).toThrow(/length or SHA-512 binding/u);
        expect(() =>
            validateDesktopBrowserProofTransportArtifactBytes(
                {
                    ...exactArtifact,
                    canonicalProofSha512Hex: 'ab'.repeat(64),
                },
                proofBytes,
            ),
        ).toThrow(/length or SHA-512 binding/u);

        await expect(
            readDesktopBrowserProofTransportArtifact({
                artifact: exactArtifact,
                generationSessionIdentifier: 'chromium-generation',
                readFile: () => Promise.reject(new Error('missing')),
                transportDirectoryPath,
            }),
        ).rejects.toThrow(/missing or unreadable/u);
        await expect(
            readDesktopBrowserProofTransportArtifact({
                artifact: exactArtifact,
                generationSessionIdentifier: 'chromium-generation',
                readFile: () =>
                    Promise.resolve(
                        encodeDesktopBrowserProofTransportBytesAsBase64(
                            Uint8Array.from([9, 9, 9]),
                        ),
                    ),
                transportDirectoryPath,
            }),
        ).rejects.toThrow(/length or SHA-512 binding/u);
    });

    it('rejects role mixing, wrong proof ownership, and changed proof bytes', () => {
        expect(
            parseDesktopBrowserProofEvidenceWorkerStartMessage({
                caseIdentifiers:
                    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.generation,
                command: 'generate-selected-proof-runtime-evidence',
                generationSessionIdentifier: 'chromium-generation',
                ownershipRole: 'generation',
                wasmSha256Hex,
            }),
        ).toMatchObject({ ownershipRole: 'generation' });
        expect(() =>
            parseDesktopBrowserProofEvidenceWorkerStartMessage({
                caseIdentifiers:
                    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.verification,
                command: 'generate-selected-proof-runtime-evidence',
                generationSessionIdentifier: 'chromium-generation',
                ownershipRole: 'generation',
                proofBytes: Uint8Array.from([1]),
                wasmSha256Hex,
            }),
        ).toThrow(/role-mixed/u);

        const proofBytes = Uint8Array.from([1, 7, 19]);
        const proofSummary =
            summarizeDesktopBrowserProofTransportBytes(proofBytes);
        const verificationMessage = {
            canonicalProofByteLength: proofSummary.byteLength,
            canonicalProofSha512Hex: proofSummary.sha512Hex,
            command: 'verify-selected-proof-runtime-evidence',
            generationCaseIdentifier: 'same-secret-generation',
            generationRunOrdinal: 1,
            generationSessionIdentifier: 'firefox-generation',
            ownershipRole: 'verification',
            proofBytes,
            suiteId,
            verificationCaseIdentifier: 'same-secret-verification',
            verificationRunOrdinal: 2,
            verificationSessionIdentifier: 'webkit-verification',
            wasmSha256Hex,
        } as const;
        expect(
            parseDesktopBrowserProofEvidenceWorkerStartMessage(
                verificationMessage,
            ),
        ).toMatchObject({ ownershipRole: 'verification' });
        expect(() =>
            parseDesktopBrowserProofEvidenceWorkerStartMessage({
                ...verificationMessage,
                verificationCaseIdentifier: 'ballot-validity-verification',
            }),
        ).toThrow(/does not own/u);
        expect(() =>
            parseDesktopBrowserProofEvidenceWorkerStartMessage({
                ...verificationMessage,
                canonicalProofByteLength: proofSummary.byteLength + 1,
            }),
        ).toThrow(/do not match their transport binding/u);
        expect(() =>
            parseDesktopBrowserProofEvidenceWorkerStartMessage({
                ...verificationMessage,
                ownershipRole: 'generation',
            }),
        ).toThrow(/role-mixed/u);
    });
});
