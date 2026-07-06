import type {
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import {
    createFoundationTranscriptCoreFixture,
    createFoundationTranscriptFixture,
} from '#tests/support/foundation-transcript-fixture';

type VerifyFoundationTranscript = (
    input: FoundationTranscriptInput,
) => FoundationTranscriptVerification;
type VerifyTranscriptCoreFixture = (
    fixture: TranscriptCoreFixture,
) => Promise<TranscriptCoreVerificationResult>;
type DeriveCollectiveBgvSetupRosterHash = (
    entries: readonly Readonly<{
        readonly rosterPosition: number;
        readonly trusteeIdentity: string;
        readonly signingPublicKeyHash: string;
    }>[],
) => string;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const verifyFoundationTranscript =
    publicApiRuntimeRecord.verifyFoundationTranscript as VerifyFoundationTranscript;
const verifyTranscriptCoreFixture =
    publicApiRuntimeRecord.verifyTranscriptCoreFixture as VerifyTranscriptCoreFixture;
const deriveCollectiveBgvSetupRosterHash =
    publicApiRuntimeRecord.deriveCollectiveBgvSetupRosterHash as DeriveCollectiveBgvSetupRosterHash;

const requiredPublicFunctions = [
    [
        'deriveCollectiveBgvSetupRosterHash',
        publicApiRuntimeRecord.deriveCollectiveBgvSetupRosterHash,
    ],
    [
        'deriveFrozenRosterParameters',
        publicApiRuntimeRecord.deriveFrozenRosterParameters,
    ],
    ['derivePollSpecHash', publicApiRuntimeRecord.derivePollSpecHash],
    [
        'deriveThresholdParameters',
        publicApiRuntimeRecord.deriveThresholdParameters,
    ],
    [
        'deriveThresholdParametersHash',
        publicApiRuntimeRecord.deriveThresholdParametersHash,
    ],
    [
        'deriveValidatedFirstValidOrder',
        publicApiRuntimeRecord.deriveValidatedFirstValidOrder,
    ],
    [
        'evaluateActionCapability',
        publicApiRuntimeRecord.evaluateActionCapability,
    ],
    [
        'createSetupPackageVerificationInput',
        publicApiRuntimeRecord.createSetupPackageVerificationInput,
    ],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
    ],
    [
        'isValidLifecycleTransition',
        publicApiRuntimeRecord.isValidLifecycleTransition,
    ],
    ['validatePollSpec', publicApiRuntimeRecord.validatePollSpec],
    ['verifyBoardConsistency', publicApiRuntimeRecord.verifyBoardConsistency],
    ['verifyCastReceiptShell', publicApiRuntimeRecord.verifyCastReceiptShell],
    ['verifyCloseRecordShell', publicApiRuntimeRecord.verifyCloseRecordShell],
    [
        'verifyRecoveryEpochUpdate',
        publicApiRuntimeRecord.verifyRecoveryEpochUpdate,
    ],
    [
        'verifyRosterExternalAcceptance',
        publicApiRuntimeRecord.verifyRosterExternalAcceptance,
    ],
    [
        'verifyRosterManifestTranscript',
        publicApiRuntimeRecord.verifyRosterManifestTranscript,
    ],
    ['verifyFoundationTranscript', verifyFoundationTranscript],
    ['verifyTargetFinality', publicApiRuntimeRecord.verifyTargetFinality],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
    ],
    ['verifySetupPackage', publicApiRuntimeRecord.verifySetupPackage],
    ['verifyPrivateVssShare', publicApiRuntimeRecord.verifyPrivateVssShare],
] as const;

const requiredPublicFunctionNames = requiredPublicFunctions
    .map(([publicFunctionName]) => publicFunctionName)
    .sort();

describe('election foundation public package API in Node', () => {
    it('exposes safe runtime functions and keeps runtime exports callable', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(
            expect.arrayContaining(requiredPublicFunctionNames),
        );
        for (const [
            publicFunctionName,
            publicFunction,
        ] of requiredPublicFunctions) {
            expect(typeof publicFunction, publicFunctionName).toBe('function');
        }
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('verifies the deterministic foundation transcript through the public package', () => {
        const fixture = createFoundationTranscriptFixture();
        const verification = verifyFoundationTranscript(fixture.input);

        expect(verification.isValid).toBe(true);
        expect(verification.electionManifestHash).toBe(
            fixture.expectedHashes.electionManifestHash,
        );
        expect(verification.rosterExternalAcceptanceHash).toBe(
            fixture.expectedHashes.rosterExternalAcceptanceHash,
        );
        expect(verification.firstValidOrderHash).toBe(
            fixture.expectedHashes.firstValidOrderHash,
        );
        expect(verification.targetFinalityRecordHash).toBe(
            fixture.expectedHashes.targetFinalityRecordHash,
        );
        expect(verification.nextRequiredEvidence).toEqual(
            expect.arrayContaining([
                'direct ballot proof verification',
                'decoded result verification',
                'supported-phone mobile runtime evidence',
            ]),
        );

        const wrongTopCountInput = {
            ...fixture.input,
            expectedTopOptionCount: fixture.input.expectedTopOptionCount - 1,
        };
        expect(
            verifyFoundationTranscript(wrongTopCountInput).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetFinalityPolicyMismatch',
                }),
            ]),
        );
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

    it('matches foundation roots through the packaged transcript-core WASM verifier', async () => {
        const fixture = createFoundationTranscriptFixture();
        const transcriptCoreFixture = createFoundationTranscriptCoreFixture(
            fixture.expectedHashes,
        );
        const transcriptCoreVerification = await verifyTranscriptCoreFixture(
            transcriptCoreFixture,
        );

        expect(transcriptCoreVerification).toMatchObject({
            isValid: true,
            caseName: 'foundation-transcript-roots',
            objectHash512: transcriptCoreFixture.expectedObjectHash512,
            chunkRoot: transcriptCoreFixture.expectedChunkRoot,
        });
    });
});
