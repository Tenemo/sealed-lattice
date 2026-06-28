import type {
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

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
type VerifyTranscript = () => {
    readonly ok: boolean;
    readonly refusedObjects: readonly {
        readonly code: string;
    }[];
};
type VerifyTargetDecryptionResult =
    () => Promise<publicApiRuntime.TargetDecryptionResultVerification>;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const verifyFoundationTranscript =
    publicApiRuntimeRecord.verifyFoundationTranscript as VerifyFoundationTranscript;
const verifyTranscriptCoreFixture =
    publicApiRuntimeRecord.verifyTranscriptCoreFixture as VerifyTranscriptCoreFixture;
const verifyTranscript =
    publicApiRuntimeRecord.verifyTranscript as VerifyTranscript;
const verifyTargetDecryptionResult =
    publicApiRuntimeRecord.verifyTargetDecryptionResult as VerifyTargetDecryptionResult;

const requiredPublicFunctions = [
    [
        'deriveFrozenRosterProfile',
        publicApiRuntimeRecord.deriveFrozenRosterProfile,
    ],
    ['derivePollSpecHash', publicApiRuntimeRecord.derivePollSpecHash],
    ['deriveThresholdProfile', publicApiRuntimeRecord.deriveThresholdProfile],
    [
        'deriveThresholdProfileHash',
        publicApiRuntimeRecord.deriveThresholdProfileHash,
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
    ['verifyTranscript', verifyTranscript],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
    ],
    ['verifySetupPackage', publicApiRuntimeRecord.verifySetupPackage],
    ['verifyPrivateVssShare', publicApiRuntimeRecord.verifyPrivateVssShare],
    [
        'verifyTargetDecryptionResult',
        publicApiRuntimeRecord.verifyTargetDecryptionResult,
    ],
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

    it('keeps reserved transcript verification fail closed', () => {
        expect(verifyTranscript()).toMatchObject({
            ok: false,
            refusedObjects: [
                expect.objectContaining({ code: 'OperationUnavailable' }),
            ],
        });
    });

    it('keeps public target-result verification fail closed', async () => {
        await expect(verifyTargetDecryptionResult()).resolves.toEqual({
            ok: false,
            operation: 'verifyTargetDecryptionResult',
            refusalReason: 'CompactVssPublicMaterialNotBinding',
        });
    });

    it('verifies the deterministic foundation transcript through the public package', () => {
        const fixture = createFoundationTranscriptFixture();
        const verification = verifyFoundationTranscript(fixture.input);

        expect(verification.ok).toBe(true);
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

    it('matches foundation roots through the packaged transcript-core WASM verifier', async () => {
        const fixture = createFoundationTranscriptFixture();
        const transcriptCoreFixture = createFoundationTranscriptCoreFixture(
            fixture.expectedHashes,
        );
        const transcriptCoreVerification = await verifyTranscriptCoreFixture(
            transcriptCoreFixture,
        );

        expect(transcriptCoreVerification).toMatchObject({
            ok: true,
            caseName: 'foundation-transcript-roots',
            objectHash512: transcriptCoreFixture.expectedObjectHash512,
            chunkRoot: transcriptCoreFixture.expectedChunkRoot,
        });
    });
});
