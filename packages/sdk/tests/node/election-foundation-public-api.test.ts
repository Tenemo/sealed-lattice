import {
    targetBoundShareSelectionProfileId,
    targetDecryptionProfileId,
    type CapabilityContext,
    type CapabilityDecision,
    type FoundationTranscriptInput,
    type FoundationTranscriptVerification,
    type FirstValidOrderingInput,
    type FirstValidOrderingVerification,
    type LifecycleLabelInput,
    type LifecycleLabels,
    type LifecycleTransition,
    type PollSpecInput,
    type PollSpecValidation,
    type ProtocolAction,
    type ThresholdProfile,
    type ThresholdProfileInput,
    type TranscriptCoreFixture,
    type TranscriptCoreVerificationResult,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import {
    createFoundationTranscriptCoreFixture,
    createFoundationTranscriptFixture,
} from '#tests/support/foundation-transcript-fixture';

type DeriveThresholdProfile = (
    input: ThresholdProfileInput,
) => ThresholdProfile;
type ValidatePollSpec = (input: PollSpecInput) => PollSpecValidation;
type IsValidLifecycleTransition = (transition: LifecycleTransition) => boolean;
type DeriveLifecycleLabels = (input: LifecycleLabelInput) => LifecycleLabels;
type EvaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
) => CapabilityDecision;
type DeriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
) => FirstValidOrderingVerification;
type VerifyFoundationTranscript = (
    input: FoundationTranscriptInput,
) => FoundationTranscriptVerification;
type VerifyTranscriptCoreFixture = (
    fixture: TranscriptCoreFixture,
) => Promise<TranscriptCoreVerificationResult>;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveThresholdProfile =
    publicApiRuntimeRecord.deriveThresholdProfile as DeriveThresholdProfile;
const validatePollSpec =
    publicApiRuntimeRecord.validatePollSpec as ValidatePollSpec;
const isValidLifecycleTransition =
    publicApiRuntimeRecord.isValidLifecycleTransition as IsValidLifecycleTransition;
const deriveLifecycleLabels =
    publicApiRuntimeRecord.deriveLifecycleLabels as DeriveLifecycleLabels;
const evaluateActionCapability =
    publicApiRuntimeRecord.evaluateActionCapability as EvaluateActionCapability;
const deriveValidatedFirstValidOrder =
    publicApiRuntimeRecord.deriveValidatedFirstValidOrder as DeriveValidatedFirstValidOrder;
const verifyFoundationTranscript =
    publicApiRuntimeRecord.verifyFoundationTranscript as VerifyFoundationTranscript;
const verifyTranscriptCoreFixture =
    publicApiRuntimeRecord.verifyTranscriptCoreFixture as VerifyTranscriptCoreFixture;

const requiredPublicFunctions = [
    [
        'deriveFrozenRosterProfile',
        publicApiRuntimeRecord.deriveFrozenRosterProfile,
    ],
    ['deriveLifecycleLabels', deriveLifecycleLabels],
    ['derivePollSpecHash', publicApiRuntimeRecord.derivePollSpecHash],
    ['deriveThresholdProfile', deriveThresholdProfile],
    [
        'deriveThresholdProfileHash',
        publicApiRuntimeRecord.deriveThresholdProfileHash,
    ],
    ['deriveValidatedFirstValidOrder', deriveValidatedFirstValidOrder],
    ['evaluateActionCapability', evaluateActionCapability],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
    ],
    ['isValidLifecycleTransition', isValidLifecycleTransition],
    ['validatePollSpec', validatePollSpec],
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
    ['verifyTranscript', publicApiRuntimeRecord.verifyTranscript],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
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

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 10,
            targetBoundShareSelectionProfile: {
                profileId: targetBoundShareSelectionProfileId,
                certificateHash: 'target-bound-certificate-hash',
                targetDecryptionProfileId,
                targetBasisHash: 'target-basis-hash',
                decryptionShareQuorum: 9,
                minimumSharesForInterpolation: 4,
                minimumArrivalsForRobustDecode: 9,
                invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
                selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
            },
        });

        expect(thresholdProfile.privacyCorruptionBound).toBe(3);
        expect(
            validatePollSpec({
                pollId: 'poll',
                question: 'Question',
                options: ['A', 'B'],
                topOptionCount: 1,
            }),
        ).toMatchObject({ ok: true });
        expect(
            isValidLifecycleTransition({
                from: 'votingOpen',
                to: 'votingClosed',
            }),
        ).toBe(true);

        const labels = deriveLifecycleLabels({
            lifecycleState: 'fullyVerified',
            thresholdProfile,
            mheSecurityClosure: 'ActiveMalicious',
            localRosterAccepted: true,
            runtimeClaimGatePassed: true,
            directProofTransportPresent: true,
            mobileReplayEvidencePresent: true,
            targetDecryptionCertificatePresent: true,
            targetDecryptionClosureApplied: true,
            activeMaliciousClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
        expect(labels.primary).toContain('fullyVerified');
        expect(
            evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'targetFinalityReached',
                thresholdProfile,
                pollSpecValid: true,
                localRosterAccepted: true,
                rosterExternalAcceptanceHash: 'accepted-roster-hash',
                actionContextRosterExternalAcceptanceHash:
                    'accepted-roster-hash',
                targetFinalityAccepted: true,
                evaluatorReplaySucceeded: true,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
        expect(
            publicApiRuntimeRecord.verifyTranscript as () => {
                readonly ok: boolean;
                readonly refusedObjects: readonly {
                    readonly code: string;
                }[];
            },
        ).toBeTypeOf('function');
        expect(
            (
                publicApiRuntimeRecord.verifyTranscript as () => {
                    readonly ok: boolean;
                    readonly refusedObjects: readonly {
                        readonly code: string;
                    }[];
                }
            )(),
        ).toMatchObject({
            ok: false,
            refusedObjects: [
                expect.objectContaining({ code: 'OperationUnavailable' }),
            ],
        });
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextHash: 'context',
                selectionPolicyHash: 'policy',
                expectedSelectionPolicyHash: 'policy',
                currentRecoveryEpochMap: {
                    participant: {
                        signerIdentity: 'participant',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectHash: 'candidate',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextHash: 'context',
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }),
        ).toMatchObject({
            ok: true,
            orderedObjects: [
                expect.objectContaining({ objectHash: 'candidate' }),
            ],
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
        expect(
            (
                publicApiRuntimeRecord.verifyTranscript as () => {
                    readonly ok: boolean;
                    readonly refusedObjects: readonly {
                        readonly code: string;
                    }[];
                }
            )(),
        ).toMatchObject({
            ok: false,
            refusedObjects: [
                expect.objectContaining({ code: 'OperationUnavailable' }),
            ],
        });
    });

    it('matches foundation roots through the packaged transcript-core WASM verifier', async () => {
        const fixture = createFoundationTranscriptFixture();
        const transcriptCoreFixture = createFoundationTranscriptCoreFixture(
            fixture.expectedHashes,
        );
        const transcriptCoreVerification = await verifyTranscriptCoreFixture(
            transcriptCoreFixture,
        );

        expect(transcriptCoreFixture.baseClaimProfile).toBe(
            'FoundationTranscript',
        );
        expect(transcriptCoreFixture.mheSecurityClosure).toBe('FoundationOnly');
        expect(transcriptCoreVerification).toMatchObject({
            caseName: 'foundation-transcript-roots',
            label: 'TranscriptCoreVerified',
            objectHash512: transcriptCoreFixture.expectedObjectHash512,
            chunkRoot: transcriptCoreFixture.expectedChunkRoot,
            statusLabels: ['TranscriptCoreVerified'],
        });
    });
});
