import type {
    CapabilityContext,
    CapabilityDecision,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ThresholdProfile,
    ThresholdProfileInput,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';
import publicSurface from '../../public-surface.json' with { type: 'json' };

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

const requiredPublicFunctions = [
    ['createBridgeProof', publicApiRuntimeRecord.createBridgeProof],
    ['deriveLifecycleLabels', deriveLifecycleLabels],
    ['deriveThresholdProfile', deriveThresholdProfile],
    ['deriveValidatedFirstValidOrder', deriveValidatedFirstValidOrder],
    ['evaluateActionCapability', evaluateActionCapability],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
    ],
    ['isValidLifecycleTransition', isValidLifecycleTransition],
    ['validatePollSpec', validatePollSpec],
    ['verifyBoardConsistency', publicApiRuntimeRecord.verifyBoardConsistency],
    ['verifyBridgeProof', publicApiRuntimeRecord.verifyBridgeProof],
    ['verifyCastReceiptShell', publicApiRuntimeRecord.verifyCastReceiptShell],
    ['verifyCloseRecordShell', publicApiRuntimeRecord.verifyCloseRecordShell],
    ['verifyFirstValidPolicy', publicApiRuntimeRecord.verifyFirstValidPolicy],
    [
        'verifyOneShotSharePolicy',
        publicApiRuntimeRecord.verifyOneShotSharePolicy,
    ],
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
    ['verifyTargetFinality', publicApiRuntimeRecord.verifyTargetFinality],
    ['verifyTranscript', publicApiRuntimeRecord.verifyTranscript],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
    ],
] as const;

const allowedRuntimeExports = [...publicSurface.runtimeExports].sort();
const forbiddenPublicKeys = publicSurface.forbiddenRuntimeExports;

describe('election foundation public package API in Node', () => {
    it('exposes only the safe runtime functions and keeps forbidden operations absent', () => {
        expect(
            requiredPublicFunctions.map(
                ([publicFunctionName]) => publicFunctionName,
            ),
        ).toEqual(publicSurface.runtimeExports);
        expect(Object.keys(publicApiRuntimeRecord).sort()).toEqual(
            allowedRuntimeExports,
        );
        for (const [
            publicFunctionName,
            publicFunction,
        ] of requiredPublicFunctions) {
            expect(typeof publicFunction, publicFunctionName).toBe('function');
        }
        for (const publicKey of forbiddenPublicKeys) {
            expect(publicKey in publicApiRuntimeRecord).toBe(false);
        }
    });

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 20,
        });

        expect(thresholdProfile.privacyCorruptionBound).toBe(6);
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
                from: 'VotingOpen',
                to: 'VotingClosed',
            }),
        ).toBe(true);
        const labels = deriveLifecycleLabels({
            lifecycleState: 'FullyVerifiedResult',
            thresholdProfile,
            mheSecurityStage: 'ActiveMalicious',
            localRosterExternallyAccepted: true,
            mobileClaimGatePassed: true,
            bridgeMobileCertificatePresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            cpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            stageXClosureApplied: true,
            stageCClosureApplied: true,
            stageAClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.resultClaimLabels).toEqual(['FullyVerifiedResult']);
        expect(labels.modes).toEqual([]);
        expect(
            evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'EvaluationProofVerified',
                thresholdProfile,
                pollSpecValid: true,
                localRosterExternallyAccepted: true,
                targetFinalityAccepted: true,
                evaluationProofVerified: true,
                bridgeMobileCertificatePresent: true,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
        expect(
            publicApiRuntimeRecord.createBridgeProof as () => {
                readonly ok: boolean;
                readonly refusedObjects: readonly {
                    readonly code: string;
                }[];
            },
        ).toBeTypeOf('function');
        expect(
            (
                publicApiRuntimeRecord.createBridgeProof as () => {
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
                requiredContextDigest: 'context',
                selectionPolicyDigest: 'policy',
                expectedSelectionPolicyDigest: 'policy',
                currentRecoveryEpochMap: {
                    participant: {
                        signerIdentity: 'participant',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectDigest: 'candidate',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest: 'context',
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }),
        ).toMatchObject({
            ok: true,
            orderedObjects: [
                expect.objectContaining({ objectDigest: 'candidate' }),
            ],
        });
    });
});
