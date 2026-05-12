import type {
    CapabilityContext,
    CapabilityDecision,
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
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
type DeriveValidatedFirstComeOrder = (
    input: FirstComeOrderingInput,
) => FirstComeOrderingVerification;

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
const deriveValidatedFirstComeOrder =
    publicApiRuntimeRecord.deriveValidatedFirstComeOrder as DeriveValidatedFirstComeOrder;

const requiredPublicFunctions = [
    ['deriveValidatedFirstComeOrder', deriveValidatedFirstComeOrder],
    ['deriveLifecycleLabels', deriveLifecycleLabels],
    ['deriveThresholdProfile', deriveThresholdProfile],
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
    ['verifyFirstComePolicy', publicApiRuntimeRecord.verifyFirstComePolicy],
    [
        'verifyRecoveryEpochUpdate',
        publicApiRuntimeRecord.verifyRecoveryEpochUpdate,
    ],
    [
        'verifyRosterManifestTranscript',
        publicApiRuntimeRecord.verifyRosterManifestTranscript,
    ],
    ['verifyTargetFinality', publicApiRuntimeRecord.verifyTargetFinality],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
    ],
] as const;

const allowedRuntimeExports = requiredPublicFunctions
    .map(([publicFunctionName]) => publicFunctionName)
    .sort();

const forbiddenPublicKeys = [
    'getShare',
    'exportShare',
    'exportSecretKey',
    'importSecretKey',
    'setSecretKey',
    'thresholdDecrypt',
    'partialDecrypt',
    'partialDecryptWithoutTarget',
    'decryptToFile',
    'decryptToString',
    'rawHEAdd',
    'rawHEMul',
    'rawHERelin',
    'rawHERotate',
    'rawNTT',
    'rawRNSLimbAccess',
    'setNoiseFloodSigma',
    'setSmudgingDistribution',
    'bootstrap',
    'decryptAggregateShare',
    'decryptExactSum',
    'decryptRank',
    'decryptComparisonBit',
    'decryptIntermediateWire',
    'verifyEvaluationReplayAttestationShell',
    'verifyTargetAcceptedRecordShell',
    'verifyTopKDecryptionShareShell',
    'createShamirPolynomial',
    'derivePlaintextTopKOracle',
    'decodeSparseTopKTarget',
    'fieldModulus',
];

describe('election foundation public package API in Node', () => {
    it('exposes only the safe runtime functions and keeps forbidden operations absent', () => {
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
            lifecycleState: 'ResultComputedAuditable',
            thresholdProfile,
            mheSecurityStage: 'ActiveMalicious',
            mobileClaimGatePassed: true,
        });

        expect(labels.resultClaimLabel).toBe('ResultComputedAuditable');
        expect(labels.modes).toEqual([]);
        expect(
            evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'EvaluationReplayOpen',
                thresholdProfile,
                pollSpecValid: true,
                targetFinalityAccepted: true,
                replayAttestationCount: thresholdProfile.evaluationReplayQuorum,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
        expect(
            deriveValidatedFirstComeOrder({
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
                candidates: [
                    {
                        objectDigest: 'candidate',
                        objectType: 'TargetFinalityRecord',
                        boardSeq: 1,
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
            orderedCandidates: [
                expect.objectContaining({ objectDigest: 'candidate' }),
            ],
        });
    });
});
