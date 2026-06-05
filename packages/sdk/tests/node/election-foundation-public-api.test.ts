import {
    targetBoundShareSelectionProfileId,
    targetDecryptionProfileId,
    type CapabilityContext,
    type CapabilityDecision,
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
    ['verifyFirstValidPolicy', publicApiRuntimeRecord.verifyFirstValidPolicy],
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
            rosterSize: 20,
            targetBoundShareSelectionProfile: {
                profileId: targetBoundShareSelectionProfileId,
                certificateHash: 'target-bound-certificate-hash',
                targetDecryptionProfileId,
                targetBasisHash: 'target-basis-hash',
                decryptionShareQuorum: 9,
                minimumSharesForInterpolation: 7,
                minimumArrivalsForRobustDecode: 9,
                invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
                selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
            },
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
});
