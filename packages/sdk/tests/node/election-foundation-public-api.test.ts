import {
    cpadProfileId,
    targetBoundShareSelectionProfileId,
    type CapabilityContext,
    type CapabilityDecision,
    type FirstValidOrderingInput,
    type FirstValidOrderingVerification,
    type FutureProtocolOperationResult,
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
const verifyBridgeProof =
    publicApiRuntimeRecord.verifyBridgeProof as () => FutureProtocolOperationResult;

const requiredPublicFunctions = [
    [
        'deriveFrozenRosterProfile',
        publicApiRuntimeRecord.deriveFrozenRosterProfile,
    ],
    ['deriveLifecycleLabels', deriveLifecycleLabels],
    ['derivePollSpecDigest', publicApiRuntimeRecord.derivePollSpecDigest],
    ['deriveThresholdProfile', deriveThresholdProfile],
    [
        'deriveThresholdProfileDigest',
        publicApiRuntimeRecord.deriveThresholdProfileDigest,
    ],
    ['deriveValidatedFirstValidOrder', deriveValidatedFirstValidOrder],
    ['evaluateActionCapability', evaluateActionCapability],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
    ],
    ['isValidLifecycleTransition', isValidLifecycleTransition],
    ['validatePollSpec', validatePollSpec],
    [
        'verifyAggregateDerivationComponent',
        publicApiRuntimeRecord.verifyAggregateDerivationComponent,
    ],
    ['verifyBallotProof', publicApiRuntimeRecord.verifyBallotProof],
    ['verifyBoardConsistency', publicApiRuntimeRecord.verifyBoardConsistency],
    ['verifyBridgeProof', publicApiRuntimeRecord.verifyBridgeProof],
    ['verifyCastReceiptShell', publicApiRuntimeRecord.verifyCastReceiptShell],
    [
        'verifyClaimBearingBallotPackage',
        publicApiRuntimeRecord.verifyClaimBearingBallotPackage,
    ],
    ['verifyCloseRecordShell', publicApiRuntimeRecord.verifyCloseRecordShell],
    ['verifyFirstValidPolicy', publicApiRuntimeRecord.verifyFirstValidPolicy],
    [
        'verifyOneShotSharePolicy',
        publicApiRuntimeRecord.verifyOneShotSharePolicy,
    ],
    ['verifyReceiverKeyProof', publicApiRuntimeRecord.verifyReceiverKeyProof],
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

    it('keeps the public bridge verifier fail-closed until M9 relation closure', () => {
        expect(verifyBridgeProof()).toEqual({
            acceptedDigests: [],
            ok: false,
            operation: 'verifyBridgeProof',
            refusedObjects: [
                {
                    code: 'OperationUnavailable',
                    message:
                        'verifyBridgeProof is reserved for later protocol implementation and is not implemented in this package build.',
                },
            ],
            statusLabels: [],
            unresolvedReason: 'OperationUnavailable',
        });
    });

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 20,
            targetBoundShareSelectionProfile: {
                profileId: targetBoundShareSelectionProfileId,
                certificateDigest: 'target-bound-certificate-digest',
                cpadProfileId,
                targetBasisDigest: 'target-basis-digest',
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
            mheSecurityClosure: 'activeMalicious',
            localRosterAccepted: true,
            runtimeClaimGatePassed: true,
            bridgeBenchmarkReportPresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            kllpsCpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            evaluationProofClosureApplied: true,
            kllpsCpadClosureApplied: true,
            activeMaliciousClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
        expect(labels.modes).toEqual([]);
        expect(
            evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'evaluationProofVerified',
                thresholdProfile,
                pollSpecValid: true,
                localRosterAccepted: true,
                rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                actionContextRosterExternalAcceptanceDigest:
                    'accepted-roster-digest',
                targetFinalityAccepted: true,
                evaluationProofVerified: true,
                bridgeBenchmarkReportPresent: true,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
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
