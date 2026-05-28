import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    CapabilityContext,
    CapabilityDecision,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
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
type EvaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
) => CapabilityDecision;
type DeriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
) => FirstValidOrderingVerification;
type VerifyBoardConsistency = (
    input: BoardConsistencyInput,
) => BoardConsistencyVerification;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveThresholdProfile =
    publicApiRuntimeRecord.deriveThresholdProfile as DeriveThresholdProfile;
const validatePollSpec =
    publicApiRuntimeRecord.validatePollSpec as ValidatePollSpec;
const evaluateActionCapability =
    publicApiRuntimeRecord.evaluateActionCapability as EvaluateActionCapability;
const deriveValidatedFirstValidOrder =
    publicApiRuntimeRecord.deriveValidatedFirstValidOrder as DeriveValidatedFirstValidOrder;
const verifyBoardConsistency =
    publicApiRuntimeRecord.verifyBoardConsistency as VerifyBoardConsistency;
const expectedRuntimeExports = [
    'deriveFrozenRosterProfile',
    'deriveLifecycleLabels',
    'derivePollSpecDigest',
    'deriveThresholdProfile',
    'deriveThresholdProfileDigest',
    'deriveValidatedFirstValidOrder',
    'evaluateActionCapability',
    'isActionCurrentForRecoveryEpoch',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyAggregateDerivationComponent',
    'verifyBallotProof',
    'verifyBoardConsistency',
    'verifyBridgeProof',
    'verifyCastReceiptShell',
    'verifyClaimBearingBallotPackage',
    'verifyCloseRecordShell',
    'verifyFirstValidPolicy',
    'verifyOneShotSharePolicy',
    'verifyReceiverKeyProof',
    'verifyRecoveryEpochUpdate',
    'verifyRosterExternalAcceptance',
    'verifyRosterManifestTranscript',
    'verifyTargetFinality',
    'verifyTranscript',
    'verifyTranscriptCoreFixture',
] as const;

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions and keeps obvious raw APIs absent', () => {
        expect(Object.keys(publicApiRuntimeRecord).sort()).toEqual([
            ...expectedRuntimeExports,
        ]);
        for (const publicFunctionName of expectedRuntimeExports) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
        for (const publicKey of publicSurface.forbiddenRuntimeExports) {
            expect(publicKey in publicApiRuntimeRecord).toBe(false);
        }
    });

    it('runs the deterministic election foundation without WASM-specific APIs', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 20,
        });

        expect(thresholdProfile.releaseQuorum).toBe(14);
        expect(
            validatePollSpec({
                pollId: 'browser-poll',
                question: 'Question',
                options: ['A', 'B', 'C'],
                topOptionCount: 2,
            }),
        ).toMatchObject({ ok: true });
        expect(
            evaluateActionCapability('DeriveAggregateContribution', {
                lifecycleState: 'votingClosed',
                thresholdProfile,
                pollSpecValid: true,
                localRosterAccepted: true,
                rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                actionContextRosterExternalAcceptanceDigest:
                    'accepted-roster-digest',
                setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                turnoutCount: thresholdProfile.releaseQuorum,
                bridgeBenchmarkReportPresent: true,
                bridgeProverCertificatePresent: true,
            }),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
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
        expect(
            verifyBoardConsistency({
                ceremonyId: 'ceremony',
                boardPolicyDigest: 'policy',
                expectedBoardPublicKeyDigest: 'board-key',
                signedBoardHeads: [],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });
});
