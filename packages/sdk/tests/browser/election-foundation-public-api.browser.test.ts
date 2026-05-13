import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    CapabilityContext,
    CapabilityDecision,
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
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
type EvaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
) => CapabilityDecision;
type DeriveValidatedFirstComeOrder = (
    input: FirstComeOrderingInput,
) => FirstComeOrderingVerification;
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
const deriveValidatedFirstComeOrder =
    publicApiRuntimeRecord.deriveValidatedFirstComeOrder as DeriveValidatedFirstComeOrder;
const verifyBoardConsistency =
    publicApiRuntimeRecord.verifyBoardConsistency as VerifyBoardConsistency;

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions and keeps obvious raw APIs absent', () => {
        expect(typeof publicApiRuntimeRecord.deriveLifecycleLabels).toBe(
            'function',
        );
        expect(typeof deriveValidatedFirstComeOrder).toBe('function');
        expect(typeof deriveThresholdProfile).toBe('function');
        expect(typeof evaluateActionCapability).toBe('function');
        expect(
            typeof publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
        ).toBe('function');
        expect(typeof publicApiRuntimeRecord.isValidLifecycleTransition).toBe(
            'function',
        );
        expect(typeof validatePollSpec).toBe('function');
        expect(typeof verifyBoardConsistency).toBe('function');
        expect(typeof publicApiRuntimeRecord.verifyCastReceiptShell).toBe(
            'function',
        );
        expect(typeof publicApiRuntimeRecord.verifyCloseRecordShell).toBe(
            'function',
        );
        expect(typeof publicApiRuntimeRecord.verifyFirstComePolicy).toBe(
            'function',
        );
        expect(typeof publicApiRuntimeRecord.verifyRecoveryEpochUpdate).toBe(
            'function',
        );
        expect(
            typeof publicApiRuntimeRecord.verifyRosterManifestTranscript,
        ).toBe('function');
        expect(typeof publicApiRuntimeRecord.verifyTargetFinality).toBe(
            'function',
        );
        expect(typeof publicApiRuntimeRecord.verifyTranscriptCoreFixture).toBe(
            'function',
        );
        expect('thresholdDecrypt' in publicApiRuntimeRecord).toBe(false);
        expect('rawHEAdd' in publicApiRuntimeRecord).toBe(false);
        expect('rawNTT' in publicApiRuntimeRecord).toBe(false);
        expect(
            'verifyEvaluationReplayAttestationShell' in publicApiRuntimeRecord,
        ).toBe(false);
        expect(
            'verifyTargetAcceptedRecordShell' in publicApiRuntimeRecord,
        ).toBe(false);
        expect('verifyTopKDecryptionShareShell' in publicApiRuntimeRecord).toBe(
            false,
        );
        expect('createShamirPolynomial' in publicApiRuntimeRecord).toBe(false);
        expect('derivePlaintextTopKOracle' in publicApiRuntimeRecord).toBe(
            false,
        );
        expect('decodeSparseTopKTarget' in publicApiRuntimeRecord).toBe(false);
        expect('fieldModulus' in publicApiRuntimeRecord).toBe(false);
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
                lifecycleState: 'VotingClosed',
                thresholdProfile,
                pollSpecValid: true,
                setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                turnoutCount: thresholdProfile.releaseQuorum,
            }),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
        });
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
