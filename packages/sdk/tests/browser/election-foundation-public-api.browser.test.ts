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
const requiredPublicFunctionNames = [
    'deriveThresholdProfile',
    'validatePollSpec',
    'evaluateActionCapability',
    'deriveValidatedFirstValidOrder',
    'verifyBoardConsistency',
] as const;

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(
            expect.arrayContaining([...requiredPublicFunctionNames]),
        );
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('runs the deterministic election foundation without WASM-specific APIs', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 10,
        });

        expect(thresholdProfile.releaseQuorum).toBe(10);
        expect(
            validatePollSpec({
                pollId: 'browser-poll',
                question: 'Question',
                options: ['A', 'B', 'C'],
                topOptionCount: 2,
            }),
        ).toMatchObject({ ok: true });
        expect(
            evaluateActionCapability('VerifyEncryptedBallotProofs', {
                lifecycleState: 'votingClosed',
                thresholdProfile,
                pollSpecValid: true,
                localRosterAccepted: true,
                rosterExternalAcceptanceHash: 'accepted-roster-hash',
                actionContextRosterExternalAcceptanceHash:
                    'accepted-roster-hash',
                setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                turnoutCount: thresholdProfile.releaseQuorum,
                directProofTransportPresent: true,
            }),
        ).toEqual({
            allowed: true,
            action: 'VerifyEncryptedBallotProofs',
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
        expect(
            verifyBoardConsistency({
                ceremonyId: 'ceremony',
                boardPolicyHash: 'policy',
                expectedBoardPublicKeyHash: 'board-key',
                signedBoardHeads: [],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });
});
