import { describe, expect, it } from 'vitest';

import {
    type FirstValidOrderingInput,
    type RecoveryEpochMapEntry,
    type ValidatedFirstValidObject,
    contextHash,
    deriveProtocolHash,
    deriveValidatedFirstValidOrder,
    manifestPolicyHashes,
} from './election-foundation-test-helpers';

describe('first-valid ordering shells', () => {
    it('orders validated first-valid candidates and deduplicates retransmission', () => {
        const recoveryEpochState: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const objects: ValidatedFirstValidObject[] = [
            {
                objectHash: 'object-b',
                objectType: 'TargetFinalityRecord',
                boardSequence: 2,
                boardPosition: 1,
                signerIdentity: 'participant-2',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextHash,
                isByteIdenticalRetransmission: false,
            },
            {
                objectHash: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 1,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextHash,
                isByteIdenticalRetransmission: false,
            },
            {
                objectHash: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 3,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextHash,
                isByteIdenticalRetransmission: true,
            },
        ];
        const input: FirstValidOrderingInput = {
            objects,
            requiredContextHash: contextHash,
            selectionPolicyHash: manifestPolicyHashes.firstValidPolicyHash,
            expectedSelectionPolicyHash:
                manifestPolicyHashes.firstValidPolicyHash,
            currentRecoveryEpochMap: {
                'participant-1': recoveryEpochState,
                'participant-2': {
                    signerIdentity: 'participant-2',
                    currentRecoveryEpoch: 0,
                    currentDeviceEpoch: 0,
                },
            },
        };

        expect(deriveValidatedFirstValidOrder(input)).toMatchObject({
            ok: true,
            orderedObjects: [
                expect.objectContaining({ objectHash: 'object-a' }),
                expect.objectContaining({ objectHash: 'object-b' }),
            ],
        });

        const badInput: FirstValidOrderingInput = {
            ...input,
            selectionPolicyHash: deriveProtocolHash('ChallengeDomainHash', {
                payload: { policy: 'wrong' },
                purpose: 'fixture-first-valid-policy-v1',
            }),
            objects: [
                {
                    ...objects[0],
                    contextHash: deriveProtocolHash('ActionContextHash', {
                        context: 'wrong',
                    }),
                },
                objects[1],
                {
                    ...objects[1],
                    objectHash: 'object-stale',
                    recoveryEpoch: 9,
                    actionSequence: 1,
                },
                {
                    ...objects[1],
                    objectHash: 'object-c',
                },
            ],
        };

        expect(deriveValidatedFirstValidOrder(badInput).refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'FirstValidPolicyMismatch' }),
                expect.objectContaining({ code: 'FirstValidContextMismatch' }),
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
                expect.objectContaining({
                    code: 'ConflictingFirstValidObject',
                }),
            ]),
        );
    });

    it('rejects same-identity first-valid conflicts across action sequences', () => {
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextHash: contextHash,
                selectionPolicyHash: manifestPolicyHashes.firstValidPolicyHash,
                expectedSelectionPolicyHash:
                    manifestPolicyHashes.firstValidPolicyHash,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectHash: 'object-a',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextHash,
                        isByteIdenticalRetransmission: false,
                    },
                    {
                        objectHash: 'object-b',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 1,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 1,
                        contextHash,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ConflictingFirstValidObject',
                }),
            ]),
        );
    });

    it('rejects malformed first-valid candidate shape before ordering', () => {
        const baseCandidate: ValidatedFirstValidObject = {
            objectHash: 'object-a',
            objectType: 'TargetFinalityRecord',
            boardSequence: 1,
            boardPosition: 0,
            signerIdentity: 'participant-1',
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 0,
            contextHash,
            isByteIdenticalRetransmission: false,
        };
        const result = deriveValidatedFirstValidOrder({
            requiredContextHash: contextHash,
            selectionPolicyHash: manifestPolicyHashes.firstValidPolicyHash,
            expectedSelectionPolicyHash:
                manifestPolicyHashes.firstValidPolicyHash,
            currentRecoveryEpochMap: {
                'participant-1': {
                    signerIdentity: 'participant-1',
                    currentRecoveryEpoch: 0,
                    currentDeviceEpoch: 0,
                },
            },
            objects: [
                {
                    ...baseCandidate,
                    objectHash: 'negative-position',
                    boardPosition: -1,
                },
                {
                    ...baseCandidate,
                    objectHash: 'unsafe-action-sequence',
                    actionSequence: Number.MAX_SAFE_INTEGER + 1,
                },
                {
                    ...baseCandidate,
                    objectHash: '',
                },
                {
                    ...baseCandidate,
                    objectHash: 'malformed-retransmission-flag',
                    isByteIdenticalRetransmission: 'yes' as unknown as boolean,
                },
            ],
        });

        expect(result.ok).toBe(false);
        expect(result.orderedObjects).toEqual([]);
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object sequence and epoch fields must be non-negative safe integers.',
                }),
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object string fields must be non-empty canonical strings.',
                }),
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object retransmission flag must be boolean.',
                }),
            ]),
        );
    });
});
