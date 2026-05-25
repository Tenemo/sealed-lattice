import { describe, expect, it } from 'vitest';

import {
    type FirstValidOrderingInput,
    type RecoveryEpochMapEntry,
    type ValidatedFirstValidObject,
    contextDigest,
    deriveProtocolDigest,
    deriveValidatedFirstValidOrder,
    manifestPolicyDigests,
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
                objectDigest: 'object-b',
                objectType: 'TargetFinalityRecord',
                boardSequence: 2,
                boardPosition: 1,
                signerIdentity: 'participant-2',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 1,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 3,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: true,
            },
        ];
        const input: FirstValidOrderingInput = {
            objects,
            requiredContextDigest: contextDigest,
            selectionPolicyDigest: manifestPolicyDigests.firstValidPolicyDigest,
            expectedSelectionPolicyDigest:
                manifestPolicyDigests.firstValidPolicyDigest,
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
                expect.objectContaining({ objectDigest: 'object-a' }),
                expect.objectContaining({ objectDigest: 'object-b' }),
            ],
        });

        const badInput: FirstValidOrderingInput = {
            ...input,
            selectionPolicyDigest: deriveProtocolDigest(
                'FirstValidPolicyDigest',
                { policy: 'wrong' },
            ),
            objects: [
                {
                    ...objects[0],
                    contextDigest: deriveProtocolDigest('ActionContextDigest', {
                        context: 'wrong',
                    }),
                },
                objects[1],
                {
                    ...objects[1],
                    objectDigest: 'object-stale',
                    recoveryEpoch: 9,
                    actionSequence: 1,
                },
                {
                    ...objects[1],
                    objectDigest: 'object-c',
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
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectDigest: 'object-a',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                    {
                        objectDigest: 'object-b',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 1,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 1,
                        contextDigest,
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
            objectDigest: 'object-a',
            objectType: 'TargetFinalityRecord',
            boardSequence: 1,
            boardPosition: 0,
            signerIdentity: 'participant-1',
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 0,
            contextDigest,
            isByteIdenticalRetransmission: false,
        };
        const result = deriveValidatedFirstValidOrder({
            requiredContextDigest: contextDigest,
            selectionPolicyDigest: manifestPolicyDigests.firstValidPolicyDigest,
            expectedSelectionPolicyDigest:
                manifestPolicyDigests.firstValidPolicyDigest,
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
                    objectDigest: 'negative-position',
                    boardPosition: -1,
                },
                {
                    ...baseCandidate,
                    objectDigest: 'unsafe-action-sequence',
                    actionSequence: Number.MAX_SAFE_INTEGER + 1,
                },
                {
                    ...baseCandidate,
                    objectDigest: '',
                },
                {
                    ...baseCandidate,
                    objectDigest: 'malformed-retransmission-flag',
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
