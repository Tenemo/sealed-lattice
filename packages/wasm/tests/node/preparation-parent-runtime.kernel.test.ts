import { describe, expect, it } from 'vitest';

import { openActionKeySetRuntime } from '../../src/action-key-set-runtime.js';
import {
    actionSignatureKeyByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
    type PairEncryptionKeyPair,
} from '../../src/pair-encryption-runtime.js';
import {
    actionSignatureCarrierByteLength,
    openPreparationParentRuntime,
    preparationParentBodyByteLength,
} from '../../src/preparation-parent-runtime.js';
import {
    openPrivatePreparationBodyRuntime,
    privatePreparationBodyByteLength,
    privatePreparationPlaintextByteLength,
    type PrivatePreparationContextInput,
} from '../../src/private-preparation-body-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const participantCount = 10;
const senderPosition = 2;
const recipientPosition = 8;

const pseudorandomBytes = (length: number, seed: bigint): Uint8Array => {
    let state = seed;
    const mask = (1n << 64n) - 1n;
    return Uint8Array.from({ length }, () => {
        state ^= (state << 13n) & mask;
        state ^= state >> 7n;
        state ^= (state << 17n) & mask;
        state &= mask;
        return Number(state & 0xffn);
    });
};

describe('preparation parent scalar WASM runtime', () => {
    it('verifies the exact signed manifest before admitting a private carrier', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const keySetRuntime = openActionKeySetRuntime(kernel);
        const bodyRuntime = openPrivatePreparationBodyRuntime(kernel);
        const parentRuntime = openPreparationParentRuntime(kernel);
        const actionProposalIdentity = pseudorandomBytes(64, 0x4a31n);
        const actionKeySetBodies: Uint8Array[] = [];
        let senderPreparationSecretKey: Uint8Array | undefined;
        let incomingPair: PairEncryptionKeyPair | undefined;

        for (
            let rosterPosition = 0;
            rosterPosition < participantCount;
            rosterPosition += 1
        ) {
            const signatureSecretKeys = Array.from(
                { length: 4 },
                (_, purpose) =>
                    pseudorandomBytes(
                        actionSignatureKeyByteLength,
                        0x1000n + BigInt(rosterPosition * 16 + purpose),
                    ),
            );
            const signatureVerificationKeys = signatureSecretKeys.map(
                (secret) => signatureRuntime.deriveVerificationKey(secret),
            );
            const pairKeys = Array.from(
                { length: participantCount - 1 },
                (_, keyIndex) =>
                    pairRuntime.generateKeyPair(
                        pseudorandomBytes(
                            pairEncryptionKeyGenerationRandomnessByteLength,
                            0x9000n + BigInt(rosterPosition * 32 + keyIndex),
                        ),
                    ),
            );
            if (rosterPosition === senderPosition) {
                senderPreparationSecretKey = signatureSecretKeys[0];
            }
            if (rosterPosition === recipientPosition) {
                const senderKeyIndex =
                    senderPosition < recipientPosition
                        ? senderPosition
                        : senderPosition - 1;
                incomingPair = pairKeys[senderKeyIndex];
            }
            actionKeySetBodies.push(
                keySetRuntime.encode({
                    participantCount,
                    proposalIdentity: actionProposalIdentity,
                    rosterPosition,
                    nonce: pseudorandomBytes(
                        32,
                        0xa700n + BigInt(rosterPosition),
                    ),
                    actionSignatureVerificationKeys: signatureVerificationKeys,
                    pairEncryptionKeys: pairKeys.map(
                        (pair) => pair.encryptionKey,
                    ),
                }).body,
            );
        }

        const actionKeySetRosterIdentity = keySetRuntime.verifyCompleteRoster(
            participantCount,
            actionKeySetBodies,
        );
        expect(senderPreparationSecretKey).toBeDefined();
        expect(incomingPair).toBeDefined();
        if (
            senderPreparationSecretKey === undefined ||
            incomingPair === undefined
        ) {
            throw new Error('test key custody was not constructed');
        }

        const context: PrivatePreparationContextInput = {
            participantCount,
            actionProposalIdentity,
            actionKeySetRosterIdentity,
            preparationAttempt: 7,
            predecessorIdentity: pseudorandomBytes(64, 0x3311n),
            senderPosition,
            recipientPosition,
        };
        const privateCarrier = bodyRuntime.seal(
            context,
            incomingPair.encryptionKey,
            pseudorandomBytes(32, 0x4711n),
            pseudorandomBytes(896, 0x8123n),
            pseudorandomBytes(privatePreparationPlaintextByteLength, 0x77b1n),
        );
        expect(privateCarrier.body).toHaveLength(
            privatePreparationBodyByteLength,
        );

        const privateBodyIdentities: Uint8Array[] = [];
        for (
            let candidateRecipient = 0;
            candidateRecipient < participantCount;
            candidateRecipient += 1
        ) {
            if (candidateRecipient === senderPosition) {
                continue;
            }
            privateBodyIdentities.push(
                candidateRecipient === recipientPosition
                    ? privateCarrier.identity
                    : pseudorandomBytes(
                          64,
                          0xb000n + BigInt(candidateRecipient),
                      ),
            );
        }
        const parent = parentRuntime.encode({
            participantCount,
            actionProposalIdentity,
            actionKeySetRosterIdentity,
            preparationAttempt: context.preparationAttempt,
            predecessorIdentity: context.predecessorIdentity,
            senderPosition,
            subsetCommitments: pseudorandomBytes(120 * 64, 0xc011n),
            privateBodyIdentities,
        });
        expect(parent.body).toHaveLength(
            preparationParentBodyByteLength(participantCount),
        );
        const parentSignature = signatureRuntime.signBodyIdentity(
            senderPreparationSecretKey,
            parent.identity,
        );
        const signatureCarrier = parentRuntime.encodeSignature(
            participantCount,
            senderPosition,
            parent.identity,
            parentSignature,
        );
        expect(signatureCarrier).toHaveLength(actionSignatureCarrierByteLength);

        expect(
            parentRuntime.verifyPrivateCarrier(
                context,
                actionKeySetBodies,
                parent.body,
                signatureCarrier,
                privateCarrier.body,
            ),
        ).toEqual({
            senderPosition,
            recipientPosition,
            parentIdentity: parent.identity,
            bodyIdentity: privateCarrier.identity,
        });

        const mutatedSignature = Uint8Array.from(signatureCarrier);
        mutatedSignature[mutatedSignature.byteLength - 1] ^= 1;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                actionKeySetBodies,
                parent.body,
                mutatedSignature,
                privateCarrier.body,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const mutatedBody = Uint8Array.from(privateCarrier.body);
        mutatedBody[mutatedBody.byteLength - 1] ^= 1;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                actionKeySetBodies,
                parent.body,
                signatureCarrier,
                mutatedBody,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const reorderedRoster = [...actionKeySetBodies];
        [reorderedRoster[0], reorderedRoster[1]] = [
            reorderedRoster[1],
            reorderedRoster[0],
        ];
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                reorderedRoster,
                parent.body,
                signatureCarrier,
                privateCarrier.body,
            ),
        ).toThrow(ConstructionKernelCommandError);
    });
});
