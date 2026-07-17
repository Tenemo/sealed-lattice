import type { ActionRandomnessScope } from '../src/action-randomness-runtime.js';

export const actionRandomnessTestVector = Object.freeze({
    actionRandomnessCommitment:
        '358a1f0d923ca0ee03d6a5ddd4dd1bcd49c1c0d71e66e3e82e575097aba76d5fce106820325f0459528e341511ebacfb872a42d6ae7e2e1ed5ab12b3b079d12e',
    freshBallotAttemptIdentifier: '91'.repeat(32),
    ordinaryProof: Object.freeze({
        applicationSlotHash:
            'f50cfe10a74b5b8aa9415cc29e117cfcb9502cf3761f1446cb33d7bb435cd0b8449574d8c5f76c88701f308eda1b6f5875e14bdd7b3f429eab1c5d331d7b7fed',
        applicationStatementHash: '66'.repeat(64),
        attemptIdentifier:
            'c8a28cfe1918292c8e10281e260b03d728082c1de7504da1826856b6b1ad1925',
        nonce: '70'.repeat(32),
        producerSequence: 19n,
        rosterPosition: 2,
    }),
    persistentProof: Object.freeze({
        applicationSlotHash:
            'a9ec539baadfd0826d74fd4ce7a4ef912bf8953af1a34a135bbcbc4e3c9cf32bcfe024e28d36b7867343a9bbc296a5721994e185a6e31eb4cf56cbaf3b30098d',
        applicationStatementHash: '66'.repeat(64),
        attemptIdentifier:
            'fdfd5bd73a3589fedfbc12ae823d0682a7a71d93168fdb8eadbef8a8a159e861',
        rosterPosition: 2,
        statementSchemaIdentifier: 0x1211 as const,
    }),
    rosterHash: '55'.repeat(64),
    rootFillByte: 0x5a,
    scope: Object.freeze({
        suiteId: '11'.repeat(64),
        ceremonyContextHash: '22'.repeat(64),
        actionContextHash: '33'.repeat(64),
        participantId: '44'.repeat(64),
    }) satisfies ActionRandomnessScope,
    targetRelease: Object.freeze({
        applicationSlotHash:
            'ae265abb8caf456bff90acdb2a656e3672038e204be379b8ec5735165b7c0f8d1d24e8da506beb3774ab1c6aba1b89960251d7b62b01888728f56be8d8df4d8a',
        attemptIdentifier:
            'ba3e74764257152f936b3b97e5f909ca65a5e4afb85320069b9728550d44af19',
        rosterPosition: 2,
    }),
});

export const createDeterministicCryptoProvider = (
    requests: readonly Readonly<{
        readonly byteLength: number;
        readonly fillByte: number;
    }>[],
): Readonly<{
    readonly cryptoProvider: Crypto;
    callCount(): number;
}> => {
    let callIndex = 0;
    const cryptoProvider = {
        getRandomValues: (output: Uint8Array): Uint8Array => {
            const request = requests[callIndex];
            if (request === undefined) {
                throw new Error('Unexpected deterministic entropy request.');
            }
            if (output.byteLength !== request.byteLength) {
                throw new Error(
                    `Expected ${String(request.byteLength)} entropy bytes, received ${String(output.byteLength)}.`,
                );
            }
            callIndex += 1;
            output.fill(request.fillByte);
            return output;
        },
    } as unknown as Crypto;

    return Object.freeze({
        cryptoProvider,
        callCount: () => callIndex,
    });
};
