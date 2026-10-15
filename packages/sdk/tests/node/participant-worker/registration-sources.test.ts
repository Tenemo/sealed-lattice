import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    chunkBytes,
    type ParticipantLimits,
} from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    streamRegistrations,
    registrationCandidateKey,
    registrationFile,
} from '#packages/sdk/src/participant/worker/stages/roster/roster.js';
import { participantRelayFixture } from '#packages/sdk/tests/participant-relay-fixture.js';

afterEach(() => vi.unstubAllGlobals());
const relay = { base: 'https://relay.invalid/' };
const limits = {
    maximumHeaderBytes: 512,
    signatureBytes: 8642,
    publicKeyBytes: 17,
    maximumSourceCiphertextBytes: chunkBytes + 37,
} as ParticipantLimits['registration'];

describe('source-bearing registration transport', () => {
    it('feeds every source chunk before finishing each record and returns only admitted candidates', async () => {
        const transport = participantRelayFixture();
        vi.stubGlobal('fetch', transport.fetch);
        const identities = ['01'.repeat(64), '02'.repeat(64)];
        for (const identity of identities)
            await transport.publish(
                registrationCandidateKey(identity),
                new Map([
                    [registrationFile.header, new Uint8Array(41)],
                    [
                        registrationFile.signature,
                        new Uint8Array(limits.signatureBytes),
                    ],
                    [
                        registrationFile.publicKey,
                        new Uint8Array(limits.publicKeyBytes),
                    ],
                    [
                        registrationFile.sourceCiphertexts,
                        new Uint8Array(limits.maximumSourceCiphertextBytes),
                    ],
                ]),
            );
        const steps: { operation: number; position: number; length: number }[] =
            [];
        const candidates = await streamRegistrations(
            relay,
            identities,
            limits,
            2,
            (operation, position, bytes) => {
                steps.push({ operation, position, length: bytes.length });
                return true;
            },
        );
        expect(candidates).toHaveLength(2);
        for (let position = 0; position < 2; position++)
            expect(
                steps
                    .filter((step) => step.position === position)
                    .map((step) => [step.operation, step.length]),
            ).toEqual([
                [0, 2 + 64 + 4 + 41 + limits.signatureBytes],
                [1, 17],
                [2, 0],
                [3, chunkBytes],
                [3, 37],
                [4, 0],
            ]);
    });

    it.each(['missing', 'refused'] as const)(
        'withholds record completion for a %s source body',
        async (fault) => {
            const transport = participantRelayFixture();
            vi.stubGlobal('fetch', transport.fetch);
            const identity = '01'.repeat(64);
            const files = new Map<string, Uint8Array>([
                [registrationFile.header, new Uint8Array(41)],
                [
                    registrationFile.signature,
                    new Uint8Array(limits.signatureBytes),
                ],
                [
                    registrationFile.publicKey,
                    new Uint8Array(limits.publicKeyBytes),
                ],
            ]);
            if (fault !== 'missing')
                files.set(
                    registrationFile.sourceCiphertexts,
                    new Uint8Array(37),
                );
            await transport.publish(registrationCandidateKey(identity), files);
            const operations: number[] = [];
            await expect(
                streamRegistrations(
                    relay,
                    [identity],
                    limits,
                    1,
                    (operation) => {
                        operations.push(operation);
                        return operation !== 3;
                    },
                ),
            ).rejects.toThrow();
            expect(operations).not.toContain(4);
            expect(operations).toContain(5);
        },
    );
});
