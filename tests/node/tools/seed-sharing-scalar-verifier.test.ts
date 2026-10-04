import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import {
    seedSharingProbes,
    verifySeedSharingProof,
} from '#tools/ci/seed-sharing-scalar-verifier.mjs';

// This tiny ABI fixture checks byte transport and view invalidation only.
// Its byte sum is not a cryptographic verifier or proof-security argument.
const transportFixture = (bodyLength: number, callsHost = false) => {
    const module = binaryen.parseText(`(module
        ${callsHost ? '(import "parallel" "wait" (func $host))' : ''}
        (memory (export "memory") 1 16)
        (global $count (mut i32) (i32.const 0))
        (global $sum (mut i32) (i32.const 0))
        (func $grow (drop (memory.grow (i32.const 1))))
        (func (export "seed_verifier_input_pointer") (result i32) (i32.const 16))
        (func (export "seed_verifier_input_capacity") (result i32) (i32.const 8))
        (func (export "seed_verifier_header_length") (result i32) (i32.const 4))
        (func (export "seed_verifier_begin") (param $context i32) (param $length i32) (result i32)
            ${callsHost ? '(call $host)' : ''}
            (if (i32.ne (local.get $context) (i32.const 0)) (then (return (i32.const 3))))
            (if (i32.ne (local.get $length) (i32.const 4)) (then (return (i32.const 2))))
            (if (i32.ne (i32.load (i32.const 16)) (i32.const 67305985)) (then (return (i32.const 4))))
            (call $grow)
            (i32.const 0))
        (func (export "seed_verifier_push") (param $length i32) (result i32) (local $index i32)
            (if (i32.or (i32.lt_u (local.get $length) (i32.const 1)) (i32.gt_u (local.get $length) (i32.const 8)))
                (then (return (i32.const 2))))
            (loop $bytes
                (global.set $sum (i32.add (global.get $sum) (i32.load8_u (i32.add (i32.const 16) (local.get $index)))))
                (local.set $index (i32.add (local.get $index) (i32.const 1)))
                (br_if $bytes (i32.lt_u (local.get $index) (local.get $length))))
            (global.set $count (i32.add (global.get $count) (local.get $length)))
            (call $grow)
            (i32.const 0))
        (func (export "seed_verifier_finish") (result i32)
            (if (i32.ne (global.get $count) (i32.const ${String(bodyLength)})) (then (return (i32.const 2))))
            (if (i32.ne (global.get $sum) (i32.const ${String((bodyLength * (bodyLength + 1)) / 2)})) (then (return (i32.const 5))))
            (i32.const 0)))`);
    try {
        return module.emitBinary();
    } finally {
        module.dispose();
    }
};

const proofBytes = (bodyLength: number) =>
    Uint8Array.from([
        1,
        2,
        3,
        4,
        ...Array.from({ length: bodyLength }, (_, index) => index + 1),
    ]);

describe('portable scalar verifier transport', () => {
    it('reacquires linear-memory views after begin and every push and preserves final chunk boundaries', async () => {
        for (const bodyLength of [1, 8, 9, 16, 17]) {
            const bytes = proofBytes(bodyLength);
            const reads: number[][] = [];
            const result = await verifySeedSharingProof({
                moduleBytes: transportFixture(bodyLength),
                proof: {
                    bytes: bytes.length,
                    sha512: 'synthetic transport fixture',
                },
                probe: seedSharingProbes[0],
                readExact: (length, position) => {
                    reads.push([length, position]);
                    return Promise.resolve(
                        bytes.slice(position, position + length),
                    );
                },
            });
            expect(result.code).toBe(0);
            expect(result.suppliedBytes).toBe(bytes.length);
            expect(result.maximumLinearMemoryBytes).toBe(
                (2 + Math.ceil(bodyLength / 8)) * 65_536,
            );
            expect(reads).toEqual([
                [4, 0],
                ...Array.from(
                    { length: Math.ceil(bodyLength / 8) },
                    (_, index) => [
                        Math.min(8, bodyLength - index * 8),
                        4 + index * 8,
                    ],
                ),
            ]);
        }
    });

    it('propagates host errors and invalid read lengths instead of manufacturing a verifier refusal', async () => {
        const bytes = proofBytes(9);
        const input = {
            moduleBytes: transportFixture(9),
            proof: {
                bytes: bytes.length,
                sha512: 'synthetic transport fixture',
            },
            probe: seedSharingProbes[0],
        };
        const failure = new Error('The host cannot read its pinned input.');
        await expect(
            verifySeedSharingProof({
                ...input,
                readExact: () => Promise.reject(failure),
            }),
        ).rejects.toBe(failure);
        for (const difference of [-1, 1])
            await expect(
                verifySeedSharingProof({
                    ...input,
                    readExact: (length) =>
                        Promise.resolve(new Uint8Array(length + difference)),
                }),
            ).rejects.toThrow('wrong length');
        await expect(
            verifySeedSharingProof({
                ...input,
                moduleBytes: transportFixture(9, true),
                readExact: (length, position) =>
                    Promise.resolve(bytes.slice(position, position + length)),
            }),
        ).rejects.toThrow('Scalar verification invoked parallel.wait');
        const refused = await verifySeedSharingProof({
            ...input,
            probe: { ...input.probe, context: 3 },
            readExact: (length, position) =>
                Promise.resolve(bytes.slice(position, position + length)),
        });
        expect(refused.code).toBe(3);
        expect(refused.suppliedBytes).toBe(4);
    });
});
