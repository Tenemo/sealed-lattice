import binaryen from 'binaryen';
import { describe, expect, it, vi } from 'vitest';

import {
    admitOpeningSources,
    verifyOpeningShareProof,
} from '#tools/ci/opening-share-scalar.mjs';
import { generateBoundedProof } from '#tools/ci/seed-sharing-scalar-prover.mjs';

type OpeningApi = Parameters<typeof verifyOpeningShareProof>[0]['api'];
type FixtureApi = OpeningApi & {
    fixture_sources(): number;
    fixture_openings(): number;
};

// Actual Wasm checks ordered complete byte streams, not cryptography. Its
// explicit source0/source1/opening contract catches a coordinator that skips
// verification, reuses stale views, reorders bytes or manufactures a refusal.
const fixtureModule = (lengths: readonly [number, number, number]) => {
    const module = binaryen.parseText(`(module
        (memory (export "memory") 1 32)
        (global $failed (mut i32) (i32.const 0))
        (global $sources (mut i32) (i32.const 0))
        (global $openings (mut i32) (i32.const 0))
        (global $active (mut i32) (i32.const 0))
        (global $stream (mut i32) (i32.const 0))
        (global $position (mut i32) (i32.const 0))
        (func $fail (param $code i32) (result i32)
            (if (i32.eqz (global.get $failed)) (then (global.set $failed (local.get $code))))
            (global.set $active (i32.const 0)) (global.get $failed))
        (func $grow (drop (memory.grow (i32.const 1))))
        (func $length (result i32)
            (if (i32.eq (global.get $stream) (i32.const 0)) (then (return (i32.const ${lengths[0]}))))
            (if (i32.eq (global.get $stream) (i32.const 1)) (then (return (i32.const ${lengths[1]}))))
            (i32.const ${lengths[2]}))
        (func (export "opening_input_pointer") (result i32) (i32.const 16))
        (func (export "opening_input_capacity") (result i32) (i32.const 8))
        (func (export "opening_header_length") (result i32) (i32.const 4))
        (func (export "fixture_sources") (result i32) (global.get $sources))
        (func (export "fixture_openings") (result i32) (global.get $openings))
        (func (export "opening_source_begin") (param $slot i32) (param $length i32) (result i32) (local $header i32)
            (if (global.get $failed) (then (return (global.get $failed))))
            (if (i32.ne (local.get $length) (i32.const 4)) (then (return (call $fail (i32.const 2)))))
            (if (i32.or (global.get $active) (i32.or (i32.ne (local.get $slot) (global.get $sources)) (i32.ge_u (local.get $slot) (i32.const 2))))
                (then (return (call $fail (i32.const 6)))))
            (local.set $header (select (i32.const 67305985) (i32.const 134678021) (i32.eqz (local.get $slot))))
            (if (i32.ne (i32.load (i32.const 16)) (local.get $header)) (then (return (call $fail (i32.const 3)))))
            (global.set $stream (local.get $slot)) (global.set $position (i32.const 0))
            (global.set $active (i32.const 1)) (call $grow) (i32.const 0))
        (func (export "opening_verifier_begin") (param $context i32) (param $length i32) (result i32)
            (if (global.get $failed) (then (return (global.get $failed))))
            (if (i32.or (global.get $active) (i32.or (i32.ne (global.get $sources) (i32.const 2)) (global.get $openings)))
                (then (return (call $fail (i32.const 6)))))
            (if (i32.ne (local.get $length) (i32.const 4)) (then (return (call $fail (i32.const 2)))))
            (if (i32.or (local.get $context) (i32.ne (i32.load (i32.const 16)) (i32.const 202050057)))
                (then (return (call $fail (i32.const 3)))))
            (global.set $stream (i32.const 2)) (global.set $position (i32.const 0))
            (global.set $active (i32.const 1)) (global.set $openings (i32.const 1))
            (call $grow) (i32.const 0))
        (func $push (export "opening_source_push") (export "opening_verifier_push") (param $length i32) (result i32) (local $index i32) (local $expected i32)
            (if (global.get $failed) (then (return (global.get $failed))))
            (if (i32.eqz (global.get $active)) (then (return (call $fail (i32.const 6)))))
            (if (i32.or (i32.eqz (local.get $length)) (i32.or (i32.gt_u (local.get $length) (i32.const 8)) (i32.gt_u (i32.add (global.get $position) (local.get $length)) (call $length))))
                (then (return (call $fail (i32.const 2)))))
            (loop $bytes
                (local.set $expected (i32.add (i32.const 17) (i32.add (i32.mul (global.get $stream) (i32.const 66)) (i32.add (global.get $position) (local.get $index)))))
                (if (i32.ne (i32.load8_u (i32.add (i32.const 16) (local.get $index))) (local.get $expected))
                    (then (return (call $fail (i32.const 4)))))
                (local.set $index (i32.add (local.get $index) (i32.const 1)))
                (br_if $bytes (i32.lt_u (local.get $index) (local.get $length))))
            (global.set $position (i32.add (global.get $position) (local.get $length)))
            (call $grow) (i32.const 0))
        (func $finish (export "opening_source_finish") (export "opening_verifier_finish") (result i32)
            (if (global.get $failed) (then (return (global.get $failed))))
            (if (i32.eqz (global.get $active)) (then (return (call $fail (i32.const 6)))))
            (if (i32.ne (global.get $position) (call $length)) (then (return (call $fail (i32.const 5)))))
            (global.set $active (i32.const 0))
            (if (i32.lt_u (global.get $stream) (i32.const 2))
                (then (global.set $sources (i32.add (global.get $sources) (i32.const 1)))))
            (i32.const 0)))`);
    try {
        return module.emitBinary();
    } finally {
        module.dispose();
    }
};

const fixture = async (
    lengths: readonly [number, number, number] = [9, 17, 10],
) => {
    const moduleBytes = fixtureModule(lengths);
    const instance = await WebAssembly.instantiate(
        await WebAssembly.compile(new Uint8Array(moduleBytes)),
    );
    const api = instance.exports as unknown as FixtureApi;
    const payloads = lengths.map((length, stream) =>
        Uint8Array.from([
            ...[1, 2, 3, 4].map((byte) => byte + 4 * stream),
            ...Array.from(
                { length },
                (_unused, index) => 17 + 66 * stream + index,
            ),
        ]),
    );
    const proofs = payloads.map((bytes, index) => ({
        bytes: bytes.length,
        sha512: 'synthetic-transport-' + String(index),
    }));
    const reads: number[][] = [];
    const readPredecessor = vi.fn(
        (index: number, length: number, position: number) => {
            reads.push([index, length, position]);
            return Promise.resolve(
                payloads[index].slice(position, position + length),
            );
        },
    );
    const readExact = vi.fn((length: number, position: number) => {
        reads.push([2, length, position]);
        return Promise.resolve(payloads[2].slice(position, position + length));
    });
    return {
        moduleBytes,
        api,
        payloads,
        proofs,
        reads,
        input: {
            api,
            predecessors: proofs.slice(0, 2),
            readPredecessor,
            proof: proofs[2],
            probe: { name: 'synthetic opening', proof: 0, context: 0 },
            readExact,
        },
    };
};

describe('opening proof source transport', () => {
    it.each([1, 8, 9, 17])(
        'admits complete ordered sources before an opening across %i-byte boundaries and memory growth',
        async (length) => {
            const lengths = [length, length + 1, length + 2] as const;
            const fixed = await fixture(lengths);
            const result = await verifyOpeningShareProof(fixed.input);
            expect(result.code).toBe(0);
            expect(result.sourceResults.map((source) => source.code)).toEqual([
                0, 0,
            ]);
            expect(fixed.api.fixture_sources()).toBe(2);
            expect(fixed.api.fixture_openings()).toBe(1);
            expect(fixed.reads).toEqual(
                lengths.flatMap((bytes, index) => [
                    [index, 4, 0],
                    ...Array.from(
                        { length: Math.ceil(bytes / 8) },
                        (_unused, chunk) => [
                            index,
                            Math.min(8, bytes - 8 * chunk),
                            4 + 8 * chunk,
                        ],
                    ),
                ]),
            );
            expect(result.maximumLinearMemoryBytes).toBe(
                (4 +
                    lengths.reduce(
                        (sum, bytes) => sum + Math.ceil(bytes / 8),
                        0,
                    )) *
                    65_536,
            );
        },
    );

    it.each([
        ['missing-all', 6],
        ['missing-second', 6],
        ['first-slot-one', 6],
        ['repeated-slot', 6],
        ['reordered', 3],
        ['duplicate', 3],
        ['truncated', 5],
        ['changed', 4],
    ] as const)(
        'keeps the first refusal for %s instead of substituting a generic stage verdict',
        async (sourceControl, expected) => {
            const fixed = await fixture();
            const result = await verifyOpeningShareProof({
                ...fixed.input,
                probe: { ...fixed.input.probe, sourceControl },
            });
            expect(result.code).toBe(expected);
            expect(fixed.api.fixture_openings()).toBe(0);
            expect(fixed.input.readExact.mock.calls).toEqual([[4, 0]]);
            expect(fixed.api.opening_verifier_finish()).toBe(expected);
            expect(fixed.api.opening_source_begin(0, 4)).toBe(expected);
        },
    );

    it('does not treat a host-declared source EOF as proof verification', async () => {
        const fixed = await fixture();
        const result = await admitOpeningSources({
            ...fixed.input,
            predecessors: [{ ...fixed.proofs[0], bytes: 4 }, fixed.proofs[1]],
        });
        expect(result.map((source) => source.code)).toEqual([5]);
        expect(fixed.api.fixture_sources()).toBe(0);
        expect(fixed.reads).toEqual([[0, 4, 0]]);
        expect(fixed.api.opening_verifier_begin(0, 4)).toBe(5);
    });

    it('propagates partial source IO and malformed read lengths without attempting opening work', async () => {
        const fixed = await fixture();
        const failure = new Error(
            'The first source disappeared during transfer.',
        );
        await expect(
            verifyOpeningShareProof({
                ...fixed.input,
                readPredecessor: (index, length, position) =>
                    position === 0
                        ? fixed.input.readPredecessor(index, length, position)
                        : Promise.reject(failure),
            }),
        ).rejects.toBe(failure);
        expect(fixed.input.readExact).not.toHaveBeenCalled();
        expect(fixed.api.fixture_sources()).toBe(0);
        expect(fixed.api.fixture_openings()).toBe(0);
        for (const delta of [-1, 1]) {
            const malformed = await fixture();
            await expect(
                verifyOpeningShareProof({
                    ...malformed.input,
                    readPredecessor: (_index, length) =>
                        Promise.resolve(new Uint8Array(length + delta)),
                }),
            ).rejects.toThrow('wrong length');
            expect(malformed.input.readExact).not.toHaveBeenCalled();
            expect(malformed.api.fixture_sources()).toBe(0);
        }
    });

    it('does not call a prover or output sink before both sources verify', async () => {
        const fixed = await fixture();
        const emitChunk = vi.fn(
            (index: number, offset: number, bytes: Uint8Array) =>
                Promise.resolve({ index, offset, length: bytes.length }),
        );
        // This module deliberately exports no prover. An accidental call
        // before source admission therefore cannot be masked by a fake prover.
        await expect(
            generateBoundedProof({
                moduleBytes: fixed.moduleBytes,
                relation: 'opening-share',
                expectedBytes: 5,
                emitChunk,
                predecessors: fixed.input.predecessors,
                readPredecessor: (_index, length) =>
                    Promise.resolve(new Uint8Array(length)),
            }),
        ).rejects.toThrow('failed predecessor admission');
        expect(emitChunk).not.toHaveBeenCalled();
    });
});
