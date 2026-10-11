import binaryen from 'binaryen';
import { describe, expect, it, vi } from 'vitest';

import { runFheKeySourceScreen } from '#tools/ci/fhe-key-source-scalar.mjs';

// A transport fixture, not a key source screen. Its pending span is changed
// by memory growth only after acknowledgment, exposing stale-view mistakes.
const fixture = (
    bytes = 13,
    capacity = 5,
    flaw?: 'bytes' | 'phase' | 'length' | 'randomness',
) => {
    const module = binaryen.parseText(`(module
      ${flaw === 'randomness' ? '(import "word_proof" "fill_random" (func $random (param i32 i32) (result i32)))' : ''}
      (memory (export "memory") 1 32)
      (global $phase (mut i32) (i32.const 0))
      (global $offset (mut i32) (i32.const 0))
      (global $length (mut i32) (i32.const 0))
      (global $acks (mut i32) (i32.const 0))
      (func (export "key_source_screen_output_capacity") (result i32) (i32.const ${String(capacity)}))
      (func (export "key_source_screen_phase") (result i32) (global.get $phase))
      (func (export "key_source_screen_output_length") (result i32) (global.get $length))
      (func (export "key_source_screen_output_pointer") (result i32) (i32.const 16))
      (func (export "fixture_acks") (result i32) (global.get $acks))
      (func (export "key_source_screen_begin") (result i32)
        (if (i32.ne (global.get $phase) (i32.const 0)) (then (return (i32.const 6))))
        ${flaw === 'randomness' ? '(drop (call $random (i32.const 16) (i32.const 1)))' : ''}
        (global.set $phase (i32.const 1)) (drop (memory.grow (i32.const 1))) (i32.const 0))
      (func (export "key_source_screen_step") (result i32)
        (if (i32.ne (global.get $length) (i32.const 0)) (then
          ${flaw === 'bytes' ? '(i32.store8 (i32.const 16) (i32.const 99))' : ''}
          ${flaw === 'phase' ? '(global.set $phase (i32.const 13))' : ''}
          ${flaw === 'length' ? '(global.set $length (i32.const 1))' : ''}
          (return (i32.const 6))))
        (if (i32.eq (global.get $phase) (i32.const 1))
          (then (global.set $phase (i32.const 2)) (return (i32.const 0))))
        (if (i32.eq (global.get $phase) (i32.const 2))
          (then (global.set $phase (i32.const 12)) (return (i32.const 0))))
        (i32.const 6))
      (func (export "key_source_screen_next_output") (result i32) (local $index i32)
        (if (i32.ne (global.get $length) (i32.const 0)) (then (return (i32.const 6))))
        (if (i32.eq (global.get $offset) (i32.const ${String(bytes)}))
          (then (global.set $phase (i32.const 13)) (return (i32.const 0))))
        (drop (memory.grow (i32.const 1)))
        (global.set $length (i32.sub (i32.const ${String(bytes)}) (global.get $offset)))
        (if (i32.gt_u (global.get $length) (i32.const ${String(capacity)}))
          (then (global.set $length (i32.const ${String(capacity)}))))
        (loop $write
          (i32.store8 (i32.add (i32.const 16) (local.get $index)) (i32.add (i32.add (global.get $offset) (local.get $index)) (i32.const 1)))
          (local.set $index (i32.add (local.get $index) (i32.const 1)))
          (br_if $write (i32.lt_u (local.get $index) (global.get $length))))
        (i32.const 0))
      (func (export "key_source_screen_ack_output") (result i32)
        (if (i32.eqz (global.get $length)) (then (return (i32.const 6))))
        (global.set $offset (i32.add (global.get $offset) (global.get $length)))
        (global.set $length (i32.const 0))
        (global.set $acks (i32.add (global.get $acks) (i32.const 1)))
        (drop (memory.grow (i32.const 1))) (i32.const 0)))`);
    try {
        return module.emitBinary();
    } finally {
        module.dispose();
    }
};

const captureInstance = () => {
    const original = WebAssembly.instantiate;
    let instance: WebAssembly.Instance | undefined;
    const spy = vi
        .spyOn(WebAssembly, 'instantiate')
        .mockImplementation(async (module, imports) => {
            const value = await original(module, imports);
            instance = value;
            return value;
        });
    return {
        spy,
        acks: () => (instance!.exports.fixture_acks as () => number)(),
    };
};

describe('bounded scalar output transport', () => {
    it('copies each grown-memory span and never acknowledges before its sink receipt', async () => {
        const observed = captureInstance();
        let release!: () => void;
        let received!: () => void;
        const pending = new Promise<void>((resolve) => {
            release = resolve;
        });
        const first = new Promise<void>((resolve) => {
            received = resolve;
        });
        const chunks: Uint8Array[] = [];
        try {
            const generation = runFheKeySourceScreen({
                caseIndex: 0,
                moduleBytes: fixture(),
                expectedBytes: 13,
                emitChunk: async (index, offset, bytes) => {
                    expect(observed.acks()).toBe(index);
                    chunks.push(bytes);
                    if (index === 0) {
                        received();
                        await pending;
                    }
                    return { index, offset, length: bytes.length };
                },
            });
            await first;
            expect(observed.acks()).toBe(0);
            expect(chunks).toHaveLength(1);
            release();
            const result = await generation;
            expect(result).toMatchObject({
                bytes: 13,
                chunks: 3,
                steps: 2,
                controlCases: 5,
                maximumLinearMemoryBytes: 8 * 65536,
            });
            expect(chunks.map((chunk) => chunk.length)).toEqual([5, 5, 3]);
            expect(chunks.flatMap((chunk) => [...chunk])).toEqual(
                Array.from({ length: 13 }, (_, index) => index + 1),
            );
            expect(observed.acks()).toBe(3);
            for (const operation of [
                'premature_ack_output',
                'step_with_pending_output',
                'next_with_pending_output',
                'rebegin_with_pending_output',
                'duplicate_ack_output',
            ])
                expect(
                    result.calls.find((call) => call.operation === operation)
                        ?.count,
                ).toBe(1);
            expect(result.longestCall?.milliseconds).toBeGreaterThanOrEqual(0);
            expect(
                result.calls.find(
                    (call) => call.operation === 'step' && call.phase === 2,
                )?.count,
            ).toBe(1);
        } finally {
            release?.();
            observed.spy.mockRestore();
        }
    });

    it('detects a refusal that mutates pending output and refuses an unknown case or proof randomness import', async () => {
        for (const flaw of ['bytes', 'phase', 'length'] as const) {
            const sink = vi.fn(
                (index: number, offset: number, bytes: Uint8Array) =>
                    Promise.resolve({ index, offset, length: bytes.length }),
            );
            await expect(
                runFheKeySourceScreen({
                    caseIndex: 0,
                    moduleBytes: fixture(13, 5, flaw),
                    expectedBytes: 13,
                    emitChunk: sink,
                }),
            ).rejects.toThrow('refused control changed');
            expect(sink).not.toHaveBeenCalled();
        }
        const sink = vi.fn((index: number, offset: number, bytes: Uint8Array) =>
            Promise.resolve({ index, offset, length: bytes.length }),
        );
        await expect(
            runFheKeySourceScreen({
                caseIndex: 1,
                moduleBytes: fixture(),
                expectedBytes: 13,
                emitChunk: sink,
            }),
        ).rejects.toThrow('Unknown key source screen case');
        await expect(
            runFheKeySourceScreen({
                caseIndex: 0,
                moduleBytes: fixture(13, 5, 'randomness'),
                expectedBytes: 13,
                emitChunk: sink,
            }),
        ).rejects.toThrow('Unknown scalar import');
        expect(sink).not.toHaveBeenCalled();
    });

    it('rejects stale, reordered and partial acknowledgments without acknowledging the pending span', async () => {
        for (const wrong of [
            { index: 1, offset: 0, length: 5 },
            { index: 0, offset: 1, length: 5 },
            { index: 0, offset: 0, length: 4 },
        ]) {
            const observed = captureInstance();
            try {
                await expect(
                    runFheKeySourceScreen({
                        caseIndex: 0,
                        moduleBytes: fixture(),
                        expectedBytes: 13,
                        emitChunk: () => Promise.resolve(wrong),
                    }),
                ).rejects.toThrow('another output span');
                expect(observed.acks()).toBe(0);
            } finally {
                observed.spy.mockRestore();
            }
        }
        const observed = captureInstance();
        try {
            await expect(
                runFheKeySourceScreen({
                    caseIndex: 0,
                    moduleBytes: fixture(),
                    expectedBytes: 13,
                    emitChunk: (index, offset, bytes) =>
                        Promise.resolve(
                            index === 0
                                ? { index, offset, length: bytes.length }
                                : { index: 0, offset: 0, length: 5 },
                        ),
                }),
            ).rejects.toThrow('another output span');
            expect(observed.acks()).toBe(1);
        } finally {
            observed.spy.mockRestore();
        }
    });

    it('propagates sink failure and refuses incorrect totals or unbounded output before success', async () => {
        const observed = captureInstance();
        const failure = new Error('The output write failed.');
        try {
            await expect(
                runFheKeySourceScreen({
                    caseIndex: 0,
                    moduleBytes: fixture(),
                    expectedBytes: 13,
                    emitChunk: () => Promise.reject(failure),
                }),
            ).rejects.toBe(failure);
            expect(observed.acks()).toBe(0);
        } finally {
            observed.spy.mockRestore();
        }
        const emitChunk = (index: number, offset: number, bytes: Uint8Array) =>
            Promise.resolve({ index, offset, length: bytes.length });
        for (const expectedBytes of [12, 14])
            await expect(
                runFheKeySourceScreen({
                    caseIndex: 0,
                    moduleBytes: fixture(),
                    expectedBytes,
                    emitChunk,
                }),
            ).rejects.toThrow();
        await expect(
            runFheKeySourceScreen({
                caseIndex: 0,
                moduleBytes: fixture(13, 1_048_577),
                expectedBytes: 13,
                emitChunk,
            }),
        ).rejects.toThrow('capacity');
    });
});
