import { describe, expect, it } from 'vitest';

import {
    assertKernelMemoryWithinProfile,
    copyFromKernelMemory,
    copyIntoKernelMemory,
    serializeBoundedKernelCommandRequest,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';

const expectCommandBoundaryCode = (
    operation: () => unknown,
    expectedCode: string,
): void => {
    let observedError: unknown;
    try {
        operation();
    } catch (error) {
        observedError = error;
    }
    expect(observedError).toBeInstanceOf(TranscriptCoreKernelCommandError);
    expect((observedError as TranscriptCoreKernelCommandError).code).toBe(
        expectedCode,
    );
};

describe('Transcript-core command boundary', () => {
    it('enforces the linear-memory ceiling and refuses out-of-bounds ranges', () => {
        const memory = new WebAssembly.Memory({ initial: 2, maximum: 3 });

        expect(() =>
            assertKernelMemoryWithinProfile(memory, 2 * 65_536),
        ).not.toThrow();
        expectCommandBoundaryCode(
            () => assertKernelMemoryWithinProfile(memory, 65_536),
            'MalformedLength',
        );
        expect(() => assertKernelMemoryWithinProfile(memory, 65_537)).toThrow(
            RangeError,
        );
        expect(() =>
            copyFromKernelMemory(
                memory,
                2 * 65_536 - 3,
                4,
                'adversarial response',
            ),
        ).toThrow(/out-of-bounds/u);
        expect(() =>
            copyFromKernelMemory(memory, 0, 1, 'null response'),
        ).toThrow(/out-of-bounds/u);
    });

    it('checks the allocator range before growing or copying input', () => {
        const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
        const copiedPointer = copyIntoKernelMemory(
            memory,
            () => 65_530,
            Uint8Array.of(1, 2, 3, 4, 5, 6),
        );
        expect(copiedPointer).toBe(65_530);
        expect(
            Array.from(new Uint8Array(memory.buffer, copiedPointer, 6)),
        ).toEqual([1, 2, 3, 4, 5, 6]);

        expectCommandBoundaryCode(
            () =>
                copyIntoKernelMemory(
                    memory,
                    () => 0xffff_fff0,
                    new Uint8Array(32),
                ),
            'MalformedLength',
        );
        expect(memory.buffer.byteLength).toBe(65_536);
    });

    it('accepts the exact UTF-8 boundary and refuses one byte over', () => {
        const request = {
            command: 'HashRaw',
            inputHex: '00',
            escaped: 'quote " and cafe\u0301',
        };
        const expected = new TextEncoder().encode(JSON.stringify(request));

        expect(
            serializeBoundedKernelCommandRequest(request, expected.byteLength),
        ).toEqual(expected);
        expectCommandBoundaryCode(
            () =>
                serializeBoundedKernelCommandRequest(
                    request,
                    expected.byteLength - 1,
                ),
            'MalformedLength',
        );
    });

    it('refuses unsafe integers, accessors, custom serializers, and cycles', () => {
        for (const invalidRequest of [null, 'HashRaw', ['HashRaw']]) {
            expectCommandBoundaryCode(
                () => serializeBoundedKernelCommandRequest(invalidRequest),
                'InvalidProtocolObject',
            );
        }

        expectCommandBoundaryCode(
            () =>
                serializeBoundedKernelCommandRequest({
                    command: 'EvaluatePlaintextComparison',
                    leftTotalScore: Number.MAX_SAFE_INTEGER + 1,
                }),
            'InvalidProtocolObject',
        );

        let accessorWasRead = false;
        const accessorRequest = { command: 'HashRaw' } as Record<
            string,
            unknown
        >;
        Object.defineProperty(accessorRequest, 'inputHex', {
            enumerable: true,
            get: () => {
                accessorWasRead = true;
                return '00';
            },
        });
        expectCommandBoundaryCode(
            () => serializeBoundedKernelCommandRequest(accessorRequest),
            'InvalidProtocolObject',
        );
        expect(accessorWasRead).toBe(false);

        expectCommandBoundaryCode(
            () =>
                serializeBoundedKernelCommandRequest({
                    command: 'HashRaw',
                    toJSON: () => ({ command: 'ListCanonicalErrorCodes' }),
                }),
            'InvalidProtocolObject',
        );

        const cyclicRequest: Record<string, unknown> = {
            command: 'HashRaw',
        };
        cyclicRequest.self = cyclicRequest;
        expectCommandBoundaryCode(
            () => serializeBoundedKernelCommandRequest(cyclicRequest),
            'InvalidProtocolObject',
        );
    });

    it('matches JSON omission and sparse-array behavior', () => {
        const sparseValues = new Array<unknown>(3);
        sparseValues[0] = 1;
        sparseValues[2] = undefined;
        const request = {
            command: 'HashRaw',
            omitted: undefined,
            sparse: sparseValues,
        };
        const expected = new TextEncoder().encode(JSON.stringify(request));

        expect(serializeBoundedKernelCommandRequest(request)).toEqual(expected);
    });

    it('serializes the validated descriptor snapshot without revisiting a proxy', () => {
        let customSerializationReadCount = 0;
        const request = new Proxy(
            { command: 'HashRaw', inputHex: '00' },
            {
                get: (target, propertyKey, receiver): unknown => {
                    if (propertyKey === 'toJSON') {
                        customSerializationReadCount += 1;
                        return () => ({ command: 'ListCanonicalErrorCodes' });
                    }
                    return Reflect.get(
                        target,
                        propertyKey,
                        receiver,
                    ) as unknown;
                },
            },
        );

        expect(serializeBoundedKernelCommandRequest(request)).toEqual(
            new TextEncoder().encode('{"command":"HashRaw","inputHex":"00"}'),
        );
        expect(customSerializationReadCount).toBe(0);
    });

    it('accepts exactly 64 JSON containers and refuses a deeper request', () => {
        const requestWithArrayDepth = (arrayDepth: number): unknown => {
            let nestedValue: unknown = null;
            for (let index = 0; index < arrayDepth; index += 1) {
                nestedValue = [nestedValue];
            }
            return { command: 'HashRaw', nested: nestedValue };
        };

        expect(() =>
            serializeBoundedKernelCommandRequest(requestWithArrayDepth(63)),
        ).not.toThrow();
        expectCommandBoundaryCode(
            () =>
                serializeBoundedKernelCommandRequest(requestWithArrayDepth(64)),
            'MalformedLength',
        );
    });
});
