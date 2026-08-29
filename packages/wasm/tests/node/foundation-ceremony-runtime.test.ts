import { describe, expect, it, vi } from 'vitest';

import {
    openFoundationCeremonyRuntime,
    type FoundationManifestInput,
} from '../../src/foundation-ceremony-runtime.js';
import type { FoundationKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';

const hash = (byte: string): string => byte.repeat(128);

const manifestInput = (optionCount: number): FoundationManifestInput => ({
    displayTitle: 'Choose priorities',
    optionDefinitions: Array.from(
        { length: optionCount },
        (_unused, optionIndex) => ({
            displayLabel: `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

const makeKernel = () => {
    const response = Uint8Array.from([
        0,
        2,
        0,
        0,
        0,
        0,
        1,
        ...new Uint8Array(64).fill(0x11),
    ]);
    const executeCommand = vi.fn((_request: Uint8Array) => response);
    const kernel: FoundationKernelCommandRuntime = { executeCommand };
    return { executeCommand, kernel };
};

const encodedOptionCount = (request: Uint8Array): number => {
    const view = new DataView(
        request.buffer,
        request.byteOffset,
        request.byteLength,
    );
    const displayTitleByteLength = view.getUint32(1, true);
    return view.getUint16(5 + displayTitleByteLength, true);
};

describe('foundation ceremony runtime input boundary', () => {
    it.each([2, 20])(
        'accepts the admitted structural option-count boundary %i',
        (optionCount) => {
            const { executeCommand, kernel } = makeKernel();
            const encoded = openFoundationCeremonyRuntime(
                kernel,
            ).encodeManifest(manifestInput(optionCount));

            expect(encoded).toEqual({
                canonicalBytes: Uint8Array.from([0, 1]),
                manifestHash: hash('1'),
            });
            expect(
                encodedOptionCount(
                    executeCommand.mock.calls[0]?.[0] ?? new Uint8Array(),
                ),
            ).toBe(optionCount);
        },
    );

    it.each([1, 21])(
        'refuses the non-admitted structural option count %i before the kernel call',
        (optionCount) => {
            const { executeCommand, kernel } = makeKernel();
            expect(() =>
                openFoundationCeremonyRuntime(kernel).encodeManifest(
                    manifestInput(optionCount),
                ),
            ).toThrow(RangeError);
            expect(executeCommand).not.toHaveBeenCalled();
        },
    );

    it('refuses accessors and malformed Unicode before crossing the trusted byte boundary', () => {
        const { executeCommand, kernel } = makeKernel();
        const runtime = openFoundationCeremonyRuntime(kernel);
        const accessorInput = manifestInput(2) as Record<string, unknown>;
        Object.defineProperty(accessorInput, 'displayTitle', {
            enumerable: true,
            get: () => 'accessor value',
        });
        expect(() => runtime.encodeManifest(accessorInput as never)).toThrow(
            'ordinary data property',
        );

        const malformedUnicodeInput = {
            ...manifestInput(2),
            displayTitle: '\ud800',
        };
        expect(() => runtime.encodeManifest(malformedUnicodeInput)).toThrow(
            'well-formed string',
        );
        expect(executeCommand).not.toHaveBeenCalled();
    });
});
