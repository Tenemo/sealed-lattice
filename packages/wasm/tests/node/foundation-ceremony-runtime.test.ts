import { describe, expect, it, vi } from 'vitest';

import {
    openFoundationCeremonyRuntime,
    type FoundationManifestInput,
} from '../../src/foundation-ceremony-runtime.js';
import type { PublishedSdkKernel } from '../../src/transcript-core-bridge/kernel-contracts.js';

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
    const encodeFoundationManifest = vi.fn(
        (
            input: Parameters<
                PublishedSdkKernel['encodeFoundationManifest']
            >[0],
        ) => ({
            canonicalBytesHex: '0001',
            manifestHash: hash('1'),
            input,
        }),
    );
    const unsupported = (): never => {
        throw new Error('unexpected kernel call');
    };
    const kernel = {
        encodeFoundationActionDefinition: unsupported,
        encodeFoundationBoardPolicy: unsupported,
        encodeFoundationManifest,
        verifyFoundationActionContext: unsupported,
        verifyFoundationActionDefinition: unsupported,
        verifyFoundationBoardPolicy: unsupported,
        verifyFoundationCeremonyContext: unsupported,
        verifyFoundationManifest: unsupported,
    } as unknown as PublishedSdkKernel;
    return { encodeFoundationManifest, kernel };
};

describe('foundation ceremony runtime input boundary', () => {
    it.each([2, 20])(
        'accepts the admitted structural option-count boundary %i',
        (optionCount) => {
            const { encodeFoundationManifest, kernel } = makeKernel();
            const encoded = openFoundationCeremonyRuntime(
                kernel,
            ).encodeManifest(manifestInput(optionCount));

            expect(encoded).toEqual({
                canonicalBytes: Uint8Array.from([0, 1]),
                manifestHash: hash('1'),
            });
            expect(
                encodeFoundationManifest.mock.calls[0]?.[0].optionDefinitions,
            ).toHaveLength(optionCount);
        },
    );

    it.each([1, 21])(
        'refuses the non-admitted structural option count %i before the kernel call',
        (optionCount) => {
            const { encodeFoundationManifest, kernel } = makeKernel();
            expect(() =>
                openFoundationCeremonyRuntime(kernel).encodeManifest(
                    manifestInput(optionCount),
                ),
            ).toThrow(RangeError);
            expect(encodeFoundationManifest).not.toHaveBeenCalled();
        },
    );

    it('refuses accessors and malformed Unicode before crossing the trusted byte boundary', () => {
        const { encodeFoundationManifest, kernel } = makeKernel();
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
        expect(encodeFoundationManifest).not.toHaveBeenCalled();
    });
});
