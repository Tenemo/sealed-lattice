import { describe, expect, it } from 'vitest';

import { createSetupPackageVerificationInput } from '#packages/protocol/src/setup/setup-package-assembly';

const manifestHash = '1'.repeat(128);
const rosterHash = '2'.repeat(128);
const setupPackageHash = '3'.repeat(128);

describe('setup package verification input', () => {
    it('takes an independent snapshot of canonical package bytes', () => {
        const callerBytes = new Uint8Array([0x12, 0x05, 0xaa, 0x55]);
        const verificationInput = createSetupPackageVerificationInput({
            canonicalSetupPackageBytes: callerBytes,
            expectedManifestHash: manifestHash,
            expectedRosterHash: rosterHash,
            expectedSetupPackageHash: setupPackageHash,
        });

        callerBytes.fill(0);

        expect(verificationInput).toEqual({
            canonicalSetupPackageBytes: new Uint8Array([
                0x12, 0x05, 0xaa, 0x55,
            ]),
            expectedManifestHash: manifestHash,
            expectedRosterHash: rosterHash,
            expectedSetupPackageHash: setupPackageHash,
        });
        expect(verificationInput.canonicalSetupPackageBytes).not.toBe(
            callerBytes,
        );
    });

    it.each([
        { name: 'an ordinary array', value: [0x12, 0x05] },
        {
            name: 'a data view',
            value: new DataView(new ArrayBuffer(4)),
        },
        { name: 'an object', value: { byteLength: 2 } },
    ])('rejects $name as canonical bytes', ({ value }) => {
        expect(() =>
            createSetupPackageVerificationInput({
                canonicalSetupPackageBytes: value as Uint8Array,
                expectedManifestHash: manifestHash,
                expectedRosterHash: rosterHash,
            }),
        ).toThrow(/canonicalSetupPackageBytes must be a Uint8Array/u);
    });

    it.each([
        {
            fieldName: 'expectedManifestHash',
            input: {
                expectedManifestHash: 'a',
                expectedRosterHash: rosterHash,
            },
        },
        {
            fieldName: 'expectedRosterHash',
            input: {
                expectedManifestHash: manifestHash,
                expectedRosterHash: 'b',
            },
        },
        {
            fieldName: 'expectedSetupPackageHash',
            input: {
                expectedManifestHash: manifestHash,
                expectedRosterHash: rosterHash,
                expectedSetupPackageHash: 'c',
            },
        },
    ])('rejects an invalid $fieldName', ({ fieldName, input }) => {
        expect(() =>
            createSetupPackageVerificationInput({
                canonicalSetupPackageBytes: new Uint8Array([0x12, 0x05]),
                ...input,
            }),
        ).toThrow(new RegExp(`${fieldName} must be a protocol hash`, 'u'));
    });
});
