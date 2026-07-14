import { beforeAll, describe, expect, it } from 'vitest';

import {
    loadFreshTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    asciiItem,
    canonicalTuple,
    unsigned16Item,
    unsigned64Item,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import {
    createDeterministicCanonicalByteFragments,
    createFoundationCanonicalTestVectors,
    foundationCanonicalSchemaIdentifiers,
} from '#packages/wasm/tests/foundation-canonical-test-vectors';

const actionDefinitionSchemaIdentifier = 0x0112;
const boardPolicySchemaIdentifier = 0x0113;

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

describe('Canonical foundation values in browser WASM', () => {
    let kernel: TranscriptCoreKernel;

    beforeAll(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('round-trips every foundation schema from contiguous and fragmented bytes', () => {
        const vectors = createFoundationCanonicalTestVectors();
        expect(vectors.map(({ schemaIdentifier }) => schemaIdentifier)).toEqual(
            foundationCanonicalSchemaIdentifiers,
        );

        for (const { canonicalBytes, name, schemaIdentifier } of vectors) {
            const expectedHex = bytesToHex(canonicalBytes);
            const contiguous = kernel.validateCanonicalFoundationValue({
                canonicalBytesHex: expectedHex,
                schemaIdentifier,
            });
            const fragmented = kernel.validateCanonicalFoundationValue({
                canonicalByteChunksHex:
                    createDeterministicCanonicalByteFragments(
                        canonicalBytes,
                    ).map(bytesToHex),
                canonicalByteLength: canonicalBytes.byteLength,
                schemaIdentifier,
            });

            expect(contiguous.canonicalBytesHex, name).toBe(expectedHex);
            expect(fragmented.canonicalBytesHex, name).toBe(expectedHex);
            expect(fragmented.bindingHash, name).toBe(contiguous.bindingHash);
        }
    });

    it('refuses malformed fragmented foundation bytes', () => {
        const actionDefinitionVector =
            createFoundationCanonicalTestVectors().find(
                (candidate) => candidate.schemaIdentifier === 0x0112,
            );
        if (actionDefinitionVector === undefined) {
            throw new Error('The action-definition vector is missing.');
        }
        const fragments = createDeterministicCanonicalByteFragments(
            actionDefinitionVector.canonicalBytes,
        ).map(bytesToHex);

        expect(() =>
            kernel.validateCanonicalFoundationValue({
                canonicalByteChunksHex: [...fragments, '00'],
                canonicalByteLength:
                    actionDefinitionVector.canonicalBytes.byteLength + 1,
                schemaIdentifier: actionDefinitionVector.schemaIdentifier,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.validateCanonicalFoundationValue({
                canonicalByteChunksHex: fragments.slice(0, -1),
                canonicalByteLength:
                    actionDefinitionVector.canonicalBytes.byteLength,
                schemaIdentifier: actionDefinitionVector.schemaIdentifier,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('agrees on canonical external bytes and context separation', () => {
        const actionBytes = canonicalTuple(
            actionDefinitionSchemaIdentifier,
            unsigned16Item(7),
            unsigned64Item(1_900_000_000_000n),
        );
        const policyBytes = canonicalTuple(
            boardPolicySchemaIdentifier,
            asciiItem('primary-board'),
        );
        const action = kernel.validateCanonicalFoundationValue({
            schemaIdentifier: actionDefinitionSchemaIdentifier,
            canonicalBytesHex: bytesToHex(actionBytes),
        });
        const policy = kernel.validateCanonicalFoundationValue({
            schemaIdentifier: boardPolicySchemaIdentifier,
            canonicalBytesHex: bytesToHex(policyBytes),
        });
        const ceremonyContextHash = kernel.deriveCeremonyContextHash({
            ceremonyIdentifier: 'browser-ceremony',
            manifestHash: '22'.repeat(64),
            rosterHash: '33'.repeat(64),
            suiteId: '11'.repeat(64),
        });
        const actionContextHash = kernel.deriveActionContextHash({
            actionDefinitionHash: action.bindingHash ?? '',
            actionIdentifier: 'browser-action',
            boardPolicyHash: policy.bindingHash ?? '',
            ceremonyContextHash,
        });

        expect(action.canonicalBytesHex).toBe(bytesToHex(actionBytes));
        expect(policy.canonicalBytesHex).toBe(bytesToHex(policyBytes));
        expect(actionContextHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            kernel.deriveActionContextHash({
                actionDefinitionHash: action.bindingHash ?? '',
                actionIdentifier: 'other-browser-action',
                boardPolicyHash: policy.bindingHash ?? '',
                ceremonyContextHash,
            }),
        ).not.toBe(actionContextHash);
    });
});
