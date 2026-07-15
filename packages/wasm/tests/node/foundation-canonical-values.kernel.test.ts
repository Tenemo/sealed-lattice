import { beforeAll, describe, expect, it } from 'vitest';

import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    emptyOptionalItem,
    hashItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
    variableValue,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import {
    createDeterministicCanonicalByteFragments,
    createFoundationCanonicalTestVectors,
    foundationCanonicalSchemaIdentifiers,
} from '#packages/wasm/tests/foundation-canonical-test-vectors';

const textEncoder = new TextEncoder();
const manifestSchemaIdentifier = 0x0110;
const optionDefinitionSchemaIdentifier = 0x0111;
const actionDefinitionSchemaIdentifier = 0x0112;
const boardPolicySchemaIdentifier = 0x0113;
const deviceWrappingAssociatedDataSchemaIdentifier = 0x0300;
const localRecordAssociatedDataSchemaIdentifier = 0x0301;
const storageRootRecoveryValueSchemaIdentifier = 0x0302;
const storageRootCommitmentPayloadSchemaIdentifier = 0x0303;
const localRecordKeyInputSchemaIdentifier = 0x0304;
const deviceWrappedStorageRootSchemaIdentifier = 0x0305;
const localRecordEnvelopeSchemaIdentifier = 0x0306;
const localRecordAuthenticatorInputSchemaIdentifier = 0x0307;
const actionStorageDerivationInputSchemaIdentifier = 0x0308;

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const displayTextItem = (value: string): Uint8Array =>
    canonicalItem(0x0c, variableValue(textEncoder.encode(value)));

const fixedBytesItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x01, value);

const participantIdentityItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x07, value);

const decodeCanonicalBase32 = (value: string): Uint8Array => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const decoded = new Uint8Array(Math.floor((value.length * 5) / 8));
    let accumulatedBits = 0;
    let accumulatedValue = 0;
    let outputOffset = 0;
    for (const character of value) {
        const digit = alphabet.indexOf(character);
        if (digit < 0) {
            throw new Error('Recovery text is not canonical base32.');
        }
        accumulatedValue = (accumulatedValue << 5) | digit;
        accumulatedBits += 5;
        while (accumulatedBits >= 8) {
            accumulatedBits -= 8;
            decoded[outputOffset] =
                (accumulatedValue >>> accumulatedBits) & 0xff;
            outputOffset += 1;
        }
        accumulatedValue &= (1 << accumulatedBits) - 1;
    }
    if (outputOffset !== decoded.length || accumulatedValue !== 0) {
        throw new Error(
            'Recovery text has non-canonical trailing base32 bits.',
        );
    }

    return decoded;
};

const firstNestedRawBytes = (tuple: Uint8Array): Uint8Array => {
    const view = new DataView(tuple.buffer, tuple.byteOffset, tuple.byteLength);
    if (view.getUint16(8, true) !== 0x01) {
        throw new Error('The first canonical item is not raw bytes.');
    }
    const itemByteLength = view.getUint32(10, true);
    const itemValue = tuple.subarray(14, 14 + itemByteLength);
    const nestedByteLength = new DataView(
        itemValue.buffer,
        itemValue.byteOffset,
        itemValue.byteLength,
    ).getUint32(0, true);

    return itemValue.slice(4, 4 + nestedByteLength);
};

const nestedTupleListItem = (values: readonly Uint8Array[]): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x09),
            unsigned32LittleEndian(values.length),
            ...values,
        ),
    );

const manifestBytes = (): Uint8Array => {
    const options = Array.from({ length: 20 }, (_unused, optionIndex) =>
        canonicalTuple(
            optionDefinitionSchemaIdentifier,
            unsigned16Item(optionIndex),
            asciiItem(`option-${String(optionIndex)}`),
            displayTextItem(`Option ${String(optionIndex + 1)}`),
        ),
    );

    return canonicalTuple(
        manifestSchemaIdentifier,
        displayTextItem('Canonical foundation test'),
        nestedTupleListItem(options),
    );
};

describe('Canonical foundation values in real WASM', () => {
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
            let contiguous: ReturnType<
                TranscriptCoreKernel['validateCanonicalFoundationValue']
            >;
            let fragmented: ReturnType<
                TranscriptCoreKernel['validateCanonicalFoundationValue']
            >;
            try {
                contiguous = kernel.validateCanonicalFoundationValue({
                    canonicalBytesHex: expectedHex,
                    schemaIdentifier,
                });
                fragmented = kernel.validateCanonicalFoundationValue({
                    canonicalByteChunksHex:
                        createDeterministicCanonicalByteFragments(
                            canonicalBytes,
                        ).map(bytesToHex),
                    canonicalByteLength: canonicalBytes.byteLength,
                    schemaIdentifier,
                });
            } catch (error) {
                throw new Error(
                    `Foundation canonical vector ${name} (schema 0x${schemaIdentifier.toString(16)}) was refused.`,
                    { cause: error },
                );
            }

            expect(contiguous.canonicalBytesHex, name).toBe(expectedHex);
            expect(fragmented.canonicalBytesHex, name).toBe(expectedHex);
            expect(fragmented.bindingHash, name).toBe(contiguous.bindingHash);
        }
    });

    it('refuses fragmented length, truncation, trailing-byte, and schema mismatches', () => {
        const actionDefinitionVector =
            createFoundationCanonicalTestVectors().find(
                (candidate) => candidate.schemaIdentifier === 0x0112,
            );
        if (actionDefinitionVector === undefined) {
            throw new Error('The action-definition vector is missing.');
        }
        const { canonicalBytes, schemaIdentifier } = actionDefinitionVector;
        const chunks =
            createDeterministicCanonicalByteFragments(canonicalBytes).map(
                bytesToHex,
            );

        for (const input of [
            {
                canonicalByteChunksHex: chunks,
                canonicalByteLength: canonicalBytes.byteLength - 1,
                schemaIdentifier,
            },
            {
                canonicalByteChunksHex: chunks.slice(0, -1),
                canonicalByteLength: canonicalBytes.byteLength,
                schemaIdentifier,
            },
            {
                canonicalByteChunksHex: [...chunks, '00'],
                canonicalByteLength: canonicalBytes.byteLength + 1,
                schemaIdentifier,
            },
            {
                canonicalByteChunksHex: chunks,
                canonicalByteLength: canonicalBytes.byteLength,
                schemaIdentifier: 0x0113,
            },
        ]) {
            expect(() =>
                kernel.validateCanonicalFoundationValue(input),
            ).toThrow(TranscriptCoreKernelCommandError);
        }
    });

    it('round-trips external values and derives context hashes from every input', () => {
        const manifest = manifestBytes();
        const actionDefinition = canonicalTuple(
            actionDefinitionSchemaIdentifier,
            unsigned16Item(5),
            unsigned64Item(1_900_000_000_000n),
        );
        const boardPolicy = canonicalTuple(
            boardPolicySchemaIdentifier,
            asciiItem('primary-board'),
        );

        const manifestValidation = kernel.validateCanonicalFoundationValue({
            schemaIdentifier: manifestSchemaIdentifier,
            canonicalBytesHex: bytesToHex(manifest),
        });
        const actionValidation = kernel.validateCanonicalFoundationValue({
            schemaIdentifier: actionDefinitionSchemaIdentifier,
            canonicalBytesHex: bytesToHex(actionDefinition),
        });
        const policyValidation = kernel.validateCanonicalFoundationValue({
            schemaIdentifier: boardPolicySchemaIdentifier,
            canonicalBytesHex: bytesToHex(boardPolicy),
        });

        expect(manifestValidation.canonicalBytesHex).toBe(bytesToHex(manifest));
        expect(actionValidation.canonicalBytesHex).toBe(
            bytesToHex(actionDefinition),
        );
        expect(policyValidation.canonicalBytesHex).toBe(
            bytesToHex(boardPolicy),
        );
        expect(manifestValidation.bindingHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(actionValidation.bindingHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(policyValidation.bindingHash).toMatch(/^[0-9a-f]{128}$/u);

        const ceremonyContextHash = kernel.deriveCeremonyContextHash({
            ceremonyIdentifier: 'ceremony-one',
            manifestHash: manifestValidation.bindingHash ?? '',
            rosterHash: '33'.repeat(64),
            suiteId: '44'.repeat(64),
        });
        const changedCeremonyContextHash = kernel.deriveCeremonyContextHash({
            ceremonyIdentifier: 'ceremony-two',
            manifestHash: manifestValidation.bindingHash ?? '',
            rosterHash: '33'.repeat(64),
            suiteId: '44'.repeat(64),
        });
        expect(ceremonyContextHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(changedCeremonyContextHash).not.toBe(ceremonyContextHash);

        const actionContextHash = kernel.deriveActionContextHash({
            actionDefinitionHash: actionValidation.bindingHash ?? '',
            actionIdentifier: 'action-one',
            boardPolicyHash: policyValidation.bindingHash ?? '',
            ceremonyContextHash,
        });
        expect(actionContextHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            kernel.deriveActionContextHash({
                actionDefinitionHash: actionValidation.bindingHash ?? '',
                actionIdentifier: 'action-one',
                boardPolicyHash: '55'.repeat(64),
                ceremonyContextHash,
            }),
        ).not.toBe(actionContextHash);
    });

    it('round-trips every operative local-storage schema through the WASM foundation decoder', async () => {
        const bindingItems = [
            hashItem(new Uint8Array(64).fill(0x11)),
            hashItem(new Uint8Array(64).fill(0x22)),
            hashItem(new Uint8Array(64).fill(0x33)),
            participantIdentityItem(new Uint8Array(64).fill(0x44)),
        ] as const;
        const actionRandomnessCommitment = new Uint8Array(64).fill(0x55);
        const recordIdentifier = new Uint8Array(64).fill(0x66);
        const ciphertext = textEncoder.encode('authenticated local record');
        const associatedData = canonicalTuple(
            localRecordAssociatedDataSchemaIdentifier,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(actionRandomnessCommitment),
            unsigned16Item(5),
            hashItem(recordIdentifier),
            unsigned64Item(0n),
            unsigned64Item(3n),
            emptyOptionalItem(0x06),
            unsigned64Item(BigInt(ciphertext.byteLength)),
        );
        const nonce = new Uint8Array(12).fill(0x77);
        const tag = new Uint8Array(16).fill(0x88);
        const authenticatorInput = canonicalTuple(
            localRecordAuthenticatorInputSchemaIdentifier,
            variableBytesItem(associatedData),
            fixedBytesItem(nonce),
            variableBytesItem(ciphertext),
            fixedBytesItem(tag),
        );
        const localRecordEnvelope = canonicalTuple(
            localRecordEnvelopeSchemaIdentifier,
            variableBytesItem(associatedData),
            fixedBytesItem(nonce),
            variableBytesItem(ciphertext),
            fixedBytesItem(tag),
            fixedBytesItem(new Uint8Array(32).fill(0x99)),
        );
        const recordKeyInput = canonicalTuple(
            localRecordKeyInputSchemaIdentifier,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(actionRandomnessCommitment),
            unsigned16Item(5),
            hashItem(recordIdentifier),
            unsigned64Item(0n),
        );
        const actionStorageDerivationInput = canonicalTuple(
            actionStorageDerivationInputSchemaIdentifier,
            unsigned16Item(1),
            ...bindingItems,
        );
        const storageRootCommitment = new Uint8Array(64).fill(0xaa);
        const commitmentPayload = canonicalTuple(
            storageRootCommitmentPayloadSchemaIdentifier,
            hashItem(storageRootCommitment),
        );

        const storageWorker = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        const prepared = await storageWorker.createAndStageDeviceWrappingState({
            binding: {
                actionContextHash: new Uint8Array(64).fill(0x33),
                ceremonyContextHash: new Uint8Array(64).fill(0x22),
                participantId: new Uint8Array(64).fill(0x44),
                suiteId: new Uint8Array(64).fill(0x11),
            },
        });
        await storageWorker.commitStagedActionStorageRoot({
            mutationIdentifier: new Uint8Array(32).fill(0xab),
        });
        const recovery = await storageWorker.prepareRecoveryExport({
            activeMutationIdentifier: new Uint8Array(32).fill(0xab),
        });
        const recoveryValue = decodeCanonicalBase32(
            recovery.canonicalRecoveryText,
        );
        const deviceAssociatedData = firstNestedRawBytes(
            prepared.wrappedStorageRoot,
        );

        const canonicalValues = [
            [
                deviceWrappingAssociatedDataSchemaIdentifier,
                deviceAssociatedData,
            ],
            [localRecordAssociatedDataSchemaIdentifier, associatedData],
            [storageRootRecoveryValueSchemaIdentifier, recoveryValue],
            [storageRootCommitmentPayloadSchemaIdentifier, commitmentPayload],
            [localRecordKeyInputSchemaIdentifier, recordKeyInput],
            [
                deviceWrappedStorageRootSchemaIdentifier,
                prepared.wrappedStorageRoot,
            ],
            [localRecordEnvelopeSchemaIdentifier, localRecordEnvelope],
            [localRecordAuthenticatorInputSchemaIdentifier, authenticatorInput],
            [
                actionStorageDerivationInputSchemaIdentifier,
                actionStorageDerivationInput,
            ],
        ] as const;
        for (const [schemaIdentifier, canonicalBytes] of canonicalValues) {
            expect(
                kernel.validateCanonicalFoundationValue({
                    canonicalBytesHex: bytesToHex(canonicalBytes),
                    schemaIdentifier,
                }).canonicalBytesHex,
            ).toBe(bytesToHex(canonicalBytes));
        }

        const mismatchedAuthenticatorInput = canonicalTuple(
            localRecordAuthenticatorInputSchemaIdentifier,
            variableBytesItem(associatedData),
            fixedBytesItem(nonce),
            variableBytesItem(concatenateBytes(ciphertext, Uint8Array.of(0))),
            fixedBytesItem(tag),
        );
        expect(() =>
            kernel.validateCanonicalFoundationValue({
                canonicalBytesHex: bytesToHex(mismatchedAuthenticatorInput),
                schemaIdentifier: localRecordAuthenticatorInputSchemaIdentifier,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        await storageWorker.destroyActiveActionStorageRoot();
    });

    it('refuses trailing bytes, reordered fields, bad Unicode, and unsupported schemas', () => {
        const canonicalManifest = manifestBytes();
        const trailingManifest = concatenateBytes(
            canonicalManifest,
            Uint8Array.of(0),
        );
        const reorderedAction = canonicalTuple(
            actionDefinitionSchemaIdentifier,
            unsigned64Item(1_900_000_000_000n),
            unsigned16Item(5),
        );
        const decomposedDisplayText = canonicalTuple(
            manifestSchemaIdentifier,
            displayTextItem('Cafe\u0301'),
            nestedTupleListItem(
                Array.from({ length: 20 }, (_unused, optionIndex) =>
                    canonicalTuple(
                        optionDefinitionSchemaIdentifier,
                        unsigned16Item(optionIndex),
                        asciiItem(`option-${String(optionIndex)}`),
                        displayTextItem(`Option ${String(optionIndex + 1)}`),
                    ),
                ),
            ),
        );

        for (const [schemaIdentifier, canonicalBytes] of [
            [manifestSchemaIdentifier, trailingManifest],
            [actionDefinitionSchemaIdentifier, reorderedAction],
            [manifestSchemaIdentifier, decomposedDisplayText],
            [0xffff, canonicalManifest],
        ] as const) {
            expect(() =>
                kernel.validateCanonicalFoundationValue({
                    schemaIdentifier,
                    canonicalBytesHex: bytesToHex(canonicalBytes),
                }),
            ).toThrow(TranscriptCoreKernelCommandError);
        }
    });
});
