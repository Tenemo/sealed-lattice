import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

type BgvParametersRejected = {
    readonly isValid: false;
    readonly unresolvedReason: 'BgvOperationRejected';
    readonly refusedObjects: readonly {
        readonly code: 'BgvOperationRejected';
        readonly reasonCode: string;
        readonly message: string;
    }[];
};

const expectBgvParametersRejected = (
    value: unknown,
    reasonCode?: string,
): BgvParametersRejected => {
    expect(value).toMatchObject({
        isValid: false,
        unresolvedReason: 'BgvOperationRejected',
    });
    const rejection = value as BgvParametersRejected;
    expect(
        rejection.refusedObjects.some(
            (refusedObject) => refusedObject.code === 'BgvOperationRejected',
        ),
    ).toBe(true);
    if (reasonCode !== undefined) {
        expect(rejection.refusedObjects[0]?.reasonCode).toBe(reasonCode);
    }

    return rejection;
};

const expectKernelCommandError = (
    command: () => unknown,
    code: TranscriptCoreKernelCommandError['code'],
    messagePattern: RegExp,
): void => {
    try {
        command();
        throw new Error('Expected a transcript-core kernel command error.');
    } catch (error) {
        expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = error as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe(code);
        expect(commandError.message).toMatch(messagePattern);
    }
};

const expectProtocolHash = (value: string, label: string): void => {
    expect(value, label).toMatch(/^[a-f0-9]{128}$/u);
};

describe('BGV-RNS backend kernel commands', () => {
    it('describes the BGV-RNS parameters and operation boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeBgvRnsParameters();
        const operationRegistry = kernel.describeBgvOperationRegistry() as {
            readonly registry: {
                readonly allowedOperations: readonly string[];
                readonly forbiddenOperations: readonly string[];
            };
            readonly bgvParametersHash: string;
        };

        expect(parameters.parameters).toMatchObject({
            polynomialDegree: 32_768,
            plaintextModulus: 65_537,
            dataPrimeBitLength: 47,
            dataLevels: 17,
            extendedLevels: 18,
        });
        expect(parameters.parameters.dataPrimes).toHaveLength(17);
        expectProtocolHash(parameters.bgvParametersHash, 'bgvParametersHash');
        expect(parameters.batchLayoutBinding).toMatchObject({
            scoreRange: { minimum: 1, maximum: 10 },
            bucketCount: 10,
            slotCount: 32_768,
            coordinatesPerOption: 11,
            scalarOnlyAggregateLayout: false,
        });
        expect(operationRegistry.bgvParametersHash).toBe(
            parameters.bgvParametersHash,
        );
        expect(operationRegistry.registry.allowedOperations).toContain(
            'homomorphicEncryptedBallotAggregation',
        );
        expect(operationRegistry.registry.forbiddenOperations).toContain(
            'scalarDegree360Comparator',
        );
        expect(operationRegistry).not.toHaveProperty(
            'forbiddenOperationRejectionFixtures',
        );
    });

    it('encodes direct encrypted ballot aggregate slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeBgvRnsParameters();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: parameters.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(encodedResult).not.toMatchObject({ isValid: false });
        const encoded = encodedResult as Exclude<
            typeof encodedResult,
            BgvParametersRejected
        >;
        expect(encoded.validation.isValid).toBe(true);
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expectProtocolHash(encoded.plaintextRoot, 'encoded plaintext root');
        expectProtocolHash(
            encoded.canonicalBytesHash512,
            'encoded plaintext canonical bytes hash',
        );
        expect(encoded.canonicalByteLength).toBe(90_311);
        expect(encoded.bgvParametersHash).toBe(parameters.bgvParametersHash);
        expect(encoded.sampledSlots).toEqual(
            expect.arrayContaining([
                { position: 0, value: 0 },
                { position: 1, value: 1 },
                { position: 2, value: 65_536 },
            ]),
        );

        const validated = kernel.validateBgvPlaintextObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
            expectedPlaintextRoot: encoded.plaintextRoot,
        });
        const analyzed = kernel.analyzeBgvCanonicalObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
        }) as {
            readonly objectKind: string;
            readonly coefficientCount: number;
        };

        expect(validated).toMatchObject({
            isValid: true,
            objectKind: 'plaintext',
            plaintextRoot: encoded.plaintextRoot,
            canonicalBytesHash512: encoded.canonicalBytesHash512,
        });
        expect(analyzed).toMatchObject({
            objectKind: 'plaintext',
            coefficientCount: 32_768,
        });
        expectKernelCommandError(
            () =>
                kernel.validateBgvPlaintextObject({
                    canonicalBytesHex: encoded.canonicalBytesHex ?? '',
                    expectedPlaintextRoot: '0'.repeat(128),
                }),
            'ComponentMismatch',
            /plaintext root/u,
        );

        const layoutMutations: readonly Record<string, unknown>[] = [
            {
                ...parameters.batchLayoutBinding,
                bucketCount: 9,
            },
            {
                ...parameters.batchLayoutBinding,
                coordinatesPerOption: 12,
            },
            {
                ...parameters.batchLayoutBinding,
                slotCount: 16_384,
            },
            {
                ...parameters.batchLayoutBinding,
                scoreRange: { minimum: 0, maximum: 10 },
            },
            {
                ...parameters.batchLayoutBinding,
                scalarOnlyAggregateLayout: true,
            },
            {
                ...parameters.batchLayoutBinding,
                unexpectedLayoutField: 'rejected',
            },
        ];
        for (const layoutBinding of layoutMutations) {
            expectKernelCommandError(
                () =>
                    kernel.encodeBgvBatchPlaintext({
                        slots: [1, 2, 3],
                        level: 0,
                        layoutBinding,
                    }),
                'ComponentMismatch',
                /layout binding/u,
            );
        }
    });

    it('rejects evaluator operations outside the selected registry', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.validateBgvEvaluatorOperation({
                operation: 'homomorphicEncryptedBallotAggregation',
            }),
        ).toMatchObject({
            isValid: true,
            acceptedOperation: 'homomorphicEncryptedBallotAggregation',
        });
        expectBgvParametersRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'scalarDegree360Comparator',
            }),
            'ForbiddenEvaluatorOperation',
        );
        expectBgvParametersRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'uncertifiedScoreBitDerivationOperation',
            }),
            'UncertifiedEvaluatorOperation',
        );
        expectBgvParametersRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'adHocEncryptedComparator',
            }),
            'UncertifiedEvaluatorOperation',
        );
    });

    it('validates ciphertext convention fixtures without claiming encryption evidence', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixtureResult = kernel.generateBgvCiphertextConventionFixture({
            leftSlots: [1, 2, 3],
            rightSlots: [4, 5, 6],
            includeCanonicalBytesHex: true,
        });
        expect(fixtureResult).not.toMatchObject({ isValid: false });
        const fixture = fixtureResult as Exclude<
            typeof fixtureResult,
            BgvParametersRejected
        >;

        expectProtocolHash(fixture.ciphertextRoot, 'ciphertext root');
        expectProtocolHash(
            fixture.canonicalBytesHash512,
            'ciphertext canonical bytes hash',
        );
        expect(fixture.canonicalByteLength).toBe(180_521);
        expect(fixture.validation).toMatchObject({
            isValid: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
        expect(
            kernel.validateBgvCiphertextObject({
                canonicalBytesHex: fixture.canonicalBytesHex ?? '',
                expectedCiphertextRoot: fixture.ciphertextRoot,
            }),
        ).toMatchObject({
            isValid: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
    });

    it('keeps base conversion material inside the BGV boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const baseConversionResult = kernel.generateBgvBaseConversionFixture({
            slots: [7, 8, 9, 65_536],
        });
        expect(baseConversionResult).not.toMatchObject({ isValid: false });
        const baseConversion = baseConversionResult as Exclude<
            typeof baseConversionResult,
            BgvParametersRejected
        >;

        expect(baseConversion).toMatchObject({
            convertedBasisId: 'sealed-lattice-bgv-rns-extended-basis-v1',
            convertedModulusCount: 2,
        });
        expectProtocolHash(
            baseConversion.sourcePlaintextRoot,
            'base conversion source plaintext root',
        );
        expectProtocolHash(
            baseConversion.convertedPlaintextRoot,
            'base conversion converted plaintext root',
        );
        expect(baseConversion.convertedPlaintextRoot).not.toBe(
            baseConversion.sourcePlaintextRoot,
        );
    });
});
