import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

type BgvParametersRejected = {
    readonly isValid: false;
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
    expect(value).toMatchObject({ isValid: false });
    const rejection = value as BgvParametersRejected;
    expect(Array.isArray(rejection.refusedObjects)).toBe(true);
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
        expect(operationRegistry.bgvParametersHash).toBe(
            parameters.bgvParametersHash,
        );
        expect(operationRegistry.registry.allowedOperations).toContain(
            'homomorphicEncryptedBallotAggregation',
        );
    });

    it('encodes direct encrypted ballot aggregate slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeBgvRnsParameters();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            includeCanonicalBytesHex: true,
        });

        const encoded = encodedResult as Exclude<
            typeof encodedResult,
            BgvParametersRejected
        >;
        expect(encoded.validation.isValid).toBe(true);
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expectProtocolHash(encoded.plaintextRoot, 'encoded plaintext root');
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
    });

    it('rejects evaluator operations outside the selected registry', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.validateBgvEvaluatorOperation({
                operation: 'homomorphicEncryptedBallotAggregation',
            }),
        ).toMatchObject({
            isValid: true,
        });
        expectBgvParametersRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'scalarDegree360Comparator',
            }),
            'UncertifiedEvaluatorOperation',
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
});
