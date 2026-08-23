import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
    buildSelectedLatticeEstimatorDockerArguments,
    estimatorSourceTreeSha256,
    parseSelectedLatticeEvidenceArguments,
} from '#tools/ci/run-selected-lattice-security-evidence';
import {
    buildSelectedLatticeEstimatorInput,
    canonicalJsonSha256,
    parseJsonValue,
    selectedLatticeEstimatorContainerImage,
    selectedLatticeEstimatorRevision,
    selectedLatticeEstimatorSourceTreeSha256,
    selectedLatticeEvidencePath,
    validateSelectedLatticeEvidence,
    type JsonValue,
} from '#tools/ci/selected-lattice-security-evidence';

const requireRecord = (value: unknown): Record<string, unknown> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('Expected an object in the test record.');
    }
    return value as Record<string, unknown>;
};

const requireArray = (value: unknown): unknown[] => {
    if (!Array.isArray(value)) {
        throw new Error('Expected an array in the test record.');
    }
    return value;
};

const hostileRecord = (
    evidence: JsonValue,
    mutate: (record: Record<string, unknown>) => void,
): JsonValue => {
    const record = structuredClone(evidence) as Record<string, unknown>;
    mutate(record);
    delete record.outputPayloadSha256;
    record.outputPayloadSha256 = canonicalJsonSha256(
        record as unknown as JsonValue,
    );
    return record as unknown as JsonValue;
};

describe('Selected lattice-security evidence', () => {
    let expectedInput: Awaited<
        ReturnType<typeof buildSelectedLatticeEstimatorInput>
    >;
    let checkedEvidence: JsonValue;

    beforeAll(async () => {
        expectedInput = await buildSelectedLatticeEstimatorInput();
        checkedEvidence = parseJsonValue(
            await readFile(selectedLatticeEvidencePath, 'utf8'),
        );
    });

    it('derives the exact selected topology, sample census, and corruption cases from production source', () => {
        const input = requireRecord(expectedInput);
        const topology = requireRecord(input.topology);
        expect(topology).toMatchObject({
            polynomialDegree: 32_768,
            plaintextModulus: 257,
            dataPrimesPerDecompositionBlock: 3,
            evaluatorWorkingLevel: 22,
            relinearizationLevels: [22],
            targetCiphertextLevel: 7,
            participantCount: 10,
            optionCount: 10,
        });
        expect(requireArray(topology.orderedDataPrimes)).toHaveLength(23);
        expect(requireArray(topology.orderedSpecialPrimes)).toHaveLength(3);
        expect(topology.galoisKeySchedule).toEqual([
            { catalogLevel: 14, galoisElement: 15 },
            { catalogLevel: 14, galoisElement: 19 },
            { catalogLevel: 14, galoisElement: 219 },
            { catalogLevel: 18, galoisElement: 257 },
            { catalogLevel: 18, galoisElement: 1_025 },
            { catalogLevel: 18, galoisElement: 8_193 },
        ]);

        const sampleCensus = requireRecord(input.sampleCensus);
        expect(sampleCensus.setupSummary).toEqual({
            sourceRelationCountPerParticipant: 61,
            sourceRelationCountForRoster: 610,
            deterministicDerivedRelationCount: 61,
            completePublicRelationCount: 671,
            finalRuntimeKeyRelationCount: 45,
            commonUniformPolynomialCount: 45,
            generatedComponentViewCount: 724,
            distinctPublicPolynomialCount: 716,
            duplicateComponentViewCount: 8,
        });

        const distributions = requireRecord(input.distributions);
        const corruptionCases = requireArray(distributions.corruptionCases);
        expect(
            corruptionCases.map((value) => {
                const corruptionCase = requireRecord(value);
                const collectiveSecret = requireRecord(
                    corruptionCase.collectiveSecretCoefficientDistribution,
                );
                const aggregateError = requireRecord(
                    corruptionCase.honestAggregateErrorCoefficientDistribution,
                );
                return {
                    corruptionCount: corruptionCase.corruptionCount,
                    honestContributionCount:
                        corruptionCase.honestContributionCount,
                    secretSupport: collectiveSecret.supportBeforeKnownShift,
                    errorSupport: aggregateError.support,
                };
            }),
        ).toEqual([
            {
                corruptionCount: 0,
                honestContributionCount: 10,
                secretSupport: [-10, 10],
                errorSupport: [-20, 20],
            },
            {
                corruptionCount: 1,
                honestContributionCount: 9,
                secretSupport: [-9, 9],
                errorSupport: [-18, 18],
            },
            {
                corruptionCount: 2,
                honestContributionCount: 8,
                secretSupport: [-8, 8],
                errorSupport: [-16, 16],
            },
            {
                corruptionCount: 3,
                honestContributionCount: 7,
                secretSupport: [-7, 7],
                errorSupport: [-14, 14],
            },
        ]);
    });

    it('validates the exact-profile checked record with complete attack coverage and candid scope', () => {
        const summary = validateSelectedLatticeEvidence(
            checkedEvidence,
            expectedInput,
        );
        expect(summary).toEqual({
            minimumClassicalSecurityBitsLowerBound: 138.308922768794,
            minimumQuantumSecurityBitsLowerBound: 123.127188561514,
        });

        const input = requireRecord(requireRecord(checkedEvidence).input);
        expect(input.estimator).toMatchObject({
            revision: selectedLatticeEstimatorRevision,
            sourceTreeSha256: selectedLatticeEstimatorSourceTreeSha256,
            containerImageReference: selectedLatticeEstimatorContainerImage,
            sageVersion: '9.5',
            attacks: ['primalUsvp', 'primalBdd', 'dual', 'dualHybrid'],
        });
        expect(requireArray(input.diagnosticCases)).toHaveLength(7);
        expect(requireArray(input.limitations).join('\n')).toContain(
            'do not establish joint circular or KDM security',
        );
        expect(requireArray(input.limitations).join('\n')).toContain(
            'not an RLWE reduction or proof',
        );
    });

    it('refuses stale inputs, altered geometry, missing attacks, invalid dimensions, and inconsistent minima', () => {
        const wrongDigest = structuredClone(checkedEvidence) as Record<
            string,
            unknown
        >;
        wrongDigest.outputPayloadSha256 = '00'.repeat(32);
        expect(() =>
            validateSelectedLatticeEvidence(
                wrongDigest as unknown as JsonValue,
                expectedInput,
            ),
        ).toThrow('The output payload digest does not match.');

        const staleOptionCountInput = hostileRecord(
            checkedEvidence,
            (record) => {
                const input = requireRecord(record.input);
                const topology = requireRecord(input.topology);
                topology.optionCount = 20;
            },
        );
        expect(() =>
            validateSelectedLatticeEvidence(
                staleOptionCountInput,
                expectedInput,
            ),
        ).toThrow('The estimator evidence input is stale or mismatched.');

        const wrongModulus = hostileRecord(checkedEvidence, (record) => {
            const firstEstimate = requireRecord(
                requireArray(record.estimates)[0],
            );
            firstEstimate.modulusLog2LowerBound = 1;
        });
        expect(() =>
            validateSelectedLatticeEvidence(wrongModulus, expectedInput),
        ).toThrow(
            'An estimator modulus logarithm does not match its exact input case.',
        );

        const missingAttack = hostileRecord(checkedEvidence, (record) => {
            const firstEstimate = requireRecord(
                requireArray(record.estimates)[0],
            );
            const classicalModel = requireRecord(
                requireRecord(firstEstimate.models).classical,
            );
            delete requireRecord(classicalModel.attacks).dualHybrid;
        });
        expect(() =>
            validateSelectedLatticeEvidence(missingAttack, expectedInput),
        ).toThrow('classical attack coverage is incomplete or unexpected.');

        const excessiveSamples = hostileRecord(checkedEvidence, (record) => {
            const firstEstimate = requireRecord(
                requireArray(record.estimates)[0],
            );
            const classicalModel = requireRecord(
                requireRecord(firstEstimate.models).classical,
            );
            const dualAttack = requireRecord(
                requireRecord(classicalModel.attacks).dual,
            );
            dualAttack.usedScalarSamples = 32_769;
        });
        expect(() =>
            validateSelectedLatticeEvidence(excessiveSamples, expectedInput),
        ).toThrow('classical dual used more scalar samples than supplied.');

        const wrongMinimum = hostileRecord(checkedEvidence, (record) => {
            const firstEstimate = requireRecord(
                requireArray(record.estimates)[0],
            );
            const classicalModel = requireRecord(
                requireRecord(firstEstimate.models).classical,
            );
            classicalModel.minimumSecurityBitsLowerBound = 1;
        });
        expect(() =>
            validateSelectedLatticeEvidence(wrongMinimum, expectedInput),
        ).toThrow('classical minimum does not match the attack rows.');
    });

    it('parses only the explicit record-refresh option', () => {
        expect(parseSelectedLatticeEvidenceArguments([])).toEqual({
            writeRecord: false,
        });
        expect(parseSelectedLatticeEvidenceArguments(['--'])).toEqual({
            writeRecord: false,
        });
        expect(
            parseSelectedLatticeEvidenceArguments(['--write-record']),
        ).toEqual({ writeRecord: true });
        expect(() =>
            parseSelectedLatticeEvidenceArguments(['--unknown']),
        ).toThrow(
            'The lattice-security evidence runner accepts only --write-record.',
        );
        expect(() =>
            parseSelectedLatticeEvidenceArguments([
                '--write-record',
                '--write-record',
            ]),
        ).toThrow(
            'The lattice-security evidence runner accepts only --write-record.',
        );
    });

    it('builds a network-isolated immutable estimator invocation with read-only mounts', () => {
        const repositoryRootPath = path.resolve('selected-lattice-repository');
        const estimatorSourceRootPath = path.resolve(
            'selected-lattice-estimator-source',
        );
        const estimatorInputPath = path.join(
            repositoryRootPath,
            'logs',
            'exact-run',
            'estimator-input.json',
        );
        const arguments_ = buildSelectedLatticeEstimatorDockerArguments({
            estimatorInputPath,
            estimatorSourceRootPath,
            repositoryRootPath,
        });

        expect(arguments_).toEqual([
            'run',
            '--rm',
            '--network',
            'none',
            '--entrypoint',
            '/usr/bin/sage',
            '--mount',
            `type=bind,source=${repositoryRootPath},target=/workspace,readonly`,
            '--mount',
            `type=bind,source=${estimatorSourceRootPath},target=/lattice-estimator,readonly`,
            '--env',
            'PYTHONPATH=/lattice-estimator',
            '--env',
            `SEALED_LATTICE_ESTIMATOR_REVISION=${selectedLatticeEstimatorRevision}`,
            '--env',
            `SEALED_LATTICE_ESTIMATOR_CONTAINER_IMAGE=${selectedLatticeEstimatorContainerImage}`,
            '--env',
            'SEALED_LATTICE_ESTIMATOR_SOURCE_ROOT=/lattice-estimator',
            '--workdir',
            '/workspace',
            selectedLatticeEstimatorContainerImage,
            '--python',
            '/workspace/tools/ci/selected-lattice-security-estimator.py',
            '--input',
            '/workspace/logs/exact-run/estimator-input.json',
        ]);

        expect(() =>
            buildSelectedLatticeEstimatorDockerArguments({
                estimatorInputPath: path.resolve('outside-input.json'),
                estimatorSourceRootPath,
                repositoryRootPath,
            }),
        ).toThrow('The estimator input must stay inside the repository.');
    });

    it('hashes estimator sources in ordinal path order and excludes Git metadata', async () => {
        const temporaryRootPath = await mkdtemp(
            path.join(tmpdir(), 'selected-lattice-estimator-tree-'),
        );
        try {
            await mkdir(path.join(temporaryRootPath, 'nested'));
            await writeFile(path.join(temporaryRootPath, 'B.txt'), 'upper');
            await writeFile(path.join(temporaryRootPath, 'a.txt'), 'lower');
            await writeFile(
                path.join(temporaryRootPath, 'nested', 'z.txt'),
                'nested',
            );
            const expectedDigest = createHash('sha256');
            for (const [relativePath, payload] of [
                ['B.txt', 'upper'],
                ['a.txt', 'lower'],
                ['nested/z.txt', 'nested'],
            ] as const) {
                expectedDigest.update(relativePath, 'utf8');
                expectedDigest.update(Buffer.from([0]));
                expectedDigest.update(payload, 'utf8');
                expectedDigest.update(Buffer.from([0]));
            }
            const baselineDigest =
                await estimatorSourceTreeSha256(temporaryRootPath);
            expect(baselineDigest).toBe(expectedDigest.digest('hex'));

            await mkdir(path.join(temporaryRootPath, '.git'));
            await writeFile(
                path.join(temporaryRootPath, '.git', 'ignored-object'),
                'ignored',
            );
            expect(await estimatorSourceTreeSha256(temporaryRootPath)).toBe(
                baselineDigest,
            );

            await writeFile(path.join(temporaryRootPath, 'a.txt'), 'changed');
            expect(await estimatorSourceTreeSha256(temporaryRootPath)).not.toBe(
                baselineDigest,
            );
        } finally {
            await rm(temporaryRootPath, { recursive: true, force: true });
        }
    });
});
