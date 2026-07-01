import type { PollSpec } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    dynamicRosterParametersCertificateHash,
    targetBoundShareSelectionParameters,
} from './election-foundation-fixture-constants.js';

import {
    deriveFrozenRosterParameters,
    deriveThresholdParameters,
} from '#packages/protocol/src/index';

const invalidDynamicRosterParametersCertificateHash = 'not-a-protocol-hash';
const rosterHash = 'b'.repeat(128);
const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;
const pollSpec = {
    maxRosterSize: 20,
    minRosterSize: 10,
    options: ['Alpha', 'Beta'],
    pollId: 'threshold-thresholdParameters-test',
    question: 'Choose one',
    scoreDomain: {
        max: 10,
        min: 1,
        skippedOptionScore: 1,
    },
    smallRosterPolicy: 'ForbidMicroRoster',
    topOptionCount: 1,
} as const satisfies PollSpec;

const expectFeasibleThresholds = (rosterSize: number): void => {
    const decryptionThreshold = Math.floor(rosterSize / 3) + 1;
    const thresholdParameters = deriveThresholdParameters({
        isCasualMicroRosterAcknowledged: rosterSize < 10,
        dynamicRosterParametersCertificateHash:
            rosterSize >= 10 && rosterSize !== 10
                ? dynamicRosterParametersCertificateHash
                : undefined,
        rosterSize,
        targetBoundShareSelectionParameters: {
            ...targetBoundShareSelectionParameters,
            decryptionShareQuorum: rosterSize,
            minimumSharesForInterpolation: decryptionThreshold,
            minimumArrivalsForRobustDecode: rosterSize,
        },
    });

    expect(
        rosterSize - thresholdParameters.activeFaultBound,
    ).toBeGreaterThanOrEqual(thresholdParameters.decryptionThreshold);
    expect(thresholdParameters.decryptionShareQuorum).toBeGreaterThanOrEqual(
        thresholdParameters.decryptionThreshold,
    );
    expect(thresholdParameters.maximumRaceShares).toBe(rosterSize);
    expect(thresholdParameters.setupCompletionQuorum).toBe(rosterSize);
};

describe('election foundation threshold parameters', () => {
    it.each([
        {
            rosterSize: 10,
            privacyCorruptionBound: 3,
            threshold: 4,
            activeFaultBound: 2,
            releaseQuorum: 10,
        },
        {
            rosterSize: 11,
            privacyCorruptionBound: 3,
            threshold: 4,
            activeFaultBound: 2,
            releaseQuorum: 11,
        },
        {
            rosterSize: 16,
            privacyCorruptionBound: 5,
            threshold: 6,
            activeFaultBound: 3,
            releaseQuorum: 16,
        },
        {
            rosterSize: 20,
            privacyCorruptionBound: 6,
            threshold: 7,
            activeFaultBound: 4,
            releaseQuorum: 20,
        },
    ])(
        'derives structural one-third thresholds for roster size $rosterSize',
        ({
            rosterSize,
            privacyCorruptionBound,
            threshold,
            activeFaultBound,
            releaseQuorum,
        }) => {
            const thresholdParameters = deriveThresholdParameters({
                dynamicRosterParametersCertificateHash:
                    rosterSize === 10
                        ? undefined
                        : dynamicRosterParametersCertificateHash,
                rosterSize,
            });

            expect(thresholdParameters).toMatchObject({
                rosterSize,
                privacyCorruptionBound,
                decryptionCorruptionBound: privacyCorruptionBound,
                decryptionThreshold: threshold,
                decryptionShareQuorum: null,
                targetBoundShareSelectionParameters: null,
                activeFaultBound,
                releaseQuorum,
            });
            expect(thresholdParameters.warnings).toContain(
                'ShareSelectionParametersRequired',
            );
        },
    );

    it('keeps roster size 18 at privacy corruption bound 6 under structural one-third', () => {
        expect(
            deriveThresholdParameters({ rosterSize: 18 })
                .privacyCorruptionBound,
        ).toBe(6);
    });

    it.each([...casualMicroRosterSizes, 10, 11, 16, 20])(
        'keeps threshold feasibility invariants for roster size %d',
        (rosterSize) => {
            expectFeasibleThresholds(rosterSize);
        },
    );

    it('rejects roster sizes below three', () => {
        expect(() => deriveThresholdParameters({ rosterSize: 2 })).toThrow(
            'Roster size must be at least 3.',
        );
    });

    it.each(casualMicroRosterSizes)(
        'requires explicit casual micro-roster acknowledgement for roster size %d',
        (rosterSize) => {
            expect(() => deriveThresholdParameters({ rosterSize })).toThrow(
                'Casual micro-roster parameter sets require explicit acknowledgement.',
            );
        },
    );

    it.each([
        { rosterSize: 3, threshold: 2 },
        { rosterSize: 4, threshold: 2 },
        { rosterSize: 5, threshold: 2 },
        { rosterSize: 6, threshold: 3 },
        { rosterSize: 7, threshold: 3 },
        { rosterSize: 8, threshold: 3 },
        { rosterSize: 9, threshold: 4 },
    ])(
        'marks acknowledged roster size $rosterSize as a casual micro-roster',
        ({ rosterSize, threshold }) => {
            const thresholdParameters = deriveThresholdParameters({
                isCasualMicroRosterAcknowledged: true,
                rosterSize,
            });

            expect(thresholdParameters.rosterParametersKind).toBe(
                'CasualMicroRoster',
            );
            expect(thresholdParameters.releaseQuorum).toBe(rosterSize);
            expect(thresholdParameters.setupCompletionQuorum).toBe(rosterSize);
            expect(thresholdParameters.decryptionThreshold).toBe(threshold);
            expect(thresholdParameters.warnings).toContain('CasualMicroRoster');
        },
    );

    it('marks roster size 10 as the first thresholdParameters roster', () => {
        const thresholdParameters = deriveThresholdParameters({
            rosterSize: 10,
        });

        expect(thresholdParameters.rosterParametersKind).toBe(
            'FirstParametersRoster',
        );
        expect(
            thresholdParameters.dynamicRosterParametersCertificateHash,
        ).toBeNull();
        expect(thresholdParameters.warnings).toEqual([
            'ShareSelectionParametersRequired',
        ]);
    });

    it('keeps first thresholdParameters rosters independent from dynamic roster certificate inputs', () => {
        const baselineParameters = deriveThresholdParameters({
            rosterSize: 10,
        });
        const parametersWithCertificate = deriveThresholdParameters({
            dynamicRosterParametersCertificateHash,
            rosterSize: 10,
        });

        expect(parametersWithCertificate).toEqual(baselineParameters);

        const baselineFrozenRosterParameters = deriveFrozenRosterParameters({
            pollSpec,
            rosterHash,
            rosterSize: 10,
        });
        const frozenRosterParametersWithCertificate =
            deriveFrozenRosterParameters({
                dynamicRosterParametersCertificateHash,
                pollSpec,
                rosterHash,
                rosterSize: 10,
            });

        expect(frozenRosterParametersWithCertificate).toEqual(
            baselineFrozenRosterParameters,
        );
    });

    it('does not carry invalid dynamic roster certificate hashes into first thresholdParameters rosters', () => {
        const thresholdParameters = deriveThresholdParameters({
            dynamicRosterParametersCertificateHash:
                invalidDynamicRosterParametersCertificateHash,
            rosterSize: 10,
        });

        expect(thresholdParameters.rosterParametersKind).toBe(
            'FirstParametersRoster',
        );
        expect(
            thresholdParameters.dynamicRosterParametersCertificateHash,
        ).toBeNull();

        const frozenRosterParameters = deriveFrozenRosterParameters({
            dynamicRosterParametersCertificateHash:
                invalidDynamicRosterParametersCertificateHash,
            pollSpec,
            rosterHash,
            rosterSize: 10,
        });

        expect(
            frozenRosterParameters.dynamicRosterParametersCertificateHash,
        ).toBeNull();
        expect(
            frozenRosterParameters.thresholdParameters
                .dynamicRosterParametersCertificateHash,
        ).toBeNull();
        expect(() =>
            deriveFrozenRosterParameters({
                dynamicRosterParametersCertificateHash:
                    invalidDynamicRosterParametersCertificateHash,
                pollSpec,
                rosterHash,
                rosterSize: 20,
            }),
        ).toThrow(
            'Dynamic roster parameter sets require parameter certificate coverage for the frozen roster size.',
        );
    });

    it.each([11, 16, 20])(
        'marks roster size %d as a certified dynamic thresholdParameters',
        (rosterSize) => {
            const thresholdParameters = deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize,
            });

            expect(thresholdParameters.rosterParametersKind).toBe(
                'SupportedDynamicRosterRange',
            );
            expect(thresholdParameters.warnings).toEqual([
                'ShareSelectionParametersRequired',
            ]);
        },
    );

    it.each([11, 16, 19, 20])(
        'marks roster size %d as uncertified without dynamic evidence',
        (rosterSize) => {
            const thresholdParameters = deriveThresholdParameters({
                rosterSize,
            });

            expect(thresholdParameters.rosterParametersKind).toBe(
                'UncertifiedDynamicRoster',
            );
            expect(thresholdParameters.warnings).toEqual([
                'DynamicRosterParametersCertificateRequired',
                'ShareSelectionParametersRequired',
            ]);
        },
    );

    it('rejects roster sizes above twenty', () => {
        expect(() => deriveThresholdParameters({ rosterSize: 21 })).toThrow(
            'Roster size must be at most 20.',
        );
    });

    it('warns when a certified backend bound exceeds the structural bound', () => {
        const thresholdParameters = deriveThresholdParameters({
            dynamicRosterParametersCertificateHash,
            rosterSize: 20,
            heBackendCorruptionModel: {
                kind: 'CertifiedCustom',
                backendCorruptionBound: 8,
                certificateHash: 'certified-thresholdParameters-hash',
            },
        });

        expect(thresholdParameters.structuralCorruptionBound).toBe(6);
        expect(thresholdParameters.backendCorruptionBound).toBe(8);
        expect(thresholdParameters.privacyCorruptionBound).toBe(6);
        expect(thresholdParameters.warnings).toContain(
            'BackendCorruptionBoundTooHigh',
        );
    });

    it('uses target-bound share-selection output for decryption share quorum', () => {
        const thresholdParameters = deriveThresholdParameters({
            dynamicRosterParametersCertificateHash,
            rosterSize: 20,
            targetBoundShareSelectionParameters,
        });

        expect(thresholdParameters.decryptionThreshold).toBe(7);
        expect(thresholdParameters.decryptionShareQuorum).toBe(9);
        expect(thresholdParameters.targetBoundShareSelectionParameters).toEqual(
            targetBoundShareSelectionParameters,
        );
        expect(thresholdParameters.warnings).not.toContain(
            'ShareSelectionParametersRequired',
        );
    });

    it('rejects unsupported target-bound share-selection thresholdParameters and target-basis bindings', () => {
        expect(() =>
            deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionParameters: {
                    ...targetBoundShareSelectionParameters,
                    targetBasisHash: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection parameters requires a target-basis hash.',
        );
    });

    it('rejects target-bound share-selection parameters that cannot certify safe recombination', () => {
        expect(() =>
            deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionParameters: {
                    ...targetBoundShareSelectionParameters,
                    decryptionShareQuorum: 6,
                },
            }),
        ).toThrow(
            'Target-bound decryption share quorum must be at least the decryption threshold.',
        );

        expect(() =>
            deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionParameters: {
                    ...targetBoundShareSelectionParameters,
                    certificateHash: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection parameters requires a certificate hash.',
        );

        expect(() =>
            deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionParameters: {
                    ...targetBoundShareSelectionParameters,
                    minimumArrivalsForRobustDecode: 8,
                },
            }),
        ).toThrow(
            'Target-bound robust-decode arrival count must be at least the decryption share quorum.',
        );
    });
});
