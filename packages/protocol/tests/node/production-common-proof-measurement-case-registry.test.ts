import { describe, expect, it } from 'vitest';

import type { ProductionDesktopBrowserCommonProofMeasurementCase } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';
import {
    assembleCompleteProductionCommonProofMeasurementCaseRegistry,
    orderedProductionCommonProofMeasurementCases,
    type CompleteProductionCommonProofMeasurementCaseSet,
} from '#packages/protocol/tests/support/production-common-proof-measurement-case-registry';

const unreachableOpen = (): Promise<never> =>
    Promise.reject(
        new Error('The registry test must not open a measurement session.'),
    );

const measurementCase = (
    caseIdentifier: string,
    executionKind: 'fresh' | 'resumed',
): ProductionDesktopBrowserCommonProofMeasurementCase =>
    Object.freeze({ caseIdentifier, executionKind, open: unreachableOpen });

const completeCaseSet = (): CompleteProductionCommonProofMeasurementCaseSet =>
    Object.freeze({
        ballotValidity: Object.freeze({
            fresh: measurementCase('ballot-validity-fresh', 'fresh'),
            resumed: measurementCase('ballot-validity-resumed', 'resumed'),
        }),
        evaluatorKeyAggregateCompleteList: Object.freeze({
            fresh: measurementCase(
                'evaluator-key-aggregate-complete-list-fresh',
                'fresh',
            ),
            resumed: measurementCase(
                'evaluator-key-aggregate-complete-list-resumed',
                'resumed',
            ),
        }),
        galoisKeyShareBatch: Object.freeze({
            fresh: measurementCase('galois-key-share-batch-fresh', 'fresh'),
            resumed: measurementCase(
                'galois-key-share-batch-resumed',
                'resumed',
            ),
        }),
        vssShareLinkage: Object.freeze({
            fresh: measurementCase('vss-share-linkage-fresh', 'fresh'),
            resumed: measurementCase('vss-share-linkage-resumed', 'resumed'),
        }),
    });

describe('Production common-proof measurement case registry', () => {
    it('assembles all four production families and both execution modes in canonical order', () => {
        const registry =
            assembleCompleteProductionCommonProofMeasurementCaseRegistry(
                completeCaseSet(),
            );

        expect(
            registry.map(({ caseIdentifier, executionKind }) => ({
                caseIdentifier,
                executionKind,
            })),
        ).toEqual(orderedProductionCommonProofMeasurementCases);
        expect(registry).toHaveLength(8);
        expect(Object.isFrozen(registry)).toBe(true);
        expect(
            new Set(registry.map((entry) => entry.caseIdentifier)).size,
        ).toBe(registry.length);
    });

    it('rejects a family pair that is swapped, mislabeled, or assigned the wrong execution mode', () => {
        const swapped = completeCaseSet();
        expect(() =>
            assembleCompleteProductionCommonProofMeasurementCaseRegistry({
                ...swapped,
                galoisKeyShareBatch: Object.freeze({
                    fresh: swapped.galoisKeyShareBatch.resumed,
                    resumed: swapped.galoisKeyShareBatch.fresh,
                }),
            }),
        ).toThrow('galois-key-share-batch-fresh');

        const mislabeled = completeCaseSet();
        expect(() =>
            assembleCompleteProductionCommonProofMeasurementCaseRegistry({
                ...mislabeled,
                vssShareLinkage: Object.freeze({
                    ...mislabeled.vssShareLinkage,
                    fresh: measurementCase(
                        'vss-share-linkage-alternative-fresh',
                        'fresh',
                    ),
                }),
            }),
        ).toThrow('vss-share-linkage-fresh');

        const wrongExecutionKind = completeCaseSet();
        expect(() =>
            assembleCompleteProductionCommonProofMeasurementCaseRegistry({
                ...wrongExecutionKind,
                ballotValidity: Object.freeze({
                    ...wrongExecutionKind.ballotValidity,
                    resumed: measurementCase(
                        'ballot-validity-resumed',
                        'fresh',
                    ),
                }),
            }),
        ).toThrow('ballot-validity-resumed');
    });

    it('rejects a case without an executable worker-session opener', () => {
        const caseSet = completeCaseSet();
        expect(() =>
            assembleCompleteProductionCommonProofMeasurementCaseRegistry({
                ...caseSet,
                evaluatorKeyAggregateCompleteList: Object.freeze({
                    ...caseSet.evaluatorKeyAggregateCompleteList,
                    fresh: {
                        caseIdentifier:
                            'evaluator-key-aggregate-complete-list-fresh',
                        executionKind: 'fresh',
                        open: undefined,
                    } as unknown as ProductionDesktopBrowserCommonProofMeasurementCase,
                }),
            }),
        ).toThrow('evaluator-key-aggregate-complete-list-fresh');
    });
});
