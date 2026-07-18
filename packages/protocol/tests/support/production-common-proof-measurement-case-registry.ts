import type {
    DesktopBrowserProofExecutionKind,
    ProductionDesktopBrowserCommonProofMeasurementCase,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';

type ProductionCommonProofMeasurementCasePair = Readonly<{
    fresh: ProductionDesktopBrowserCommonProofMeasurementCase;
    resumed: ProductionDesktopBrowserCommonProofMeasurementCase;
}>;

export type CompleteProductionCommonProofMeasurementCaseSet = Readonly<{
    ballotValidity: ProductionCommonProofMeasurementCasePair;
    evaluatorKeyAggregateCompleteList: ProductionCommonProofMeasurementCasePair;
    galoisKeyShareBatch: ProductionCommonProofMeasurementCasePair;
    vssShareLinkage: ProductionCommonProofMeasurementCasePair;
}>;

type RequiredProductionCommonProofMeasurementCase = Readonly<{
    caseIdentifier: string;
    executionKind: DesktopBrowserProofExecutionKind;
}>;

export const orderedProductionCommonProofMeasurementCases = Object.freeze([
    Object.freeze({
        caseIdentifier: 'galois-key-share-batch-fresh',
        executionKind: 'fresh',
    }),
    Object.freeze({
        caseIdentifier: 'galois-key-share-batch-resumed',
        executionKind: 'resumed',
    }),
    Object.freeze({
        caseIdentifier: 'vss-share-linkage-fresh',
        executionKind: 'fresh',
    }),
    Object.freeze({
        caseIdentifier: 'vss-share-linkage-resumed',
        executionKind: 'resumed',
    }),
    Object.freeze({
        caseIdentifier: 'evaluator-key-aggregate-complete-list-fresh',
        executionKind: 'fresh',
    }),
    Object.freeze({
        caseIdentifier: 'evaluator-key-aggregate-complete-list-resumed',
        executionKind: 'resumed',
    }),
    Object.freeze({
        caseIdentifier: 'ballot-validity-fresh',
        executionKind: 'fresh',
    }),
    Object.freeze({
        caseIdentifier: 'ballot-validity-resumed',
        executionKind: 'resumed',
    }),
] as const satisfies readonly RequiredProductionCommonProofMeasurementCase[]);

const requireMeasurementCase = (
    measurementCase: ProductionDesktopBrowserCommonProofMeasurementCase,
    requiredCase: RequiredProductionCommonProofMeasurementCase,
): ProductionDesktopBrowserCommonProofMeasurementCase => {
    if (
        measurementCase.caseIdentifier !== requiredCase.caseIdentifier ||
        measurementCase.executionKind !== requiredCase.executionKind ||
        typeof measurementCase.open !== 'function'
    ) {
        throw new Error(
            `The production measurement case must implement ${requiredCase.caseIdentifier} as a ${requiredCase.executionKind} execution.`,
        );
    }
    return measurementCase;
};

export const assembleCompleteProductionCommonProofMeasurementCaseRegistry = (
    caseSet: CompleteProductionCommonProofMeasurementCaseSet,
): readonly ProductionDesktopBrowserCommonProofMeasurementCase[] => {
    const suppliedCases = [
        caseSet.galoisKeyShareBatch.fresh,
        caseSet.galoisKeyShareBatch.resumed,
        caseSet.vssShareLinkage.fresh,
        caseSet.vssShareLinkage.resumed,
        caseSet.evaluatorKeyAggregateCompleteList.fresh,
        caseSet.evaluatorKeyAggregateCompleteList.resumed,
        caseSet.ballotValidity.fresh,
        caseSet.ballotValidity.resumed,
    ] as const;

    return Object.freeze(
        suppliedCases.map((measurementCase, caseIndex) => {
            const requiredCase =
                orderedProductionCommonProofMeasurementCases[caseIndex];
            if (requiredCase === undefined) {
                throw new Error(
                    'The production measurement registry contains an unexpected case.',
                );
            }
            return requireMeasurementCase(measurementCase, requiredCase);
        }),
    );
};
