import {
    collectFocusedRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';
import {
    canonicalTestLaneDefinitions,
    rustTestLanesForInventoryEntry,
    type CanonicalTestLane,
} from './test-lanes.js';

export const validateFocusedRustLaneSelection = (input: {
    readonly lane: CanonicalTestLane;
    readonly testFilter: string;
    readonly tests: readonly RustTestInventoryEntry[];
}): void => {
    if (input.tests.length === 0) {
        throw new Error(
            `${canonicalTestLaneDefinitions[input.lane].rootScript} filter ${input.testFilter} selects zero tests.`,
        );
    }
    const wrongLaneSelections = input.tests.flatMap((test) => {
        const lanes = rustTestLanesForInventoryEntry(test);
        return lanes.length === 1 && lanes[0] === input.lane
            ? []
            : [{ lanes, test }];
    });
    if (wrongLaneSelections.length > 0) {
        const firstSelection = wrongLaneSelections[0];
        if (firstSelection.lanes.length > 1) {
            throw new Error(
                `${canonicalTestLaneDefinitions[input.lane].rootScript} filter ${input.testFilter} selects ${firstSelection.test.testName}, which is owned by multiple canonical lanes: ${firstSelection.lanes.join(', ')}.`,
            );
        }
        const correctLane = firstSelection.lanes[0];
        const correctCommand =
            correctLane === undefined
                ? 'an updated canonical lane registry'
                : canonicalTestLaneDefinitions[correctLane].rootScript;
        throw new Error(
            `${canonicalTestLaneDefinitions[input.lane].rootScript} filter ${input.testFilter} selects ${firstSelection.test.testName}, which belongs to ${correctCommand}.`,
        );
    }
};

export const verifyFocusedRustLaneSelection = (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly lane: CanonicalTestLane;
    readonly testFilter: string;
}): void => {
    validateFocusedRustLaneSelection({
        lane: input.lane,
        testFilter: input.testFilter,
        tests: collectFocusedRustKernelTestInventory({
            environment: input.environment,
            testFilter: input.testFilter,
        }),
    });
};
