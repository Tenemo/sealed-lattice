import type { ActiveLocalRunLog } from './local-run-log.js';
import type { CommandInvocation } from './run-command.js';
import { heavyRustKernelTestNamePrefix } from './rust-kernel-test-arguments.js';
import {
    collectRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

type FocusedRustLane = 'rust-kernel-fast' | 'rust-kernel-heavy';

export const focusedRustLaneScripts = {
    'rust-kernel-fast': 'test:rust:kernel',
    'rust-kernel-heavy': 'test:rust:kernel:heavy',
} as const satisfies Record<FocusedRustLane, string>;

const ownersForTest = (test: RustTestInventoryEntry): FocusedRustLane[] => {
    const owners: FocusedRustLane[] = [];
    if (test.testName.includes(heavyRustKernelTestNamePrefix)) {
        owners.push('rust-kernel-heavy');
    }
    if (!test.ignored) {
        owners.push('rust-kernel-fast');
    }

    return owners;
};

const rustLaneOwnerDescription = (owner: FocusedRustLane): string =>
    focusedRustLaneScripts[owner];

const rustTestLeafName = (testName: string): string => {
    const nameParts = testName.split('::');
    return nameParts[nameParts.length - 1] ?? testName;
};

export const validateCompleteRustLaneOwnership = (
    tests: readonly RustTestInventoryEntry[],
): void => {
    if (tests.length === 0) {
        throw new Error('The complete Rust kernel test inventory is empty.');
    }

    for (const test of tests) {
        const owners = ownersForTest(test);
        if (owners.length === 1) {
            continue;
        }
        if (owners.length === 0) {
            throw new Error(
                `Ignored Rust test ${test.testName} belongs to no guarded Rust lane.`,
            );
        }
        throw new Error(
            `Rust test ${test.testName} belongs to multiple Rust lanes: ${owners.map(rustLaneOwnerDescription).join(', ')}.`,
        );
    }
};

export const validateFocusedRustLaneSelection = (input: {
    readonly lane: FocusedRustLane;
    readonly testFilter: string;
    readonly tests: readonly RustTestInventoryEntry[];
}): void => {
    const requestedScript = focusedRustLaneScripts[input.lane];
    if (input.tests.length === 0) {
        throw new Error(
            `${requestedScript} filter ${input.testFilter} selects zero tests.`,
        );
    }
    const onlySelectedTest =
        input.tests.length === 1 ? input.tests[0] : undefined;
    if (
        input.lane === 'rust-kernel-heavy' &&
        (onlySelectedTest === undefined ||
            rustTestLeafName(onlySelectedTest.testName) !== input.testFilter)
    ) {
        throw new Error(
            `${requestedScript} filter ${input.testFilter} must select exactly one test with the same leaf name.`,
        );
    }

    for (const test of input.tests) {
        const owners = ownersForTest(test);
        if (owners.length === 1 && owners[0] === input.lane) {
            continue;
        }
        if (owners.length > 1) {
            throw new Error(
                `${requestedScript} filter ${input.testFilter} selects ${test.testName}, which belongs to multiple Rust lanes: ${owners.map(rustLaneOwnerDescription).join(', ')}.`,
            );
        }
        const correctScript =
            owners.length === 0
                ? 'a dedicated guarded command'
                : rustLaneOwnerDescription(owners[0]);
        throw new Error(
            `${requestedScript} filter ${input.testFilter} selects ${test.testName}, which belongs to ${correctScript}.`,
        );
    }
};

export const verifyFocusedRustLaneSelection = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly lane: FocusedRustLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
    readonly useReleaseProfile?: boolean;
}): Promise<void> => {
    const completeTestInventory = await collectRustKernelTestInventory({
        ...(input.cargoFeatures === undefined
            ? {}
            : { cargoFeatures: input.cargoFeatures }),
        environment: input.environment,
        ...(input.inventoryCommandTransform === undefined
            ? {}
            : {
                  inventoryCommandTransform: input.inventoryCommandTransform,
              }),
        runLog: input.runLog,
        useReleaseProfile: input.useReleaseProfile,
    });
    validateCompleteRustLaneOwnership(completeTestInventory);
    validateFocusedRustLaneSelection({
        lane: input.lane,
        testFilter: input.testFilter,
        tests: completeTestInventory.filter((test) =>
            test.testName.includes(input.testFilter),
        ),
    });
};

export const verifyCompleteRustLaneOwnership = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly runLog?: ActiveLocalRunLog;
    readonly useReleaseProfile?: boolean;
}): Promise<void> => {
    validateCompleteRustLaneOwnership(
        await collectRustKernelTestInventory(input),
    );
};
