import { spawnSync } from 'node:child_process';

import {
    canonicalTestLaneDefinitions,
    rustTestLanesForInventoryEntry,
    type CanonicalTestLane,
} from './test-lanes.js';

const parseListedTests = (output: string): readonly string[] =>
    output
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.endsWith(': test'))
        .map((line) => line.slice(0, -': test'.length));

export const validateFocusedRustLaneSelection = (input: {
    readonly lane: CanonicalTestLane;
    readonly testFilter: string;
    readonly testNames: readonly string[];
}): void => {
    if (input.testNames.length === 0) {
        throw new Error(
            `${canonicalTestLaneDefinitions[input.lane].rootScript} filter ${input.testFilter} selects zero tests.`,
        );
    }
    const wrongLaneSelections = input.testNames.flatMap((testName) => {
        const lanes = rustTestLanesForInventoryEntry({
            ignored: false,
            packageName: 'sealed-lattice-kernel',
            testName,
        });
        return lanes.length === 1 && lanes[0] === input.lane
            ? []
            : [{ lanes, testName }];
    });
    if (wrongLaneSelections.length > 0) {
        const firstSelection = wrongLaneSelections[0];
        const correctLane = firstSelection.lanes[0];
        const correctCommand =
            correctLane === undefined
                ? 'an updated canonical lane registry'
                : canonicalTestLaneDefinitions[correctLane].rootScript;
        throw new Error(
            `${canonicalTestLaneDefinitions[input.lane].rootScript} filter ${input.testFilter} selects ${firstSelection.testName}, which belongs to ${correctCommand}.`,
        );
    }
};

export const verifyFocusedRustLaneSelection = (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly lane: CanonicalTestLane;
    readonly testFilter: string;
}): void => {
    const result = spawnSync(
        'cargo',
        [
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            input.testFilter,
            '--',
            '--include-ignored',
            '--list',
            '--format',
            'terse',
        ],
        {
            cwd: process.cwd(),
            encoding: 'utf8',
            env: input.environment ?? process.env,
            maxBuffer: 100 * 1024 * 1024,
        },
    );
    if (result.error !== undefined) {
        throw new Error(
            `Failed to list focused Rust tests: ${result.error.message}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Failed to list focused Rust tests for ${input.testFilter}:\n${result.stderr}${result.stdout}`,
        );
    }
    validateFocusedRustLaneSelection({
        lane: input.lane,
        testFilter: input.testFilter,
        testNames: parseListedTests(result.stdout),
    });
};
