import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    buildGatingLanes,
    buildParallelLanes,
    parseCheckArguments,
    redrawEnabledForProgressMode,
    rustKernelFastTestArguments,
    rustKernelHeavyTestPattern,
} from '#tools/ci/run-check';

const packageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm.cjs'],
    kind: 'pnpm',
} as const satisfies PackageManagerRunner;

const defaultCheckCommandArguments = (): readonly string[] =>
    [
        ...buildGatingLanes(packageManagerRunner),
        ...buildParallelLanes(packageManagerRunner),
    ].flatMap((lane) =>
        lane.commands.flatMap((command) => [command.command, ...command.args]),
    );

describe('check runner arguments', () => {
    it('uses automatic progress rendering by default', () => {
        expect(parseCheckArguments([])).toEqual({
            progressMode: 'auto',
        });
    });

    it('accepts explicit progress rendering modes', () => {
        expect(parseCheckArguments(['--progress=always'])).toEqual({
            progressMode: 'always',
        });
        expect(parseCheckArguments(['--progress', 'never'])).toEqual({
            progressMode: 'never',
        });
    });

    it('rejects unknown check arguments and progress modes', () => {
        expect(() => parseCheckArguments(['--progress=sometimes'])).toThrow(
            'Usage: run-check.ts [--no-run-log] [--progress=auto|always|never].',
        );
        expect(() => parseCheckArguments(['--unknown'])).toThrow(
            'Usage: run-check.ts [--no-run-log] [--progress=auto|always|never].',
        );
    });

    it('does not redraw forced progress on a non-terminal stream', () => {
        expect(redrawEnabledForProgressMode('always', true)).toBe(true);
        expect(redrawEnabledForProgressMode('always', false)).toBe(false);
        expect(redrawEnabledForProgressMode('auto', false)).toBeUndefined();
        expect(redrawEnabledForProgressMode('never', true)).toBe(false);
    });

    it('keeps accepted setup heavy evidence manual in the default check plan', () => {
        const commandArguments = defaultCheckCommandArguments();

        expect(commandArguments).not.toContain('test:rust:kernel:heavy');
        expect(commandArguments).not.toContain(
            'test:rust:kernel:heavy:iterate',
        );
        expect(commandArguments).not.toContain(
            'test:rust:kernel:heavy:required',
        );
        expect(commandArguments).not.toContain(
            'test:direct-ballot:setup-handoff:evidence',
        );
        expect(rustKernelFastTestArguments).toEqual(
            expect.arrayContaining(['--skip', rustKernelHeavyTestPattern]),
        );
        expect(rustKernelFastTestArguments).not.toContain('--ignored');
    });
});
