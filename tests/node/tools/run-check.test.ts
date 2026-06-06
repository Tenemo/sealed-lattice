import { describe, expect, it } from 'vitest';

import {
    buildParallelLanes,
    parseCheckArguments,
    redrawEnabledForProgressMode,
} from '#tools/ci/run-check';
import type { PackageManagerRunner } from '#tools/ci/run-command';

const packageManagerRunner: PackageManagerRunner = {
    command: 'pnpm',
    commandArgumentsPrefix: [],
    kind: 'pnpm',
};

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

    it('does not rebuild workspace packages from the parallel docs lane', () => {
        const docsLane = buildParallelLanes(packageManagerRunner).find(
            (lane) => lane.name === 'Verify docs',
        );

        expect(docsLane).toBeDefined();
        const commandTexts =
            docsLane?.commands.map((command) =>
                [command.command, ...command.args].join(' '),
            ) ?? [];

        expect(commandTexts).toEqual(
            expect.arrayContaining([
                'pnpm exec del-cli docs/src/content/docs/api/reference',
                'pnpm exec tsx ./node_modules/typedoc/bin/typedoc --options typedoc.config.mjs',
                'pnpm exec tsx ./docs/typedoc/postprocess-site-docs.ts',
                'pnpm exec del-cli docs/dist',
                'pnpm exec astro build --root docs --silent',
            ]),
        );
        expect(commandTexts).not.toContain('pnpm run docs:build');
        expect(commandTexts).not.toContain('pnpm run build');
    });
});
