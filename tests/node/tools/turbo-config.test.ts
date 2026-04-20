import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

type TurboTask = {
    readonly dependsOn?: readonly string[];
    readonly outputs?: readonly string[];
};

type TurboConfig = {
    readonly tasks: Record<string, TurboTask>;
};

const turboConfig = JSON.parse(
    readFileSync('turbo.json', 'utf8'),
) as TurboConfig;

describe('Turbo task graph', () => {
    it('uses a single package build task graph', () => {
        expect(turboConfig.tasks.build).toEqual({
            dependsOn: ['^build'],
            outputs: ['dist/**'],
        });
    });

    it('uses a single package check task graph', () => {
        expect(turboConfig.tasks.check).toEqual({
            dependsOn: ['^check'],
            outputs: [],
        });
    });

    it('does not keep duplicate root task aliases', () => {
        expect(Object.keys(turboConfig.tasks)).toEqual(['build', 'check']);
        expect(
            Object.keys(turboConfig.tasks).some((taskName) =>
                taskName.startsWith('//#'),
            ),
        ).toBe(false);
    });
});
