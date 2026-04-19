import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

type TurboTask = {
    readonly dependsOn?: readonly string[];
};

type TurboConfig = {
    readonly tasks: Record<string, TurboTask>;
};

const turboConfig = JSON.parse(
    readFileSync('turbo.json', 'utf8'),
) as TurboConfig;

const requiredPackageBuildDependencies = [
    'sealed-lattice#build',
    '@sealed-lattice/protocol#build',
    '@sealed-lattice/crypto#build',
    '@sealed-lattice/wasm#build',
    '@sealed-lattice/testkit#build',
] as const;

const taskNamesThatRequireBuiltPackages = [
    '//#test:node:workspace',
    '//#test:browser:workspace',
    '//#coverage:node:workspace',
    '//#docs:api:workspace',
] as const;

describe('Turbo task graph', () => {
    it.each(taskNamesThatRequireBuiltPackages)(
        '%s builds package entry points before consuming them',
        (taskName) => {
            const task = turboConfig.tasks[taskName];

            expect(task).toBeDefined();
            expect(task.dependsOn).toEqual(
                expect.arrayContaining([...requiredPackageBuildDependencies]),
            );
        },
    );
});
