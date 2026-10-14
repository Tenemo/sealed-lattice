import { afterEach, describe, expect, it, vi } from 'vitest';

import { resolvePackageManagerRunner } from '#tools/ci/package-manager-runner.js';

afterEach(() => vi.unstubAllEnvs());

describe('package manager runner', () => {
    it('runs a JavaScript entry point under this Node', () => {
        for (const entryPoint of [
            '/opt/node/lib/node_modules/corepack/dist/pnpm.js',
            'C:\\pnpm\\bin\\pnpm.cjs',
            '/usr/lib/node_modules/pnpm/dist/pnpm.MJS',
        ]) {
            vi.stubEnv('npm_execpath', entryPoint);
            expect(resolvePackageManagerRunner()).toEqual({
                command: process.execPath,
                commandArgumentsPrefix: [entryPoint],
            });
        }
    });

    it('runs a native package-manager executable directly', () => {
        for (const entryPoint of [
            'C:\\corepack\\pnpm\\12.11.2\\pnpm-native.exe',
            '/home/runner/setup-pnpm/node_modules/.bin/pnpm',
            '/opt/pnpm/pnpm.js-native',
        ]) {
            vi.stubEnv('npm_execpath', entryPoint);
            expect(resolvePackageManagerRunner()).toEqual({
                command: entryPoint,
                commandArgumentsPrefix: [],
            });
        }
    });
});
