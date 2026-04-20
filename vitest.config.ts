import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const resolveFromRepoRoot = (...segments: string[]): string =>
    path.resolve(repoRoot, ...segments);

const nodeTestTimeoutMs = 60_000;
const nodeHookTimeoutMs = 240_000;

const nodeProject = {
    environment: 'node',
    testTimeout: nodeTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

const mobileContextOptions = {
    'Pixel 5': {
        userAgent:
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.15 Mobile Safari/537.36',
        viewport: {
            width: 393,
            height: 727,
        },
        screen: {
            width: 393,
            height: 851,
        },
        deviceScaleFactor: 2.75,
        isMobile: true,
        hasTouch: true,
    },
    'iPhone 12': {
        userAgent:
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1',
        viewport: {
            width: 390,
            height: 664,
        },
        screen: {
            width: 390,
            height: 844,
        },
        deviceScaleFactor: 3,
        isMobile: true,
        hasTouch: true,
    },
} as const;

const desktopBrowserInstances: BrowserInstanceOption[] = [
    { browser: 'chromium', name: 'chromium-desktop' },
    { browser: 'firefox', name: 'firefox-desktop' },
    { browser: 'webkit', name: 'webkit-desktop' },
];

const mobileBrowserInstances: BrowserInstanceOption[] = [
    {
        browser: 'chromium',
        name: 'chromium-mobile',
        provider: playwright({
            contextOptions: mobileContextOptions['Pixel 5'],
        }),
    },
    {
        browser: 'webkit',
        name: 'webkit-mobile',
        provider: playwright({
            contextOptions: mobileContextOptions['iPhone 12'],
        }),
    },
];

export default defineConfig({
    resolve: {
        alias: {
            'sealed-lattice': resolveFromRepoRoot(
                'packages',
                'sdk',
                'src',
                'index.ts',
            ),
            '@sealed-lattice/protocol': resolveFromRepoRoot(
                'packages',
                'protocol',
                'src',
                'index.ts',
            ),
            '@sealed-lattice/crypto': resolveFromRepoRoot(
                'packages',
                'crypto',
                'src',
                'index.ts',
            ),
            '@sealed-lattice/wasm': resolveFromRepoRoot(
                'packages',
                'wasm',
                'src',
                'index.ts',
            ),
            '@sealed-lattice/testkit': resolveFromRepoRoot(
                'packages',
                'testkit',
                'src',
                'index.ts',
            ),
        },
    },
    test: {
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json-summary', 'lcov'],
            reportsDirectory: './coverage',
            include: [
                'packages/wasm/src/**/*.ts',
                'tools/generate-coverage-badge.ts',
                'tools/ci/check-package-boundaries.ts',
            ],
            exclude: [
                'packages/*/src/**/*.d.ts',
                'tools/ci/build-wasm-kernel.ts',
            ],
            thresholds: {
                statements: 100,
                branches: 100,
                functions: 100,
                lines: 100,
            },
        },
        projects: [
            {
                test: {
                    name: 'node',
                    include: [
                        'packages/*/tests/node/**/*.test.ts',
                        'tests/node/**/*.test.ts',
                    ],
                    ...nodeProject,
                },
            },
            {
                test: {
                    name: 'browser-desktop',
                    include: ['packages/*/tests/browser/**/*.browser.test.ts'],
                    browser: {
                        enabled: true,
                        provider: playwright(),
                        headless: true,
                        instances: desktopBrowserInstances,
                    },
                },
            },
            {
                test: {
                    name: 'browser-mobile',
                    include: ['packages/*/tests/browser/**/*.browser.test.ts'],
                    browser: {
                        enabled: true,
                        provider: playwright(),
                        headless: true,
                        instances: mobileBrowserInstances,
                    },
                },
            },
        ],
    },
});
