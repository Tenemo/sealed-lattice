import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

import { getMobileContextOptions } from './tools/ci/browser-compat/mobile-context-options';

const nodeTestTimeoutMs = 60_000;
const nodeHookTimeoutMs = 240_000;

const nodeProject = {
    environment: 'node',
    testTimeout: nodeTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
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
            contextOptions: getMobileContextOptions('Pixel 5'),
        }),
    },
    {
        browser: 'webkit',
        name: 'webkit-mobile',
        provider: playwright({
            contextOptions: getMobileContextOptions('iPhone 12'),
        }),
    },
];

export default defineConfig({
    test: {
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json-summary', 'lcov'],
            reportsDirectory: './coverage',
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.d.ts'],
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
                    include: ['tests/node/**/*.test.ts'],
                    ...nodeProject,
                },
            },
            {
                test: {
                    name: 'browser-desktop',
                    exclude: ['tests/browser/mobile.browser.test.ts'],
                    include: ['tests/browser/**/*.browser.test.ts'],
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
                    include: ['tests/browser/**/*.browser.test.ts'],
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
