import { playwright } from '@vitest/browser-playwright';
import type { BrowserContextOptions } from 'playwright';
import { defineConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

const nodeTestTimeoutMs = 60_000;
const nodeHookTimeoutMs = 240_000;

const nodeProject = {
    environment: 'node',
    testTimeout: nodeTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

type MobileDeviceName = 'Pixel 5' | 'iPhone 12';

const mobileDeviceContextOptions: Record<
    MobileDeviceName,
    BrowserContextOptions
> = {
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
};

const createMobileContextOptions = (
    deviceName: MobileDeviceName,
): BrowserContextOptions => {
    return mobileDeviceContextOptions[deviceName];
};

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
            contextOptions: createMobileContextOptions('Pixel 5'),
        }),
    },
    {
        browser: 'webkit',
        name: 'webkit-mobile',
        provider: playwright({
            contextOptions: createMobileContextOptions('iPhone 12'),
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
