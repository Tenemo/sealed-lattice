import type { BrowserContextOptions } from 'playwright';

export type MobileDeviceName = 'Pixel 5' | 'iPhone 12';

const mobileContextOptions: Readonly<
    Record<MobileDeviceName, BrowserContextOptions>
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

export const getMobileContextOptions = (
    deviceName: MobileDeviceName,
): BrowserContextOptions => {
    return mobileContextOptions[deviceName];
};
