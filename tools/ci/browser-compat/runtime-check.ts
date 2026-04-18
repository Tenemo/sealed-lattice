import * as publicApi from '../../../src/index';
import { UnsupportedRuntimeError, sha256Hex } from '../../../src/index';

type BrowserCompatibilityReport = {
    readonly directWebCrypto: {
        readonly algorithm: string;
        readonly byteDigest: string;
        readonly textDigest: string;
    };
    readonly library: {
        readonly byteDigest: string;
        readonly errorMessage: string;
        readonly errorName: string;
        readonly exportKeys: readonly string[];
        readonly textDigest: string;
    };
    readonly runtime: {
        readonly language: string;
        readonly userAgent: string;
        readonly viewport: {
            readonly height: number;
            readonly width: number;
        };
    };
};

type BrowserCompatibilityWindow = Window &
    typeof globalThis & {
        runBrowserCompatibilityCheck?: () => Promise<BrowserCompatibilityReport>;
    };

const expectedExportKeys = ['UnsupportedRuntimeError', 'sha256Hex'];
const expectedErrorMessage =
    'sealed-lattice requires globalThis.crypto.subtle.digest.';
const textVectorInput = 'sealed-lattice phase one';
const expectedTextDigest =
    'ebffdb750dd56998d4b1063006b2a588a611969130a9e944808cb9d026b56d3c';
const byteVectorInput = new Uint8Array([
    0x00, 0xff, 0x10, 0x20, 0xaa, 0xbb, 0xcc, 0xdd,
]);
const expectedByteDigest =
    'a73b12b7ce389f472e53ef53e625db20de218bdc1fa4abcc39caca976b38c705';

const assert: (condition: unknown, message: string) => asserts condition = (
    condition: unknown,
    message: string,
): asserts condition => {
    if (!condition) {
        throw new Error(message);
    }
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

const digestBytes = async (value: Uint8Array): Promise<string> => {
    const digest = await globalThis.crypto.subtle.digest(
        'SHA-256',
        Uint8Array.from(value),
    );

    return bytesToHex(new Uint8Array(digest));
};

const runDirectWebCryptoProbe = async (): Promise<
    BrowserCompatibilityReport['directWebCrypto']
> => {
    const textDigest = await digestBytes(
        new TextEncoder().encode(textVectorInput),
    );
    const byteDigest = await digestBytes(byteVectorInput);

    assert(
        textDigest === expectedTextDigest,
        `Direct Web Crypto text digest drifted: ${textDigest}`,
    );
    assert(
        byteDigest === expectedByteDigest,
        `Direct Web Crypto byte digest drifted: ${byteDigest}`,
    );

    return {
        algorithm: 'SHA-256',
        textDigest,
        byteDigest,
    };
};

const runLibraryProbe = async (): Promise<
    BrowserCompatibilityReport['library']
> => {
    const textDigest = await sha256Hex(textVectorInput);
    const byteDigest = await sha256Hex(byteVectorInput);
    const error = new UnsupportedRuntimeError();
    const exportKeys = Object.keys(publicApi).sort();

    assert(
        JSON.stringify(exportKeys) === JSON.stringify(expectedExportKeys),
        `Public browser exports changed unexpectedly: ${exportKeys.join(', ')}`,
    );
    assert(publicApi.sha256Hex === sha256Hex, 'Root sha256Hex export drifted');
    assert(
        !Object.prototype.hasOwnProperty.call(publicApi, 'getWebCrypto'),
        'Internal getWebCrypto helper leaked into the root export surface',
    );
    assert(
        textDigest === expectedTextDigest,
        `Library text digest drifted: ${textDigest}`,
    );
    assert(
        byteDigest === expectedByteDigest,
        `Library byte digest drifted: ${byteDigest}`,
    );
    assert(
        error.name === 'UnsupportedRuntimeError',
        `Unexpected runtime error name: ${error.name}`,
    );
    assert(
        error.message === expectedErrorMessage,
        `Unexpected runtime error message: ${error.message}`,
    );

    return {
        exportKeys,
        textDigest,
        byteDigest,
        errorName: error.name,
        errorMessage: error.message,
    };
};

export const runBrowserCompatibilityCheck =
    async (): Promise<BrowserCompatibilityReport> => {
        assert(typeof TextEncoder !== 'undefined', 'TextEncoder is required');
        assert(
            typeof globalThis.crypto?.subtle?.digest === 'function',
            'crypto.subtle.digest is required for browser compatibility checks',
        );
        assert(typeof navigator !== 'undefined', 'navigator is required');

        return {
            directWebCrypto: await runDirectWebCryptoProbe(),
            library: await runLibraryProbe(),
            runtime: {
                language: navigator.language,
                userAgent: navigator.userAgent,
                viewport: {
                    width: globalThis.innerWidth,
                    height: globalThis.innerHeight,
                },
            },
        };
    };

(window as BrowserCompatibilityWindow).runBrowserCompatibilityCheck =
    runBrowserCompatibilityCheck;
