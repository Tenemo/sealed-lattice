import { UnsupportedRuntimeError } from './errors.js';

type SupportedCrypto = Crypto & {
    subtle: SubtleCrypto;
};

const hasDigest = (value: Crypto | undefined): value is SupportedCrypto =>
    typeof value?.subtle?.digest === 'function';

export const requireWebCrypto = (): SupportedCrypto => {
    const cryptoApi = globalThis.crypto;
    if (!hasDigest(cryptoApi)) {
        throw new UnsupportedRuntimeError();
    }

    return cryptoApi;
};
