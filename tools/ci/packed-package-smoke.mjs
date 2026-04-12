import * as publicApi from 'sealed-lattice';
import { UnsupportedRuntimeError, sha256Hex } from 'sealed-lattice';

const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const expectedPublicKeys = ['UnsupportedRuntimeError', 'sha256Hex'];

assert(
    JSON.stringify(Object.keys(publicApi).sort()) ===
        JSON.stringify(expectedPublicKeys),
    'Packed package public exports changed unexpectedly',
);

const textDigest = await sha256Hex('sealed-lattice phase one');
assert(
    textDigest ===
        'ebffdb750dd56998d4b1063006b2a588a611969130a9e944808cb9d026b56d3c',
    'Packed package text digest did not match the committed vector',
);

const byteDigest = await sha256Hex(
    new Uint8Array([0x00, 0xff, 0x10, 0x20, 0xaa, 0xbb, 0xcc, 0xdd]),
);
assert(
    byteDigest ===
        'a73b12b7ce389f472e53ef53e625db20de218bdc1fa4abcc39caca976b38c705',
    'Packed package byte digest did not match the committed vector',
);

const runtimeError = new UnsupportedRuntimeError();
assert(
    runtimeError instanceof Error &&
        runtimeError instanceof UnsupportedRuntimeError,
    'Packed package runtime error export is not a usable error class',
);
assert(
    runtimeError.name === 'UnsupportedRuntimeError',
    'Packed package runtime error name changed unexpectedly',
);
assert(
    runtimeError.message ===
        'sealed-lattice requires globalThis.crypto.subtle.digest.',
    'Packed package runtime error message changed unexpectedly',
);

console.log('Packed package public API smoke test passed.');
