export const byteArraysEqual = (
    left: Uint8Array,
    right: Uint8Array,
): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

export const isArrayBuffer = (value: unknown): value is ArrayBuffer => {
    try {
        return Object.prototype.toString.call(value) === '[object ArrayBuffer]';
    } catch {
        return false;
    }
};

export const isUint8Array = (value: unknown): value is Uint8Array => {
    try {
        return (
            ArrayBuffer.isView(value) &&
            Object.prototype.toString.call(value) === '[object Uint8Array]'
        );
    } catch {
        return false;
    }
};
