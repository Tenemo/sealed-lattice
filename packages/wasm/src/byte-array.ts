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
