/**
 * Error thrown when the current runtime does not provide the Web Crypto API
 * features required by the public package surface.
 */
export class UnsupportedRuntimeError extends Error {
    public constructor(
        message = 'sealed-lattice requires globalThis.crypto.subtle.digest.',
    ) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
