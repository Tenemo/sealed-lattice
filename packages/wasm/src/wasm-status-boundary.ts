import type { RefusalReason } from '@sealed-lattice/types';

import { refusalReasonByCode } from './transcript-core-bridge/kernel-errors.js';

const runtimeInternalFailureStatus = 0xffff_ffff;
const runtimeInvalidSessionStatus = 0xffff_fffe;

type WasmStatusBoundaryOptions = Readonly<{
    createInternalError(message: string): Error;
    createRefusalError(refusalReason: RefusalReason): Error;
    createResourceError(): Error;
    internalFailureMessage: string;
    unknownStatusMessage: string;
}>;

export class WasmStatusBoundary {
    readonly #createInternalError: (message: string) => Error;
    readonly #createRefusalError: (refusalReason: RefusalReason) => Error;
    readonly #createResourceError: () => Error;
    readonly #internalFailureMessage: string;
    readonly #unknownStatusMessage: string;

    public constructor(options: WasmStatusBoundaryOptions) {
        this.#createInternalError = options.createInternalError;
        this.#createRefusalError = options.createRefusalError;
        this.#createResourceError = options.createResourceError;
        this.#internalFailureMessage = options.internalFailureMessage;
        this.#unknownStatusMessage = options.unknownStatusMessage;
    }

    public isInvalidSession(status: number): boolean {
        return status >>> 0 === runtimeInvalidSessionStatus;
    }

    public throwIfError(status: number): void {
        const normalizedStatus = status >>> 0;
        if (normalizedStatus === 0) {
            return;
        }
        if (
            normalizedStatus === runtimeInternalFailureStatus ||
            normalizedStatus === runtimeInvalidSessionStatus
        ) {
            throw this.#createInternalError(this.#internalFailureMessage);
        }
        const refusalReason = refusalReasonByCode.get(normalizedStatus);
        if (refusalReason === undefined) {
            throw this.#createInternalError(this.#unknownStatusMessage);
        }
        if (refusalReason === 'outsideSupportedProfile') {
            throw this.#createResourceError();
        }
        throw this.#createRefusalError(refusalReason);
    }
}
