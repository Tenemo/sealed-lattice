import type { RefusalReason } from '@sealed-lattice/types';

export class FoundationBootstrapInternalError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.name = 'FoundationBootstrapInternalError';
        this.failureCause = failureCause;
    }
}

export class FoundationBootstrapRefusalError extends Error {
    public readonly refusalReason: RefusalReason;

    public constructor(refusalReason: RefusalReason) {
        super(`The foundation bootstrap input was refused: ${refusalReason}.`);
        this.name = 'FoundationBootstrapRefusalError';
        this.refusalReason = refusalReason;
    }
}

export class FoundationBootstrapResourceError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'FoundationBootstrapResourceError';
    }
}
