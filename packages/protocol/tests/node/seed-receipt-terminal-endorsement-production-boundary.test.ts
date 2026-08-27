import { expect, it } from 'vitest';

import { SeedReceiptTerminalEndorsementCustody } from '#packages/protocol/src/runtime/seed-receipt-terminal-endorsement-custody';

it('refuses a JavaScript object that only imitates the receipt-terminal endorsement kernel shape', () => {
    const shapeOnlyKernel = Object.freeze({
        close: (): void => undefined,
        prepare: (): never => {
            throw new Error('Shape-only endorsement kernel must not run.');
        },
        produce: (): never => {
            throw new Error('Shape-only endorsement kernel must not run.');
        },
        validate: (): void => undefined,
    });

    expect(
        () =>
            new SeedReceiptTerminalEndorsementCustody({
                kernel: shapeOnlyKernel,
            } as never),
    ).toThrowError(
        expect.objectContaining({
            code: 'InvalidConfiguration',
            message:
                'Seed-receipt terminal endorsement custody requires an integrity-pinned production kernel.',
        }),
    );
});
