import { expect, it } from 'vitest';

import { SeedRecipientReceiptCustody } from '#packages/protocol/src/runtime/seed-recipient-receipt-custody';

it('refuses a JavaScript object that only imitates the recipient-receipt kernel shape', () => {
    const shapeOnlyKernel = Object.freeze({
        authenticatedInventoryAuthorization: () => Object.freeze({}),
        close: (): void => undefined,
        prepare: (): never => {
            throw new Error('Shape-only recipient kernel must not run.');
        },
        produce: (): never => {
            throw new Error('Shape-only recipient kernel must not run.');
        },
        validate: (): void => undefined,
    });

    expect(
        () =>
            new SeedRecipientReceiptCustody({
                kernel: shapeOnlyKernel,
            } as never),
    ).toThrowError(
        expect.objectContaining({
            code: 'InvalidConfiguration',
            message:
                'Seed-recipient receipt custody requires the integrity-pinned production kernel.',
        }),
    );
});
