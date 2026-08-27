import { expect, it } from 'vitest';

import { SeedCatalogSourceCustody } from '#packages/protocol/src/runtime/seed-catalog-source-custody';

it('refuses a JavaScript object that only imitates the seed-catalog source kernel shape', () => {
    const shapeOnlyKernel = Object.freeze({
        produceCatalog: (): never => {
            throw new Error('Shape-only source kernel must not run.');
        },
        produceDeliverySource: (): never => {
            throw new Error('Shape-only source kernel must not run.');
        },
        validateCatalog: (): void => undefined,
        validateDeliverySource: (): void => undefined,
    });

    expect(
        () =>
            new SeedCatalogSourceCustody({
                kernel: shapeOnlyKernel,
            } as never),
    ).toThrowError(
        expect.objectContaining({
            code: 'InvalidConfiguration',
            message:
                'Seed-catalog source custody requires an integrity-pinned production kernel.',
        }),
    );
});
