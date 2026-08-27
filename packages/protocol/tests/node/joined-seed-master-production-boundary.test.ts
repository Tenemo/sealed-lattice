import { expect, it } from 'vitest';

import { JoinedSeedMasterCustody } from '#packages/protocol/src/runtime/joined-seed-master-custody';

it('refuses a JavaScript object that only imitates the joined-custody kernel shape', () => {
    const shapeOnlyKernel = Object.freeze({
        joinAndEncode: (): Uint8Array => new Uint8Array(),
        validateRetained: (): void => undefined,
    });

    expect(
        () =>
            new JoinedSeedMasterCustody({
                kernel: shapeOnlyKernel,
            } as never),
    ).toThrowError(
        expect.objectContaining({
            code: 'InvalidConfiguration',
            message:
                'Joined seed-master custody requires an integrity-pinned production kernel.',
        }),
    );
});
