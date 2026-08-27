import { expect, it } from 'vitest';

import { SeedMailboxSenderStreamCustody } from '#packages/protocol/src/runtime/seed-mailbox-sender-stream-custody';

it('refuses a JavaScript object that only imitates the sender-mailbox kernel shape', () => {
    const shapeOnlyKernel = Object.freeze({
        close: (): void => undefined,
        produce: (): never => {
            throw new Error('Shape-only sender kernel must not run.');
        },
        validate: (): void => undefined,
    });

    expect(
        () =>
            new SeedMailboxSenderStreamCustody({
                kernel: shapeOnlyKernel,
            } as never),
    ).toThrowError(
        expect.objectContaining({
            code: 'InvalidConfiguration',
            message:
                'Seed-mailbox sender custody requires the integrity-pinned production kernel.',
        }),
    );
});
