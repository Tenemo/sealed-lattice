import { expect, it } from 'vitest';

import { PublicInputFailure } from '#packages/sdk/src/participant/worker/context.js';
import { discoverContributionOffers } from '#packages/sdk/src/participant/worker/offer-discovery.js';

const identity = (marker: number) => new Uint8Array(64).fill(marker);

it('does not let an endless invalid author starve two ready authors', async () => {
    const pages: [number, number][] = [],
        verified: number[] = [];
    const found = await discoverContributionOffers(
        3,
        2,
        (position, offset) => {
            pages.push([position, offset]);
            return Promise.resolve(
                position === 0
                    ? {
                          total: Number.MAX_SAFE_INTEGER,
                          identities: Array.from({ length: 64 }, () =>
                              identity(0),
                          ),
                      }
                    : { total: 1, identities: [identity(position)] },
            );
        },
        ({ position }) => {
            verified.push(position);
            if (position === 0) throw new PublicInputFailure('Invalid proof.');
            return Promise.resolve();
        },
    );
    expect(found.map((offer) => offer.position)).toEqual([1, 2]);
    expect(verified).toEqual([0, 1, 2]);
    expect(pages).toEqual([
        [0, 0],
        [1, 0],
        [2, 0],
    ]);
});

it('finds later valid entries and returns canonical original-position order', async () => {
    const verified: [number, number][] = [];
    const found = await discoverContributionOffers(
        3,
        2,
        (position) => {
            const identities =
                position === 0
                    ? [identity(10), identity(11), identity(12)]
                    : position === 2
                      ? [identity(20), identity(21)]
                      : [];
            return Promise.resolve({ total: identities.length, identities });
        },
        (offer) => {
            verified.push([offer.position, offer.identity[0]]);
            if (![12, 21].includes(offer.identity[0]))
                throw new PublicInputFailure('Unavailable or invalid offer.');
            return Promise.resolve();
        },
    );
    expect(verified).toEqual([
        [0, 10],
        [2, 20],
        [0, 11],
        [2, 21],
        [0, 12],
    ]);
    expect(found).toEqual([
        { position: 0, identity: identity(12) },
        { position: 2, identity: identity(21) },
    ]);
});

it('retries the same initially missing body on a new invocation and propagates resource failures', async () => {
    const reads: [number, number][] = [];
    let available = false;
    const discover = () =>
        discoverContributionOffers(
            3,
            2,
            (position, offset) => {
                reads.push([position, offset]);
                return Promise.resolve(
                    position === 1
                        ? { total: 0, identities: [] }
                        : { total: 1, identities: [identity(position)] },
                );
            },
            ({ position }) => {
                if (position === 2 && !available)
                    throw new PublicInputFailure('Body not yet retrievable.');
                return Promise.resolve();
            },
        );
    await expect(discover()).rejects.toThrow('Too few complete');
    available = true;
    expect((await discover()).map((offer) => offer.position)).toEqual([0, 2]);
    expect(reads).toEqual([
        [0, 0],
        [1, 0],
        [2, 0],
        [0, 0],
        [1, 0],
        [2, 0],
    ]);
    const resourceFailure = new Error('Resource exhausted.');
    await expect(
        discoverContributionOffers(
            3,
            2,
            () => Promise.resolve({ total: 1, identities: [identity(1)] }),
            () => {
                throw resourceFailure;
            },
        ),
    ).rejects.toBe(resourceFailure);
    await expect(
        discoverContributionOffers(
            3,
            2,
            () => {
                throw resourceFailure;
            },
            () => Promise.resolve(),
        ),
    ).rejects.toBe(resourceFailure);
});

it('stops at the initial finite snapshot even when later pages advertise a growing tail', async () => {
    const reads: number[] = [],
        checked: number[] = [];
    await expect(
        discoverContributionOffers(
            1,
            1,
            (_position, offset) => {
                reads.push(offset);
                if (offset !== 0 && offset !== 64)
                    throw new Error('The scan escaped its original snapshot.');
                return Promise.resolve({
                    total: offset === 0 ? 65 : 129,
                    identities: Array.from({ length: 64 }, (_, index) =>
                        identity(offset + index),
                    ),
                });
            },
            ({ identity: value }) => {
                checked.push(value[0]);
                if (value[0] < 65)
                    throw new PublicInputFailure('Original hint is invalid.');
                return Promise.resolve();
            },
        ),
    ).rejects.toThrow('Too few complete');
    expect(reads).toEqual([0, 64]);
    expect(checked).toEqual(Array.from({ length: 65 }, (_, index) => index));
});
