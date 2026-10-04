import { PublicInputFailure } from './context.js';

type OfferCandidate = Readonly<{
    position: number;
    identity: Uint8Array;
}>;

// Process one candidate per unresolved author each round. A busy corrupt
// author's append-only log must not starve another author's available offer.
// Each invocation scans one finite snapshot per author, so new spam cannot
// keep it alive indefinitely. A later call retries earlier unavailable bodies.
// This discovers inputs only; the caller's Rust builder still requires its
// own complete verified-offer capabilities before creating a selection.
export const discoverContributionOffers = async (
    eligibleCount: number,
    selectedCount: number,
    readPage: (
        position: number,
        offset: number,
    ) => Promise<Readonly<{ identities: Uint8Array[]; total: number }>>,
    verify: (candidate: OfferCandidate) => Promise<void>,
): Promise<OfferCandidate[]> => {
    const readers = Array.from({ length: eligibleCount }, () => ({
        offset: 0,
        total: undefined as number | undefined,
        entries: [] as Uint8Array[],
        next: 0,
        exhausted: false,
        accepted: false,
    }));
    const offers: OfferCandidate[] = [];
    while (
        readers.some(
            (reader) =>
                !reader.accepted &&
                (!reader.exhausted || reader.next < reader.entries.length),
        )
    ) {
        for (const [position, reader] of readers.entries()) {
            if (reader.accepted) continue;
            if (reader.next === reader.entries.length) {
                if (reader.exhausted) continue;
                try {
                    const page = await readPage(position, reader.offset);
                    reader.total ??= page.total;
                    if (page.total < reader.total)
                        throw new PublicInputFailure(
                            'The offer discovery prefix disappeared.',
                        );
                    reader.entries = page.identities.slice(
                        0,
                        reader.total - reader.offset,
                    );
                    reader.offset += reader.entries.length;
                    reader.next = 0;
                    reader.exhausted = reader.offset === reader.total;
                } catch (error) {
                    if (!(error instanceof PublicInputFailure)) throw error;
                    reader.exhausted = true;
                    continue;
                }
            }
            if (reader.next === reader.entries.length) continue;
            const identity = reader.entries[reader.next++];
            const offer = { position, identity };
            try {
                await verify(offer);
            } catch (error) {
                if (!(error instanceof PublicInputFailure)) throw error;
                continue;
            }
            reader.accepted = true;
            offers.push(offer);
            if (offers.length === selectedCount)
                return offers.sort(
                    (left, right) => left.position - right.position,
                );
        }
    }
    throw new PublicInputFailure(
        'Too few complete eligible contribution offers are available.',
    );
};
