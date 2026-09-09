type Envelope = Readonly<{
    author: number;
    slot: string;
    body: string;
    signature: string;
}>;

const first: Envelope = {
    author: 3,
    slot: 'poll/ballot/3',
    body: 'first-valid-body',
    signature: 'signature-of-first-body',
};
const second: Envelope = {
    author: 3,
    slot: 'poll/ballot/3',
    body: 'second-valid-body',
    signature: 'signature-of-second-body',
};

// These traces assume authentication and full byte availability. They do not
// implement either primitive or assign protocol publication authority.
export const publicationOriginOrderViews = () => {
    const publicView = {
        records: [first, second],
        honestDeliveries: [0, 1, 2].map((participant) => ({
            participant,
            messages: [first, second],
        })),
        closeIntent: { organizer: 0, action: 'close' },
    };
    return [
        { origins: [first, second], view: structuredClone(publicView) },
        { origins: [second, first], view: structuredClone(publicView) },
    ] as const;
};

export const unorderedPublicationClassifications = () =>
    [null, first.body, second.body].map((answer) => ({
        answer,
        preservesFirstSingleton: answer === first.body,
        preservesSecondSingleton: answer === second.body,
    }));

export const retainPublishedValue = (
    published: Envelope,
    incoming: Envelope,
) => {
    if (published.slot !== incoming.slot)
        throw new Error('Publication slots differ.');
    return { ...published };
};

export const delayedArchiveDiscoveryViews = () => {
    const closingView = {
        receivedRecords: [] as Envelope[],
        reports: [0, 1, 2, 3].map((sender) => ({ sender, records: [] })),
        organizerIntent: 'close',
    };
    return [
        {
            durableRecordsBeforeClose: [] as Envelope[],
            closingView: structuredClone(closingView),
            deliveredAfterClose: [] as Envelope[],
        },
        {
            durableRecordsBeforeClose: [first],
            closingView: structuredClone(closingView),
            deliveredAfterClose: [first],
        },
    ] as const;
};

// Functional reference only. `linearize` represents an already established
// authoritative publication event. It is not implemented by a receipt, this
// registry, or the caller's choice of invocation order.
export const orderedPublicationReference = (
    participantCount: number,
    organizer: number,
) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported publication roster.');
    if (
        !Number.isSafeInteger(organizer) ||
        organizer < 0 ||
        organizer >= participantCount
    )
        throw new RangeError('Invalid organizer position.');
    const issued = new Map<
        string,
        { author: number; body: string; proofValid: boolean }
    >();
    const published = new Map<number, string>();
    const history: string[] = [];
    let closed = false;
    const registerFixture = (
        author: number,
        body: string,
        proofValid: boolean,
    ) => {
        if (
            !Number.isSafeInteger(author) ||
            author < 0 ||
            author >= participantCount ||
            !body
        )
            throw new Error('Invalid publication fixture.');
        const identity = JSON.stringify([author, body]);
        const previous = issued.get(identity);
        if (previous && previous.proofValid !== proofValid)
            throw new Error('The same body cannot change proof validity.');
        issued.set(identity, { author, body, proofValid });
        return identity;
    };
    const linearize = (identity: string) => {
        const envelope = issued.get(identity);
        if (!envelope || closed || published.has(envelope.author)) return false;
        published.set(envelope.author, identity);
        history.push(identity);
        return true;
    };
    const inventory = () =>
        [...published]
            .sort(([left], [right]) => left - right)
            .map(([author, identity]) => ({
                author,
                identity,
                classification: issued.get(identity)!.proofValid
                    ? ('accepted' as const)
                    : ('invalid' as const),
            }));
    const close = (sender: number) => {
        if (sender !== organizer) return;
        closed = true;
        return { publications: [...history], inventory: inventory() };
    };
    return { registerFixture, linearize, close };
};
