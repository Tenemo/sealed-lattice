// Authenticated-message model of a freeze-and-union close candidate. Signature
// verification is represented by the immutable issued-message registry. This
// is not a wire decoder or an implementation of a protocol capability.
export type PublicationBody = Readonly<{
    slot: number;
    identity: string;
    validBallot: boolean;
}>;

type EchoCertificate = Readonly<{
    body: PublicationBody;
    signers: readonly number[];
}>;

export type PublicationCutMessage = Readonly<{
    sender: number;
    kind: 'echo' | 'ready' | 'freeze';
    certificates: readonly EchoCertificate[];
}>;

export const createPublicationCutModel = (
    participantCount: number,
    corruptPositions: readonly number[],
) => {
    if (
        !Number.isInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported publication-model roster.');
    const corrupt = new Set(corruptPositions);
    const corruptionBound = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptionBound;
    if (
        corrupt.size !== corruptPositions.length ||
        corrupt.size > corruptionBound ||
        [...corrupt].some(
            (position) =>
                !Number.isInteger(position) ||
                position < 0 ||
                position >= participantCount,
        )
    )
        throw new RangeError('Invalid model corruption set.');
    const issued: PublicationCutMessage[] = [];
    const authenticated = new Set<string>();
    const identity = (body: PublicationBody): string => JSON.stringify(body);
    const states = Array.from({ length: participantCount }, () => ({
        frozen: false,
        echoLocks: new Set<number>(),
        echoes: new Map<string, Set<number>>(),
        ready: new Map<number, EchoCertificate>(),
    }));
    const stateAt = (position: number) => {
        const state = states[position];
        if (!Number.isInteger(position) || state === undefined)
            throw new RangeError('Invalid model participant.');
        return state;
    };
    const issue = (message: PublicationCutMessage): PublicationCutMessage => {
        // Copy nested data: mutating a carrier cannot change signed bytes.
        const copy = structuredClone(message);
        authenticated.add(JSON.stringify(copy));
        issued.push(copy);
        return structuredClone(copy);
    };
    const verifiesCertificate = (certificate: EchoCertificate): boolean => {
        const unique = new Set(certificate.signers);
        return (
            unique.size === quorum &&
            unique.size === certificate.signers.length &&
            [...unique].every((sender) =>
                authenticated.has(
                    JSON.stringify({
                        sender,
                        kind: 'echo',
                        certificates: [{ body: certificate.body, signers: [] }],
                    }),
                ),
            )
        );
    };
    const echo = (sender: number, body: PublicationBody) => {
        const state = stateAt(sender);
        if (
            !Number.isInteger(body.slot) ||
            body.slot < 0 ||
            body.slot >= participantCount
        )
            throw new RangeError('Invalid model ballot slot.');
        if (!corrupt.has(sender)) {
            if (state.frozen || state.echoLocks.has(body.slot)) return;
            state.echoLocks.add(body.slot);
        }
        return issue({
            sender,
            kind: 'echo',
            certificates: [{ body, signers: [] }],
        });
    };
    const receive = (
        recipient: number,
        message: PublicationCutMessage,
    ): boolean => {
        const state = stateAt(recipient);
        if (!authenticated.has(JSON.stringify(message))) return false;
        if (message.kind === 'freeze') return true;
        const certificate = message.certificates[0];
        if (message.kind === 'ready' && !verifiesCertificate(certificate))
            return false;
        if (state.frozen || corrupt.has(recipient)) return true;
        const key = identity(certificate.body);
        const signers = state.echoes.get(key) ?? new Set<number>();
        for (const signer of message.kind === 'echo'
            ? [message.sender]
            : certificate.signers)
            signers.add(signer);
        state.echoes.set(key, signers);
        if (signers.size >= quorum && !state.ready.has(certificate.body.slot)) {
            const complete = {
                body: certificate.body,
                signers: [...signers]
                    .sort((left, right) => left - right)
                    .slice(0, quorum),
            };
            state.ready.set(certificate.body.slot, complete);
            issue({
                sender: recipient,
                kind: 'ready',
                certificates: [complete],
            });
        }
        return true;
    };
    const freeze = (sender: number): PublicationCutMessage => {
        const state = stateAt(sender);
        if (state.frozen) throw new Error('The model freeze is one-shot.');
        state.frozen = true;
        return issue({
            sender,
            kind: 'freeze',
            // The hostile case withholds every optional entry.
            certificates: corrupt.has(sender)
                ? []
                : [...state.ready.values()].sort(
                      (left, right) => left.body.slot - right.body.slot,
                  ),
        });
    };
    const inventory = (
        reports: readonly PublicationCutMessage[],
    ): readonly PublicationBody[] | undefined => {
        if (
            reports.length !== quorum ||
            new Set(reports.map(({ sender }) => sender)).size !== quorum
        )
            return;
        const bodies = new Map<number, PublicationBody>();
        for (const report of reports) {
            if (
                report.kind !== 'freeze' ||
                !authenticated.has(JSON.stringify(report))
            )
                return;
            for (const certificate of report.certificates) {
                if (!verifiesCertificate(certificate)) return;
                const previous = bodies.get(certificate.body.slot);
                if (
                    previous !== undefined &&
                    identity(previous) !== identity(certificate.body)
                )
                    return;
                bodies.set(certificate.body.slot, certificate.body);
            }
        }
        return [...bodies.values()].sort(
            (left, right) => left.slot - right.slot,
        );
    };
    return {
        quorum,
        echo,
        receive,
        freeze,
        inventory,
        messages: () => structuredClone(issued),
    };
};

const countBits = (mask: number): number => {
    let count = 0;
    for (let remaining = mask; remaining !== 0; remaining &= remaining - 1)
        count++;
    return count;
};

export const compilePublicationCutCensus = () => {
    const participantCount = 10;
    const corruptionBound = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptionBound;
    const masks = Array.from({ length: 1 << participantCount }, (_, i) => i);
    const quorums = masks.filter((mask) => countBits(mask) === quorum);
    const corruptSets = masks.filter(
        (mask) => countBits(mask) === corruptionBound,
    );
    let checkedIntersections = 0;
    let minimumHonestPublicationReporters = participantCount;
    for (const readySenders of quorums)
        for (const closeSenders of quorums)
            for (const corrupt of corruptSets) {
                minimumHonestPublicationReporters = Math.min(
                    minimumHonestPublicationReporters,
                    countBits(readySenders & closeSenders & ~corrupt),
                );
                checkedIntersections++;
            }
    return {
        participantCount,
        corruptionBound,
        quorum,
        checkedIntersections,
        minimumHonestPublicationReporters,
    };
};
