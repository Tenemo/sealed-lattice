import { fixedPublicationWitnesses } from '#tests/fixed-publication-witness-model.js';

type Token = Readonly<{
    identity: string;
    author: number;
    body: string | null;
}>;
type Certificate = Readonly<{ token: Token; witnesses: readonly number[] }>;

// Conditional publication comparison with ideal signatures and body-proof
// validity. It is not a wire verifier. Fixtures are established independently
// of producer messages, and later messages cannot change their validity.
export const createSlotPublicationModel = (
    participantCount: number,
    corruptPositions: readonly number[],
    action: string,
) => {
    const { committees, minimumWitnesses } =
        fixedPublicationWitnesses(participantCount);
    const corrupt = new Set(corruptPositions);
    const position = (value: number): void => {
        if (
            !Number.isSafeInteger(value) ||
            value < 0 ||
            value >= participantCount
        )
            throw new RangeError('Invalid participant position.');
    };
    if (
        !action ||
        corrupt.size !== corruptPositions.length ||
        corrupt.size >= minimumWitnesses
    )
        throw new Error('Invalid action or corruption set.');
    for (const member of corrupt) position(member);
    const fixtures = new Map<string, boolean>();
    const tokens = new Map<string, Token>();
    const authorLocks = new Map<number, string>();
    const attempts = new Map<number, string>();
    const closeSeen = new Set<number>();
    const witnessLocks = committees.map(() => new Map<number, string>());
    const signatures = new Set<string>();
    const published = new Map<number, Certificate>();
    let closeRequested = false;
    const signature = (member: number, token: Token): string =>
        JSON.stringify([member, token.identity]);
    const fixture = (body: string, proofValid: boolean): void => {
        if (!body || fixtures.has(body)) throw new Error('Invalid fixture.');
        fixtures.set(body, proofValid);
    };
    const requestClose = (sender: number): boolean => {
        if (sender !== 0 || closeRequested) return false;
        closeRequested = true;
        closeSeen.add(sender);
        return true;
    };
    const observeClose = (participant: number): boolean => {
        position(participant);
        if (!closeRequested) return false;
        closeSeen.add(participant);
        return true;
    };
    const beginAttempt = (author: number, body: string): boolean => {
        position(author);
        if (!fixtures.has(body)) return false;
        if (
            !corrupt.has(author) &&
            (closeSeen.has(author) ||
                attempts.has(author) ||
                authorLocks.has(author))
        )
            return false;
        attempts.set(author, body);
        return true;
    };
    const originate = (
        author: number,
        body: string | null,
    ): Token | undefined => {
        position(author);
        if (body === null ? !closeRequested : !fixtures.has(body)) return;
        if (
            !corrupt.has(author) &&
            (authorLocks.has(author) ||
                (body === null &&
                    (!closeSeen.has(author) || attempts.has(author))) ||
                (body !== null &&
                    (attempts.has(author)
                        ? attempts.get(author) !== body
                        : closeSeen.has(author))))
        )
            return;
        if (body !== null) attempts.set(author, body);
        const identity = JSON.stringify([action, author, body]);
        const token = { identity, author, body };
        tokens.set(identity, token);
        authorLocks.set(author, identity);
        signatures.add(signature(author, token));
        witnessLocks[author].set(author, identity);
        return { ...token };
    };
    const witness = (
        member: number,
        token: Token,
        bodyBytes: string | null,
    ): boolean => {
        position(member);
        const original = tokens.get(token.identity);
        if (
            !original ||
            JSON.stringify(original) !== JSON.stringify(token) ||
            !committees[token.author].includes(member)
        )
            return false;
        if (token.body === null ? bodyBytes !== null : bodyBytes !== token.body)
            return false;
        const locks = witnessLocks[token.author],
            previous = locks.get(member);
        if (
            !corrupt.has(member) &&
            previous !== undefined &&
            previous !== token.identity
        )
            return false;
        locks.set(member, token.identity);
        signatures.add(signature(member, token));
        return true;
    };
    const verifyCertificate = (certificate: Certificate): boolean => {
        const token = tokens.get(certificate.token.identity);
        if (
            !token ||
            JSON.stringify(token) !== JSON.stringify(certificate.token)
        )
            return false;
        const required = committees[token.author],
            supplied = new Set(certificate.witnesses);
        return (
            supplied.size === required.length &&
            certificate.witnesses.length === required.length &&
            required.every(
                (member) =>
                    supplied.has(member) &&
                    signatures.has(signature(member, token)),
            )
        );
    };
    const certificate = (token: Token): Certificate => ({
        token: { ...token },
        witnesses: [...committees[token.author]],
    });
    const publish = (value: Certificate): boolean => {
        if (!verifyCertificate(value)) return false;
        const previous = published.get(value.token.author);
        if (previous && previous.token.identity !== value.token.identity)
            throw new Error('Conflicting valid publication certificates.');
        published.set(value.token.author, structuredClone(value));
        return true;
    };
    const close = (values: readonly Certificate[]) => {
        if (
            !closeRequested ||
            values.length !== participantCount ||
            new Set(values.map((value) => value.token.author)).size !==
                participantCount ||
            !values.every(verifyCertificate)
        )
            return;
        return [...values]
            .sort((left, right) => left.token.author - right.token.author)
            .map(({ token }) => ({
                author: token.author,
                body: token.body,
                classification:
                    token.body === null
                        ? 'missing'
                        : fixtures.get(token.body)!
                          ? 'accepted'
                          : 'invalid',
            }));
    };
    return {
        fixture,
        requestClose,
        observeClose,
        beginAttempt,
        originate,
        witness,
        certificate,
        verifyCertificate,
        publish,
        close,
        committees,
    };
};
