// Conditional availability experiment, not a cryptographic construction.
// CKPS01 section 3.1.2, Figure 1 and Theorem 4 supply the ECHO/READY rules.
// Authentication, continued retrieval and the publicly verified recovery
// relation are ideal interfaces. The relation oracle below checks actual
// integer polynomial shares; it does not implement PVSS or prove privacy.
// Fixture masking is reversible arithmetic, never protocol encryption.

export type SetupScope = Readonly<{ poll: string; roster: string }>;
export type SetupFailureStage = 'offer' | 'echo' | 'ready' | 'opening';
export type SetupFailure = Readonly<{
    participant: number;
    before: SetupFailureStage;
}>;
type Selection = readonly string[];
export type SetupFrame = Readonly<{
    scope: SetupScope;
    sender: number;
    kind: 'offer' | 'selection' | 'echo' | 'ready' | 'opening';
    selection: Selection;
    shares?: readonly bigint[];
}>;
type Published = Readonly<{
    ordinal: number;
    author: number;
    frame: SetupFrame;
}>;

// Coefficients and recipient shares represent the witness available only to
// the finite relation oracle. An actual implementation needs a public proof
// with the same consistency, confidentiality and decodability properties.
export type RecoveryOffer = Readonly<{
    identity: string;
    dealer: number;
    coefficients: readonly bigint[];
    recipientShares: readonly bigint[];
    maskedBody: readonly bigint[];
}>;

export const polynomialValue = (
    coefficients: readonly bigint[],
    position: number,
): bigint =>
    coefficients.reduceRight(
        (value, coefficient) => value * BigInt(position + 1) + coefficient,
        0n,
    );

const residue = (value: bigint): bigint => ((value % 257n) + 257n) % 257n;

export const makeRecoveryOffer = (
    participantCount: number,
    dealer: number,
    identity: string,
    coefficients: readonly bigint[],
    body: readonly number[],
): RecoveryOffer => {
    if (
        coefficients.length === 0 ||
        body.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
    )
        throw new RangeError('An offer needs a polynomial and a byte payload.');
    return {
        identity,
        dealer,
        coefficients: [...coefficients],
        recipientShares: Array.from(
            { length: participantCount },
            (_, position) => polynomialValue(coefficients, position),
        ),
        maskedBody: body.map((byte) => residue(BigInt(byte) + coefficients[0])),
    };
};

// Exact rational Lagrange interpolation at zero. Every intermediate fraction
// remains explicit; truncating integer division cannot manufacture a seed.
export const reconstructOpeningKey = (
    points: readonly Readonly<{ participant: number; value: bigint }>[],
): bigint => {
    if (
        points.length === 0 ||
        points.some(
            ({ participant }) =>
                !Number.isInteger(participant) || participant < 0,
        ) ||
        new Set(points.map(({ participant }) => participant)).size !==
            points.length
    )
        throw new RangeError('Recovery points must be distinct and nonempty.');
    let numerator = 0n;
    let denominator = 1n;
    for (const point of points) {
        const position = BigInt(point.participant + 1);
        let termNumerator = point.value;
        let termDenominator = 1n;
        for (const other of points) {
            if (other.participant === point.participant) continue;
            const otherPosition = BigInt(other.participant + 1);
            termNumerator *= -otherPosition;
            termDenominator *= position - otherPosition;
        }
        numerator = numerator * termDenominator + termNumerator * denominator;
        denominator *= termDenominator;
    }
    if (numerator % denominator !== 0n)
        throw new RangeError('Recovery points do not reconstruct an integer.');
    return numerator / denominator;
};

type Participant = {
    active: boolean;
    confirmed: boolean;
    offered: boolean;
    seen: Map<number, Published>;
    echo: Selection | undefined;
    ready: Selection | undefined;
    delivered: Selection | undefined;
    opened: boolean;
    recovered: Map<string, readonly number[]>;
    stages: Set<string>;
};

const selectionIdentity = (selection: Selection): string =>
    JSON.stringify(selection);

export class RecoverableSetupModel {
    readonly faultBound: number;
    readonly releaseThreshold: number;
    readonly echoThreshold: number;
    readonly deliveryThreshold: number;
    readonly candidateCount: number;
    readonly participants: Participant[];
    readonly publications: Published[] = [];
    readonly trace: string[] = [];
    private readonly offers: Map<string, RecoveryOffer>;
    private readonly failures: Map<number, SetupFailureStage>;
    private readonly corrupt: ReadonlySet<number>;
    private readonly failed = new Set<number>();
    private selectionPublished = false;

    constructor(
        readonly participantCount: number,
        readonly scope: SetupScope,
        offers: readonly RecoveryOffer[],
        options: Readonly<{
            failures?: readonly SetupFailure[];
            corrupt?: readonly number[];
            candidateCount?: number;
        }> = {},
    ) {
        if (
            !Number.isSafeInteger(participantCount) ||
            participantCount < 3 ||
            participantCount > 20
        )
            throw new RangeError('Unsupported participant count.');
        this.faultBound = Math.floor((participantCount - 1) / 3);
        this.releaseThreshold = Math.max(this.faultBound + 1, 2);
        this.echoThreshold = participantCount - this.faultBound;
        this.deliveryThreshold = 2 * this.faultBound + 1;
        this.candidateCount =
            options.candidateCount ?? this.releaseThreshold + this.faultBound;
        const stageOrder: SetupFailureStage[] = [
            'offer',
            'echo',
            'ready',
            'opening',
        ];
        this.failures = new Map();
        for (const { participant, before } of options.failures ?? []) {
            const previous = this.failures.get(participant);
            if (stageOrder.indexOf(before) < 0)
                throw new RangeError('Unknown setup failure stage.');
            if (
                previous === undefined ||
                stageOrder.indexOf(before) < stageOrder.indexOf(previous)
            )
                this.failures.set(participant, before);
        }
        this.corrupt = new Set(options.corrupt);
        // Corrupt positions have no automatic honest production in this
        // experiment: their scripts may withhold or send invalid work. Charge
        // them together with stopped positions to the availability budget.
        // The static secrecy corruption bound remains a separate obligation.
        const unavailable = new Set([...this.failures.keys(), ...this.corrupt]);
        if (
            this.failures.size > this.faultBound ||
            this.corrupt.size > this.faultBound ||
            unavailable.size > this.faultBound ||
            this.failures.has(0) ||
            [...this.failures.keys(), ...this.corrupt].some(
                (position) =>
                    !Number.isInteger(position) ||
                    position < 0 ||
                    position >= participantCount,
            ) ||
            !Number.isInteger(this.candidateCount) ||
            this.candidateCount < this.releaseThreshold ||
            this.candidateCount > participantCount
        )
            throw new RangeError(
                'The setup failure or candidate scope is invalid.',
            );
        this.offers = new Map(offers.map((offer) => [offer.identity, offer]));
        if (this.offers.size !== offers.length)
            throw new RangeError('Offer identities must be distinct.');
        this.participants = Array.from({ length: participantCount }, () => ({
            active: true,
            confirmed: false,
            offered: false,
            seen: new Map(),
            echo: undefined,
            ready: undefined,
            delivered: undefined,
            opened: false,
            recovered: new Map(),
            stages: new Set(),
        }));
    }

    confirm(participant: number, roster: string): boolean {
        const state = this.participants[participant];
        if (!state?.active || roster !== this.scope.roster) return false;
        state.confirmed = true;
        return true;
    }

    private relation(offer: RecoveryOffer): boolean {
        return (
            offer.dealer >= 0 &&
            offer.dealer < this.candidateCount &&
            offer.coefficients.length === this.releaseThreshold &&
            offer.coefficients.every(
                (coefficient) => coefficient >= -256n && coefficient <= 256n,
            ) &&
            offer.coefficients[0] >= 0n &&
            offer.coefficients[0] <= 255n &&
            offer.recipientShares.length === this.participantCount &&
            offer.recipientShares.every(
                (share, position) =>
                    share === polynomialValue(offer.coefficients, position),
            ) &&
            offer.maskedBody.length > 0 &&
            offer.maskedBody.every((value) => value >= 0n && value <= 256n)
        );
    }

    private emit(author: number, frame: SetupFrame): number {
        const ordinal = this.publications.length;
        this.publications.push({ author, frame, ordinal });
        this.trace.push(
            `${author}:${frame.kind}:${selectionIdentity(frame.selection)}`,
        );
        return ordinal;
    }

    // The adversary may author arbitrary frames only in its original corrupt
    // slots. Claimed sender, poll and roster still pass reception checks.
    inject(author: number, frame: SetupFrame): number {
        if (!this.corrupt.has(author))
            throw new RangeError(
                'The adversary cannot sign for an honest participant.',
            );
        return this.emit(author, frame);
    }

    private publish(
        sender: number,
        kind: SetupFrame['kind'],
        selection: Selection,
        shares?: readonly bigint[],
    ): void {
        this.emit(sender, {
            scope: this.scope,
            sender,
            kind,
            selection,
            shares,
        });
    }

    deliver(ordinal: number, participant: number): boolean {
        const record = this.publications[ordinal];
        const state = this.participants[participant];
        if (
            !record ||
            !state?.active ||
            state.seen.has(ordinal) ||
            record.author !== record.frame.sender ||
            record.frame.scope.poll !== this.scope.poll ||
            record.frame.scope.roster !== this.scope.roster
        )
            return false;
        state.seen.set(ordinal, record);
        return true;
    }

    private available(state: Participant): Map<string, RecoveryOffer> {
        const result = new Map<string, RecoveryOffer>();
        for (const { author, frame } of state.seen.values()) {
            if (frame.kind !== 'offer' || frame.selection.length !== 1)
                continue;
            const offer = this.offers.get(frame.selection[0]);
            if (offer?.dealer === author && this.relation(offer))
                result.set(offer.identity, offer);
        }
        return result;
    }

    private selections(state: Participant): Selection[] {
        const available = this.available(state);
        return [...state.seen.values()]
            .filter(
                ({ author, frame }) =>
                    author === 0 &&
                    frame.kind === 'selection' &&
                    frame.selection.length === this.releaseThreshold &&
                    new Set(frame.selection).size === frame.selection.length &&
                    frame.selection.every((identity) =>
                        available.has(identity),
                    ) &&
                    new Set(
                        frame.selection.map(
                            (identity) => available.get(identity)!.dealer,
                        ),
                    ).size === frame.selection.length &&
                    frame.selection.every(
                        (identity, index) =>
                            index === 0 ||
                            frame.selection[index - 1] < identity,
                    ),
            )
            .map(({ frame }) => frame.selection);
    }

    private senders(
        state: Participant,
        kind: 'echo' | 'ready',
        selection: Selection,
    ): Set<number> {
        return new Set(
            [...state.seen.values()]
                .filter(
                    ({ frame }) =>
                        frame.kind === kind &&
                        selectionIdentity(frame.selection) ===
                            selectionIdentity(selection),
                )
                .map(({ author }) => author),
        );
    }

    private stopBefore(participant: number, stage: SetupFailureStage): boolean {
        if (this.failures.get(participant) !== stage) return false;
        this.participants[participant].active = false;
        this.failed.add(participant);
        this.trace.push(`${participant}:stopped-before-${stage}`);
        return true;
    }

    // One causally enabled honest action. Stopping happens before emission,
    // never by filtering messages or shares generated earlier.
    advance(participant: number): boolean {
        const state = this.participants[participant];
        if (!state?.active || !state.confirmed || this.corrupt.has(participant))
            return false;
        if (!state.offered) {
            if (this.stopBefore(participant, 'offer')) return true;
            state.offered = true;
            if (participant < this.candidateCount) {
                const offer = [...this.offers.values()].find(
                    (value) => value.dealer === participant,
                );
                if (offer) this.publish(participant, 'offer', [offer.identity]);
            }
            state.stages.add('contribution');
            return true;
        }
        if (participant === 0 && !this.selectionPublished) {
            const offered = [...this.available(state).values()].sort(
                (left, right) => left.identity.localeCompare(right.identity),
            );
            const selected = offered
                .filter(
                    (offer, index) =>
                        offered.findIndex(
                            (other) => other.dealer === offer.dealer,
                        ) === index,
                )
                .slice(0, this.releaseThreshold);
            if (selected.length === this.releaseThreshold) {
                this.publish(
                    0,
                    'selection',
                    selected.map(({ identity }) => identity),
                );
                this.selectionPublished = true;
                return true;
            }
        }
        const selections = this.selections(state);
        if (!state.echo && selections.length > 0) {
            if (this.stopBefore(participant, 'echo')) return true;
            state.echo = selections[0]!;
            state.stages.add('echo');
            this.publish(participant, 'echo', state.echo);
            return true;
        }
        if (!state.ready) {
            const ready = selections.find(
                (selection) =>
                    this.senders(state, 'echo', selection).size >=
                        this.echoThreshold ||
                    this.senders(state, 'ready', selection).size >=
                        this.faultBound + 1,
            );
            if (ready) {
                if (this.stopBefore(participant, 'ready')) return true;
                state.ready = ready;
                state.stages.add('ready');
                this.publish(participant, 'ready', ready);
                return true;
            }
        }
        if (!state.delivered) {
            const delivered = selections.find(
                (selection) =>
                    this.senders(state, 'ready', selection).size >=
                    this.deliveryThreshold,
            );
            if (delivered) {
                state.delivered = delivered;
                this.trace.push(
                    `${participant}:delivered:${selectionIdentity(delivered)}`,
                );
                return true;
            }
        }
        if (state.delivered && !state.opened) {
            if (this.stopBefore(participant, 'opening')) return true;
            state.opened = true;
            state.stages.add('opening');
            this.publish(
                participant,
                'opening',
                state.delivered,
                state.delivered.map(
                    (identity) =>
                        this.offers.get(identity)!.recipientShares[participant],
                ),
            );
            return true;
        }
        if (state.delivered && state.recovered.size === 0) {
            const points = new Map<number, readonly bigint[]>();
            for (const { author, frame } of state.seen.values()) {
                if (
                    frame.kind !== 'opening' ||
                    selectionIdentity(frame.selection) !==
                        selectionIdentity(state.delivered) ||
                    frame.shares?.length !== state.delivered.length ||
                    !frame.shares.every(
                        (share, index) =>
                            share ===
                            this.offers.get(state.delivered![index])!
                                .recipientShares[author],
                    )
                )
                    continue;
                points.set(author, frame.shares);
            }
            if (points.size >= this.releaseThreshold) {
                state.stages.add('recovery');
                const subset = [...points].slice(0, this.releaseThreshold);
                for (const [index, identity] of state.delivered.entries()) {
                    const key = reconstructOpeningKey(
                        subset.map(([author, shares]) => ({
                            participant: author,
                            value: shares[index],
                        })),
                    );
                    state.recovered.set(
                        identity,
                        this.offers
                            .get(identity)!
                            .maskedBody.map((value) =>
                                Number(residue(value - key)),
                            ),
                    );
                }
                return true;
            }
        }
        return false;
    }

    // Successful publication survives author loss. A benign suffix delivers
    // every published record to each continuer, including replayed records;
    // receipt itself produces neither a certificate nor a recovery share.
    drain(reverse = false): void {
        let changed = true;
        let turns = 0;
        while (changed) {
            if (++turns > 1000)
                throw new Error('The finite setup did not settle.');
            changed = false;
            const positions = Array.from(
                { length: this.participantCount },
                (_, position) => position,
            );
            if (reverse) positions.reverse();
            for (const position of positions) {
                for (const record of [...this.publications])
                    changed = this.deliver(record.ordinal, position) || changed;
                changed = this.advance(position) || changed;
            }
        }
    }

    unavailable(): readonly number[] {
        return [...this.failed].sort((left, right) => left - right);
    }
}
