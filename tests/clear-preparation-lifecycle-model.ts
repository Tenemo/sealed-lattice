import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import {
    setupSelectionIdentityModel,
    type SelectedContributionModel,
} from '#tests/setup-selection-wire-model.js';

type ParticipantState = {
    available: boolean;
    stopped: boolean;
    generation: 3 | 4 | 12;
    ownPhase?: number;
    endorsement?: string;
    setup?: string;
    required: Map<string, string>;
    stored: Map<string, string>;
};
export type SetupCertificateModel = Readonly<{
    selected: readonly SelectedContributionModel[];
    signers: readonly number[];
}>;

// A finite chronology model with ideal proof and signature boundaries.
// acceptVerifiedOffer represents the *completed* owning verifier over an exact
// named published-store read. That read plus monotone retention establishes
// availability; no reupload is needed. Local-only buffers do not establish it.
// Record equality models the
// authenticated original custody premise, not AES or browser persistence.
export class ClearPreparationLifecycleModel {
    readonly profile;
    private readonly participants: ParticipantState[];
    private readonly offers = new Set<string>();
    private readonly publishedOffers = new Set<string>();
    private readonly proposals = new Set<string>();
    private readonly endorsements = new Map<number, Set<string>>();
    private readonly publishedCertificates = new Set<string>();
    private readonly corrupt: Set<number>;

    constructor(
        readonly participantCount: number,
        readonly rosterIdentity: string,
        corrupt: readonly number[] = [],
    ) {
        this.profile = compileSetupSelectionCensus(participantCount);
        this.corrupt = new Set(corrupt);
        if (
            this.corrupt.size !== corrupt.length ||
            this.corrupt.size > this.profile.faultBound ||
            corrupt.some(
                (position) =>
                    !Number.isSafeInteger(position) ||
                    position < 0 ||
                    position >= participantCount,
            )
        )
            throw new RangeError('Invalid static corruption set.');
        this.participants = Array.from(
            { length: participantCount },
            (_, position) => {
                const records = new Map([
                    ['enrollment', `${position}:${rosterIdentity}`],
                    ['source-capsule', `original-source:${position}`],
                    ['source-key', `original-key:${position}`],
                ]);
                return {
                    available: true,
                    stopped: false,
                    generation: 3,
                    required: records,
                    stored: new Map(records),
                };
            },
        );
    }

    private authenticated(position: number) {
        const state = this.participants[position];
        if (state === undefined || !state.available || state.stopped)
            return undefined;
        if (
            state.required.size !== state.stored.size ||
            [...state.required].some(
                ([key, value]) => state.stored.get(key) !== value,
            )
        ) {
            state.stopped = true;
            return undefined;
        }
        return state;
    }
    private retain(state: ParticipantState, key: string, value: string) {
        state.required.set(key, value);
        state.stored.set(key, value);
    }
    private identity(selected: readonly SelectedContributionModel[]) {
        try {
            return setupSelectionIdentityModel(
                this.participantCount,
                this.rosterIdentity,
                selected,
            );
        } catch {
            return undefined;
        }
    }
    private completeInputs(selected: readonly SelectedContributionModel[]) {
        return (
            this.identity(selected) !== undefined &&
            selected.every((entry) =>
                this.offers.has(`${entry.position}:${entry.bodyIdentity}`),
            )
        );
    }

    confirm(position: number): boolean {
        const state = this.authenticated(position);
        if (state === undefined) return false;
        if (state.generation === 3) state.generation = 4;
        return state.generation === 4;
    }
    beginOwnOffer(position: number): boolean {
        const state = this.authenticated(position);
        if (
            state?.generation !== 4 ||
            position >= this.profile.eligibleCount ||
            state.ownPhase !== undefined
        )
            return false;
        state.ownPhase = 4;
        this.retain(
            state,
            'own-phase-4',
            `original-generation-seed:${position}`,
        );
        return true;
    }
    advanceOwnOffer(position: number): boolean {
        const state = this.authenticated(position);
        if (
            state?.generation !== 4 ||
            state.ownPhase === undefined ||
            state.ownPhase >= 9
        )
            return false;
        state.ownPhase++;
        const retainedPhases =
            state.ownPhase === 6
                ? [5, 6]
                : state.ownPhase >= 8
                  ? [7, state.ownPhase]
                  : [state.ownPhase];
        for (const key of [...state.required.keys()])
            if (
                key.startsWith('own-') &&
                !retainedPhases.some((phase) => key === `own-phase-${phase}`)
            ) {
                state.required.delete(key);
                state.stored.delete(key);
            }
        this.retain(
            state,
            `own-phase-${state.ownPhase}`,
            `original-work:${position}:${state.ownPhase}`,
        );
        return true;
    }
    acceptLocallyVerifiedOffer(entry: SelectedContributionModel): boolean {
        if (
            !Number.isSafeInteger(entry.position) ||
            entry.position < 0 ||
            entry.position >= this.profile.eligibleCount ||
            !/^[0-9a-f]{128}$/u.test(entry.bodyIdentity)
        )
            return false;
        this.offers.add(`${entry.position}:${entry.bodyIdentity}`);
        return true;
    }
    acceptVerifiedOffer(entry: SelectedContributionModel): boolean {
        if (!this.acceptLocallyVerifiedOffer(entry)) return false;
        this.publishedOffers.add(`${entry.position}:${entry.bodyIdentity}`);
        return true;
    }
    publishOffer(entry: SelectedContributionModel): boolean {
        const identity = `${entry.position}:${entry.bodyIdentity}`;
        if (!this.offers.has(identity)) return false;
        this.publishedOffers.add(identity);
        return true;
    }
    propose(selected: readonly SelectedContributionModel[]): boolean {
        const organizer = this.authenticated(0);
        const identity = this.identity(selected);
        if (
            organizer?.generation !== 4 ||
            identity === undefined ||
            !this.completeInputs(selected) ||
            (!this.corrupt.has(0) &&
                this.proposals.size > 0 &&
                !this.proposals.has(identity))
        )
            return false;
        this.proposals.add(identity);
        return true;
    }
    lockEndorsement(
        position: number,
        selected: readonly SelectedContributionModel[],
    ): boolean {
        const state = this.authenticated(position);
        const identity = this.identity(selected);
        if (
            state?.generation !== 4 ||
            identity === undefined ||
            !this.proposals.has(identity) ||
            !this.completeInputs(selected) ||
            (state.endorsement !== undefined && state.endorsement !== identity)
        )
            return false;
        if (state.endorsement !== undefined) return true;
        state.endorsement = identity;
        this.retain(state, 'endorsement-intent', identity);
        return true;
    }
    publishEndorsement(position: number): boolean {
        const state = this.authenticated(position);
        if (state?.generation !== 4 || state.endorsement === undefined)
            return false;
        this.retain(state, 'endorsement-signature', state.endorsement);
        const choices = this.endorsements.get(position) ?? new Set<string>();
        choices.add(state.endorsement);
        this.endorsements.set(position, choices);
        return true;
    }
    verifyCertificate(certificate: SetupCertificateModel): string | undefined {
        const identity = this.identity(certificate.selected);
        if (
            identity === undefined ||
            !this.proposals.has(identity) ||
            !this.completeInputs(certificate.selected) ||
            certificate.signers.length !== this.profile.quorum ||
            certificate.signers.some(
                (position, index) =>
                    !Number.isSafeInteger(position) ||
                    position < 0 ||
                    position >= this.participantCount ||
                    (index > 0 && certificate.signers[index - 1] >= position) ||
                    !this.endorsements.get(position)?.has(identity),
            )
        )
            return undefined;
        return identity;
    }
    publishCertificate(certificate: SetupCertificateModel): boolean {
        const identity = this.verifyCertificate(certificate);
        if (
            identity === undefined ||
            certificate.selected.some(
                (entry) =>
                    !this.publishedOffers.has(
                        `${entry.position}:${entry.bodyIdentity}`,
                    ),
            )
        )
            return false;
        this.publishedCertificates.add(identity);
        return true;
    }
    activate(position: number, certificate: SetupCertificateModel): boolean {
        const state = this.authenticated(position);
        const identity = this.verifyCertificate(certificate);
        if (
            state === undefined ||
            state.generation === 3 ||
            identity === undefined ||
            !this.publishedCertificates.has(identity) ||
            (state.setup !== undefined && state.setup !== identity)
        )
            return false;
        // Authenticate before retirement, including unfinished excluded own
        // work. Neither an own offer nor this party's endorsement is required.
        for (const key of [...state.required.keys()])
            if (
                key.startsWith('own-') ||
                key === 'source-capsule' ||
                key === 'source-key'
            ) {
                state.required.delete(key);
                state.stored.delete(key);
            }
        state.generation = 12;
        state.ownPhase = undefined;
        state.setup = identity;
        return true;
    }
    disappear(position: number) {
        this.participants[position].available = false;
    }
    damage(
        position: number,
        key: string,
        kind: 'missing' | 'changed' | 'extra',
    ) {
        const state = this.participants[position];
        if (kind === 'missing') state.stored.delete(key);
        else state.stored.set(key, kind);
    }
    restart(position: number): boolean {
        return this.authenticated(position) !== undefined;
    }
    snapshot(position: number) {
        const state = this.participants[position];
        return {
            generation: state.generation,
            stopped: state.stopped,
            ownPhase: state.ownPhase,
            endorsement: state.endorsement,
            setup: state.setup,
            required: [...state.required],
            stored: [...state.stored],
        };
    }
}
