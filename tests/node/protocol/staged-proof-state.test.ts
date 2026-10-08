import { describe, expect, it } from 'vitest';

// Finite probability controls for the staged hidden-state argument. These
// labels are a one-time-pad experiment, not protocol records or proof bytes.
type Schedule = Readonly<{
    generationLimits: readonly number[];
    availableMemory: number;
    retryExtraMemory: number;
    lostBeforeContinuation: boolean;
    lostBeforeReplay: boolean;
}>;
type Materialized = Readonly<{ label: number; challenge: number }>;

const observed = (
    generationReads: number,
    schedule: Schedule,
    materialize: () => Materialized,
    resampleOnReplay = false,
    healMissingState = false,
) => {
    const trace: string[] = [];
    let checkpoint = false;
    for (const limit of schedule.generationLimits) {
        for (let read = 0; read < Math.min(limit, generationReads); read++)
            trace.push(`generation read ${read}`);
        if (limit < generationReads) {
            trace.push('generation pending');
        } else {
            trace.push('checkpoint retained');
            checkpoint = true;
            break;
        }
    }
    if (!checkpoint) return trace;
    if (schedule.lostBeforeContinuation) return [...trace, 'stopped'];
    trace.push('continuation intent retained');
    let retained = materialize();
    for (let attempt = 0; attempt < 2; attempt++) {
        if (attempt === 1) {
            if (schedule.lostBeforeReplay && !healMissingState)
                return [...trace, 'stopped'];
            trace.push('original state authenticated');
            if (resampleOnReplay) retained = materialize();
        }
        // A later allocation may depend on the complete hidden disclosure.
        // Its failure is included even when that disclosure is never published.
        const required = 1 + ((retained.label + retained.challenge) % 3);
        trace.push(`allocation ${required}`);
        const memory =
            schedule.availableMemory + attempt * schedule.retryExtraMemory;
        trace.push(
            memory < required
                ? 'continuation pending'
                : `published ${retained.label}:${retained.challenge}`,
        );
    }
    return trace;
};

const add = (
    distribution: Map<string, bigint>,
    trace: string[],
    mass: bigint,
) => {
    const key = trace.join('|');
    distribution.set(key, (distribution.get(key) ?? 0n) + mass);
};

describe('staged hidden proof-state coupling', () => {
    it('preserves complete stopped, unfinished and replayed histories across the continuation cut', () => {
        const generationWeights = [1n, 2n, 1n];
        for (const generationLimits of [[], [0], [1], [1, 2], [1, 3], [3]])
            for (const availableMemory of [0, 1, 2, 3])
                for (const retryExtraMemory of [-1, 0, 1, 3])
                    for (const lostBeforeContinuation of [false, true])
                        for (const lostBeforeReplay of [false, true]) {
                            const schedule = {
                                generationLimits,
                                availableMemory,
                                retryExtraMemory,
                                lostBeforeContinuation,
                                lostBeforeReplay,
                            };
                            // The deferred producer has no witness input. Its
                            // independent output label is drawn only at the cut.
                            const deferred = new Map<string, bigint>();
                            for (let reads = 1; reads <= 3; reads++)
                                for (let label = 0; label < 3; label++)
                                    for (
                                        let challenge = 0;
                                        challenge < 3;
                                        challenge++
                                    )
                                        add(
                                            deferred,
                                            observed(reads, schedule, () => ({
                                                label,
                                                challenge,
                                            })),
                                            generationWeights[reads - 1],
                                        );
                            // Enumerate the real experiment's original mask,
                            // not the simulator's label. The late marginal is
                            // uniform for each witness by a distinct bijection.
                            for (let witness = 0; witness < 3; witness++) {
                                const real = new Map<string, bigint>();
                                for (let mask = 0; mask < 3; mask++)
                                    for (let reads = 1; reads <= 3; reads++)
                                        for (
                                            let challenge = 0;
                                            challenge < 3;
                                            challenge++
                                        )
                                            add(
                                                real,
                                                observed(
                                                    reads,
                                                    schedule,
                                                    () => ({
                                                        label:
                                                            (witness + mask) %
                                                            3,
                                                        challenge,
                                                    }),
                                                ),
                                                generationWeights[reads - 1],
                                            );
                                expect(real).toEqual(deferred);
                                expect(
                                    [...real.values()].reduce(
                                        (sum, mass) => sum + mass,
                                        0n,
                                    ),
                                ).toBe(36n);
                            }
                        }
    });

    it('uses no continuation value before authority and only one materialization on replay', () => {
        const schedule: Schedule = {
            generationLimits: [1, 3],
            availableMemory: 0,
            retryExtraMemory: 3,
            lostBeforeContinuation: false,
            lostBeforeReplay: false,
        };
        let calls = 0;
        const materialize = () => {
            calls++;
            return { label: 2, challenge: 0 };
        };
        observed(3, { ...schedule, generationLimits: [1, 2] }, materialize);
        observed(3, { ...schedule, lostBeforeContinuation: true }, materialize);
        expect(calls).toBe(0);
        const trace = observed(3, schedule, materialize);
        expect(calls).toBe(1);
        expect(trace.slice(-4)).toEqual([
            'continuation pending',
            'original state authenticated',
            'allocation 3',
            'published 2:0',
        ]);
    });

    it('rejects final-marginal reasoning when an early failure reveals the mask', () => {
        const joint = (witness: number) => {
            const complete = new Map<string, bigint>();
            const marginal = new Map<string, bigint>();
            for (let mask = 0; mask < 3; mask++) {
                const label = (mask + witness) % 3;
                // The first attempt can remain resource-pending; a later
                // retry with more capacity publishes from the original tape.
                const early =
                    mask === 0
                        ? 'early allocation pending'
                        : 'early allocation succeeded';
                add(complete, [early, `later published ${label}`], 1n);
                add(marginal, [`later published ${label}`], 1n);
            }
            return { complete, marginal };
        };
        const left = joint(0),
            right = joint(1);
        expect(left.marginal).toEqual(right.marginal);
        expect(left.complete).not.toEqual(right.complete);
        expect(
            left.complete.get('early allocation pending|later published 0'),
        ).toBe(1n);
        expect(
            right.complete.has('early allocation pending|later published 0'),
        ).toBe(false);
    });

    it('keeps replay identity and required-state loss outside the transcript cache', () => {
        const schedule: Schedule = {
            generationLimits: [3],
            availableMemory: 3,
            retryExtraMemory: 0,
            lostBeforeContinuation: false,
            lostBeforeReplay: false,
        };
        const repeated = new Map<string, bigint>();
        const resampled = new Map<string, bigint>();
        for (let first = 0; first < 3; first++)
            for (let second = 0; second < 3; second++) {
                let draws = 0;
                const materialize = () => ({
                    label: draws++ === 0 ? first : second,
                    challenge: 0,
                });
                add(repeated, observed(1, schedule, materialize), 1n);
                draws = 0;
                add(resampled, observed(1, schedule, materialize, true), 1n);
            }
        expect(resampled).not.toEqual(repeated);
        expect(resampled.size).toBe(9);
        expect(repeated.size).toBe(3);
        const materialize = () => ({ label: 1, challenge: 2 });
        const lost = { ...schedule, lostBeforeReplay: true };
        const stopped = observed(1, lost, materialize);
        expect(stopped[stopped.length - 1]).toBe('stopped');
        expect(observed(1, lost, materialize, false, true)).not.toEqual(
            stopped,
        );
    });
});
