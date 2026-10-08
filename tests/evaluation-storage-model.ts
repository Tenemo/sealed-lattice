import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { evaluateFixedModulusBfvRanking } from '#tests/fixed-modulus-bfv-ranking-model.js';
import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

type Instruction = { operation: number; inputs: number[]; parameter: number };
const unsigned = (value: number, width = 4) => {
    const bytes = Buffer.alloc(width);
    bytes.writeUIntLE(value, 0, width);
    return bytes;
};
const item = (type: number, bytes: Buffer) =>
    Buffer.concat([unsigned(type, 2), unsigned(bytes.length), bytes]);
const variable = (bytes: Buffer) =>
    Buffer.concat([unsigned(bytes.length), bytes]);

// Reuses the independent algebraic ranking emitter, then applies the public
// BRK1 postorder encoding. There are no ciphertexts, keys or proof operations.
export const compileRankingProgramModel = (
    profile: SupportedProfile,
    topCount = profile.optionCount,
) => {
    if (
        !Number.isInteger(topCount) ||
        topCount < 1 ||
        topCount > profile.optionCount
    )
        throw new RangeError('Unsupported result prefix.');
    const original: Instruction[] = [];
    const append = (operation: number, inputs: number[], parameter = 0) => {
        const index = original.length;
        original.push({ operation, inputs, parameter });
        return index;
    };
    const inputs = Array.from(
        { length: profile.participantCount },
        (_, position) => append(0, [], position),
    );
    const result = evaluateFixedModulusBfvRanking(
        inputs,
        profile.optionCount,
        fixedModulusBfvInputs.comparisonBlockWidth,
        {
            add: (left, right) => append(1, [left, right]),
            multiply: (left, right) => append(2, [left, right]),
            multiplyScalar: (value, exponent) => append(3, [value], exponent),
            multiplyPlaintext: (value, exponent) =>
                append(
                    4,
                    [value],
                    exponent +
                        (topCount === profile.optionCount
                            ? 0
                            : profile.optionCount * topCount),
                ),
            addPlaintext: (value, purpose) =>
                append(
                    5,
                    [value],
                    purpose === 'comparison-input-offset'
                        ? 0
                        : purpose === 'comparison-constant'
                          ? 1
                          : topCount === profile.optionCount
                            ? 2
                            : 2 + topCount,
                ),
            rotate: (value) => append(6, [value]),
        },
    ).result;
    const seen = new Set<number>(),
        order: number[] = [];
    const visit = (index: number) => {
        if (seen.has(index)) return;
        seen.add(index);
        original[index].inputs.forEach(visit);
        order.push(index);
    };
    visit(result);
    assert.equal(order.length, original.length);
    const renamed = new Map(order.map((value, index) => [value, index]));
    const instructions = order.map((index) => ({
        ...original[index],
        inputs: original[index].inputs.map((input) => renamed.get(input)!),
    }));
    const bytes = Buffer.concat([
        Buffer.from('BRK1'),
        unsigned(Number(fixedModulusBfvInputs.polynomialDegree)),
        unsigned(instructions.length),
        unsigned(instructions.length - 1),
        ...instructions.map((instruction) =>
            Buffer.concat([
                unsigned(instruction.operation),
                unsigned(instruction.inputs[0] ?? 0xffffffff),
                unsigned(instruction.inputs[1] ?? 0xffffffff),
                unsigned(instruction.parameter),
            ]),
        ),
    ]);
    const identityInput = Buffer.concat([
        unsigned(1, 2),
        unsigned(1, 2),
        unsigned(2),
        item(2, variable(Buffer.from('sealed-lattice/ranking-program/v1'))),
        item(1, variable(bytes)),
    ]);
    return {
        instructions,
        bytes,
        identity: createHash('shake256', { outputLength: 64 })
            .update(identityInput)
            .digest('hex'),
    };
};

// Source operands: ranking::{capacity,scratch_bytes}, arithmetic-jobs::job_bytes
// and participant-module::memory_plan. This exact lane has zero helpers.
export const compileScalarEvaluationCapacity = (profile: SupportedProfile) => {
    const rns = compileRnsArithmeticResourceCensus(profile);
    const residue = rns.degree * 8n;
    const polynomial = rns.canonicalPolynomialBytes;
    const tensor = rns.exactProductPrimes,
        external = rns.externalProductPrimes;
    const gadget = profile.gadgetLength;
    const maximum = (...values: bigint[]) =>
        values.reduce((left, right) => (left > right ? left : right));
    const minimum = (left: bigint, right: bigint) =>
        left < right ? left : right;
    const setPrimes = (8n << 20n) / (64n + residue);
    const held = (count: bigint) => minimum(count, setPrimes);
    const jobBytes =
        16n +
        8n +
        72n +
        8n * rns.coefficientWords * 1024n +
        maximum(
            (held(tensor) + 1n) * residue,
            held(external) * (2n * residue + 64n),
            2n * residue + gadget * 64n + 24n * 4096n,
            2n * 8n * 2048n * (tensor + rns.coefficientWords),
        );
    const tensorScratch = 3n * polynomial + 4n * tensor * residue;
    const keyedScratch = polynomial + (2n * external + 2n * gadget) * residue;
    const loadScratch = 2n * polynomial + external * residue;
    const scratchBytes = [
        0n,
        0n,
        maximum(tensorScratch, 2n * polynomial + keyedScratch, loadScratch),
        0n,
        2n * (polynomial + rns.keyProductPrimes * residue),
        0n,
        maximum(2n * polynomial, polynomial + keyedScratch, loadScratch),
    ];
    const evaluatorPlanningBytes = 402_653_184n;
    const scalarInstanceBoundBytes = 671_088_640n;
    const reserves =
        67_108_864n + 2_097_152n + tensor * 2n * residue + jobBytes;
    const storedValueBytes = 2n * polynomial;
    const capacities = scratchBytes.map((scratch) => {
        const available =
            minimum(evaluatorPlanningBytes, scalarInstanceBoundBytes) -
            reserves -
            scratch;
        assert.ok(available >= 3n * storedValueBytes);
        return Number(available / storedValueBytes);
    });
    return {
        rns,
        jobBytes,
        scratchBytes,
        capacities,
        evaluatorPlanningBytes,
        scalarInstanceBoundBytes,
        storedValueBytes,
        keyOrdinalBytes: external * residue,
        multiplicationKeyBytes: rns.multiplicationKeyRecordBytes,
        rotationKeyBytes: rns.multiplicationKeyRecordBytes / 2n,
    };
};

type Cache = 'multiplication' | 'rotation' | undefined;
type EvaluationStorageEvent = {
    step: number;
    operation: number;
    capacity: number;
    cache: Cache;
    changedCache: boolean;
    spills: number[];
    reloads: number[];
    drops: number[];
    retired: number[];
    stored: number[];
    payloadBytes: bigint;
};

// Interprets only liveness and successful storage transitions. A reload keeps
// its stored copy until last use. Old host key records survive native cache
// invalidation while spills/readbacks/reloads run, then an awaited deletion
// precedes the replacement bank's ordinal writes (SDK target::evaluate).
export const compileEvaluationStorage = (
    profile: SupportedProfile,
    topCount = profile.optionCount,
) => {
    const program = compileRankingProgramModel(profile, topCount);
    const capacity = compileScalarEvaluationCapacity(profile);
    const instructions = program.instructions;
    const uses = instructions.map(() => 0);
    instructions.forEach((instruction) =>
        instruction.inputs.forEach((input) => uses[input]++),
    );
    uses[uses.length - 1] = 1;
    const resident = new Set<number>(),
        stored = new Set<number>();
    const events: EvaluationStorageEvent[] = [];
    let cache: Cache,
        hostKeys = 0n,
        peakBytes = 0n,
        peakStored = 0,
        spillCount = 0,
        reloadCount = 0,
        dropCount = 0,
        keyBankWrites = 0n;
    let peak:
        | { step: number; phase: string; keyBytes: bigint; stored: number[] }
        | undefined;
    const sample = (step: number, phase: string) => {
        peakStored = Math.max(peakStored, stored.size);
        const bytes =
            hostKeys + BigInt(stored.size) * capacity.storedValueBytes;
        if (bytes > peakBytes) {
            peakBytes = bytes;
            peak = {
                step,
                phase,
                keyBytes: hostKeys,
                stored: [...stored].sort((left, right) => left - right),
            };
        }
    };
    for (const [step, instruction] of instructions.entries()) {
        const wanted =
            instruction.operation === 2
                ? 'multiplication'
                : instruction.operation === 6
                  ? 'rotation'
                  : cache;
        const changedCache = wanted !== cache;
        cache = wanted;
        const required = new Set(instruction.inputs);
        const reloads = [...required]
            .sort((left, right) => left - right)
            .filter((input) => !resident.has(input));
        reloads.forEach((input) => assert.ok(stored.has(input)));
        const spills: number[] = [],
            drops: number[] = [];
        const nextUse = (input: number) => {
            const following = instructions
                .slice(step + 1)
                .findIndex((next) => next.inputs.includes(input));
            return following < 0 ? instructions.length : step + 1 + following;
        };
        while (
            resident.size + reloads.length + 1 >
            capacity.capacities[instruction.operation]
        ) {
            const candidates = [...resident].filter(
                (input) => !required.has(input),
            );
            assert.ok(candidates.length > 0);
            candidates.sort(
                (left, right) => nextUse(right) - nextUse(left) || right - left,
            );
            const evicted = candidates[0];
            resident.delete(evicted);
            (stored.has(evicted) ? drops : spills).push(evicted);
        }
        for (const input of spills) {
            stored.add(input);
            sample(step, 'spill written before possible key-bank replacement');
        }
        reloads.forEach((input) => resident.add(input));
        if (changedCache) {
            hostKeys = 0n;
            sample(step, 'old key bank deleted');
            const ordinals =
                (cache === 'multiplication' ? 4 : 2) *
                Number(profile.gadgetLength);
            for (let ordinal = 0; ordinal < ordinals; ordinal++) {
                hostKeys += capacity.keyOrdinalBytes;
                keyBankWrites += capacity.keyOrdinalBytes;
                sample(step, 'replacement key ordinal written');
            }
        }
        resident.add(step);
        sample(step, 'before execution');
        const retired: number[] = [];
        for (const input of instruction.inputs)
            if (--uses[input] === 0) {
                resident.delete(input);
                stored.delete(input);
                retired.push(input);
            }
        sample(step, 'last-use records deleted');
        spillCount += spills.length;
        reloadCount += reloads.length;
        dropCount += drops.length;
        events.push({
            step,
            operation: instruction.operation,
            capacity: capacity.capacities[instruction.operation],
            cache,
            changedCache,
            spills,
            reloads,
            drops,
            retired,
            stored: [...stored].sort((left, right) => left - right),
            payloadBytes:
                hostKeys + BigInt(stored.size) * capacity.storedValueBytes,
        });
    }
    assert.equal(stored.size, 0);
    return {
        program,
        capacity,
        events,
        peak,
        peakBytes,
        peakStored,
        spillCount,
        reloadCount,
        dropCount,
        keyBankWriteBytes: keyBankWrites,
        spillWriteBytes: BigInt(spillCount) * capacity.storedValueBytes,
        spillReadbackBytes: BigInt(spillCount) * capacity.storedValueBytes,
        reloadBytes: BigInt(reloadCount) * capacity.storedValueBytes,
        scratchPlanningBytes: 268_435_456n,
        scratchVarianceCeilingBytes: 402_653_184n,
    };
};
