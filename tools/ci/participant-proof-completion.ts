import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { rewriteWorkerCheckpoint } from './worker-instrumentation.js';

export type ProofCompletionCut = 'final-record' | 'body-commit';
export type PreparationCut = Readonly<{
    kind: 'contribution' | 'selection' | 'selection-readback' | 'endorsement';
    phase: number;
}>;

// The root generation stays four while the preparation journal's independent
// authorities advance.
// Observe the actual authenticated journal after commit/readback, never an
// uncommitted producer flag. This hook exists only in the guarded worker copy.
export const preparationHaltingClient = (
    worker: Buffer,
    cut: PreparationCut,
) => {
    if (cut.kind === 'selection-readback') {
        assert.equal(cut.phase, 1);
        const patched = rewriteWorkerCheckpoint(
            worker,
            'selection-readback',
            (readback) =>
                `${readback}\nself.postMessage({type:'participant-preparation-halt',kind:'selection-readback',phase:1});\nawait new Promise(() => undefined);`,
        );
        return {
            generation: 4,
            worker: patched,
            digest: createHash('sha512').update(patched).digest('hex'),
            preparationCut: cut,
        };
    }
    assert.ok(
        cut.kind === 'contribution'
            ? Number.isInteger(cut.phase) && cut.phase >= 4 && cut.phase <= 9
            : cut.phase === 1 || cut.phase === 2,
    );
    const field = ['contribution', 'selection', 'endorsement'].indexOf(
        cut.kind,
    );
    const patched = rewriteWorkerCheckpoint(
        worker,
        'root-readback',
        (matched) => `
        if (head.generation === 4) {
            const journal = manifest.suffixes.preparation;
            let journalOffset = 0;
            if (journal) {
                for (let journalField = 0; journalField < 3; journalField++) {
                    const journalLength = new DataView(journal.buffer, journal.byteOffset + journalOffset, 4).getUint32(0, true);
                    journalOffset += 4;
                    if (journalField === ${String(field)} && journalLength > 0 && journal[journalOffset] === ${String(cut.phase)}) {
                        self.postMessage({type:'participant-preparation-halt',kind:${JSON.stringify(cut.kind)},phase:${String(cut.phase)}});
                        await new Promise(() => undefined);
                    }
                    journalOffset += journalLength;
                }
            }
        }
        ${matched}`,
    );
    return {
        generation: 4,
        worker: patched,
        digest: createHash('sha512').update(patched).digest('hex'),
        preparationCut: cut,
    };
};
export type ProofCompletionSlotObservation = Readonly<{
    type: 'participant-proof-record';
    offset: number;
    length: number;
    sha512: string;
    instrumentationMilliseconds: number;
}>;
export type ProofCompletionHaltObservation = Readonly<{
    type: 'participant-proof-completion';
    cut: ProofCompletionCut;
    proofBytes: number;
    storedSlots: number;
}>;

// Only the diagnostic worker observes private record hashes. Each store has
// completed before its observation; neither observation creates authority.
export const proofCompletionHaltingClient = (
    worker: Buffer,
    cut: ProofCompletionCut,
) => {
    const observed = rewriteWorkerCheckpoint(
        worker,
        'proof-slot-store',
        (matched) =>
            matched +
            `
        const observationStarted = performance.now();
        const observationHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-512', buffer.subarray(0, used))), value => value.toString(16).padStart(2, '0')).join('');
        self.postMessage({type:'participant-proof-record',offset:stored,length:used,sha512:observationHash,instrumentationMilliseconds:performance.now()-observationStarted});
    `,
    );
    const halt = `self.postMessage({type:'participant-proof-completion',cut:${JSON.stringify(cut)},proofBytes:proof.reduce((sum, record) => sum + record.length, 0),storedSlots:proof.length}); await new Promise(() => undefined);`;
    const patched = rewriteWorkerCheckpoint(
        observed,
        cut === 'final-record' ? 'proof-finish' : 'proof-body-commit',
        (matched) =>
            cut === 'final-record'
                ? matched + '\n' + halt
                : halt + '\n' + matched,
    );
    return {
        generation: 4,
        cut,
        worker: patched,
        digest: createHash('sha512').update(patched).digest('hex'),
        originalDigest: createHash('sha512').update(worker).digest('hex'),
    };
};

export const validateProofCompletionObservation = (
    value: Readonly<{
        slots: readonly ProofCompletionSlotObservation[];
        halt: ProofCompletionHaltObservation;
    }>,
    bounds: Readonly<{ minimumProofBytes: number; maximumProofBytes: number }>,
    chunkBytes: number,
) => {
    const { slots, halt } = value;
    assert.ok(
        Number.isSafeInteger(halt.proofBytes) &&
            halt.proofBytes >= bounds.minimumProofBytes &&
            halt.proofBytes <= bounds.maximumProofBytes,
    );
    assert.ok(halt.cut === 'final-record' || halt.cut === 'body-commit');
    assert.equal(halt.storedSlots, Math.ceil(halt.proofBytes / chunkBytes));
    assert.equal(slots.length, halt.storedSlots);
    for (const [index, slot] of slots.entries()) {
        assert.equal(slot.offset, index * chunkBytes);
        assert.equal(
            slot.length,
            Math.min(chunkBytes, halt.proofBytes - slot.offset),
        );
        assert.match(slot.sha512, /^[0-9a-f]{128}$/u);
        assert.ok(
            Number.isFinite(slot.instrumentationMilliseconds) &&
                slot.instrumentationMilliseconds >= 0,
        );
    }
};
