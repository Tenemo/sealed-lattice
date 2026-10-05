import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export type PaddingCut = 'padding' | 'final-slot';
export type PreparationCut = Readonly<{
    kind: 'contribution' | 'selection' | 'selection-readback' | 'endorsement';
    phase: number;
}>;

// The root generation stays four while independent PRE1 authorities advance.
// Observe the actual authenticated journal after commit/readback, never an
// uncommitted producer flag. This hook exists only in the guarded worker copy.
export const preparationHaltingClient = (
    worker: Buffer,
    cut: PreparationCut,
) => {
    if (cut.kind === 'selection-readback') {
        assert.equal(cut.phase, 1);
        const source = worker.toString('utf8');
        const boundary =
            /(await publication\.finish\(\);)(\s*await endorseSetup\(session,\s*relay,\s*retained\);)/gu;
        assert.equal(
            [...source.matchAll(boundary)].length,
            1,
            'The worker must contain one authenticated selection-readback continuation.',
        );
        const patched = Buffer.from(
            source.replace(
                boundary,
                (_matched: string, readback: string, endorsement: string) =>
                    `${readback}\nself.postMessage({type:'participant-preparation-halt',kind:'selection-readback',phase:1});\nawait new Promise(() => undefined);\n${endorsement}`,
            ),
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
    const source = worker.toString('utf8');
    const boundary =
        /return \{\s*head,\s*plaintext: reopened,\s*manifest\s*\};/gu;
    assert.equal(
        [...source.matchAll(boundary)].length,
        1,
        'The worker must contain one completed root readback.',
    );
    const field = ['contribution', 'selection', 'endorsement'].indexOf(
        cut.kind,
    );
    const instrumented = source.replace(
        boundary,
        (matched) => `
        if (head.generation === 4) {
            const journal = manifest.suffixes.preparation;
            let journalOffset = 4;
            if (journal && journal[0] === 80 && journal[1] === 82 && journal[2] === 69 && journal[3] === 49) {
                for (let journalField = 0; journalField < 3; journalField++) {
                    const journalLength = new DataView(journal.buffer, journal.byteOffset + journalOffset, 4).getUint32(0, true);
                    journalOffset += 4;
                    if (journalField === ${String(field)} && journalLength > 0 && journal[journalOffset + ${cut.kind === 'contribution' ? '4' : '0'}] === ${String(cut.phase)}) {
                        self.postMessage({type:'participant-preparation-halt',kind:${JSON.stringify(cut.kind)},phase:${String(cut.phase)}});
                        await new Promise(() => undefined);
                    }
                    journalOffset += journalLength;
                }
            }
        }
        ${matched}`,
    );
    const patched = Buffer.from(instrumented);
    return {
        generation: 4,
        worker: patched,
        digest: createHash('sha512').update(patched).digest('hex'),
        preparationCut: cut,
    };
};
export type PaddingSlotObservation = Readonly<{
    type: 'participant-padding-slot';
    offset: number;
    length: number;
    sha512: string;
    instrumentationMilliseconds: number;
}>;
export type PaddingHaltObservation = Readonly<{
    type: 'participant-padding-halt';
    cut: PaddingCut;
    proofBytes: number;
    slotOffset: number;
    slotLength: number;
    storedSlots: number;
    totalSlots: number;
    paddingOnly: boolean;
}>;

// This code exists only in an explicitly instrumented research worker. The
// store callback has completed before the observation or halt; the product
// worker, private state schema and cryptographic acceptance are unchanged.
export const paddingHaltingClient = (worker: Buffer, cut: PaddingCut) => {
    const source = worker.toString('utf8');
    const boundary =
        /await store\(slot,\s*buffer\.subarray\(0,\s*slot\.length\)\);/gu;
    assert.equal(
        [...source.matchAll(boundary)].length,
        1,
        'The worker must contain one completed private proof-slot store.',
    );
    const condition =
        cut === 'padding'
            ? 'slot.offset + slot.length > length'
            : 'next + 1 === slots.length';
    const instrumented = source.replace(
        boundary,
        (matched) =>
            matched +
            `
        const paddingObservationStarted = performance.now();
        const paddingObservationHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-512', buffer.subarray(0, slot.length))), value => value.toString(16).padStart(2, '0')).join('');
        self.postMessage({type:'participant-padding-slot',offset:slot.offset,length:slot.length,sha512:paddingObservationHash,instrumentationMilliseconds:performance.now()-paddingObservationStarted});
        if (${condition}) {
            self.postMessage({type:'participant-padding-halt',cut:${JSON.stringify(cut)},proofBytes:length,slotOffset:slot.offset,slotLength:slot.length,storedSlots:next+1,totalSlots:slots.length,paddingOnly:slot.offset>=length});
            await new Promise(() => undefined);
        }
    `,
    );
    const patched = Buffer.from(instrumented);
    return {
        generation: 4,
        cut,
        worker: patched,
        digest: createHash('sha512').update(patched).digest('hex'),
        originalDigest: createHash('sha512').update(worker).digest('hex'),
    };
};

// Private replay diagnostics compare fixed slots, including zeros beyond the
// logical proof. Neither these hashes nor this check grants a capability.
export const validatePaddingObservation = (
    value: Readonly<{
        slots: readonly PaddingSlotObservation[];
        halt: PaddingHaltObservation;
    }>,
    bounds: Readonly<{ minimumProofBytes: number; maximumProofBytes: number }>,
    chunkBytes: number,
) => {
    const { slots, halt } = value;
    assert.ok(
        halt.proofBytes >= bounds.minimumProofBytes &&
            halt.proofBytes <= bounds.maximumProofBytes,
    );
    assert.equal(
        halt.totalSlots,
        Math.ceil(bounds.maximumProofBytes / chunkBytes),
    );
    assert.equal(slots.length, halt.storedSlots);
    assert.ok(slots.length > 0 && slots.length <= halt.totalSlots);
    for (const [index, slot] of slots.entries()) {
        assert.equal(slot.offset, index * chunkBytes);
        assert.equal(
            slot.length,
            Math.min(chunkBytes, bounds.maximumProofBytes - slot.offset),
        );
        assert.match(slot.sha512, /^[0-9a-f]{128}$/u);
        assert.ok(
            Number.isFinite(slot.instrumentationMilliseconds) &&
                slot.instrumentationMilliseconds >= 0,
        );
    }
    const last = slots[slots.length - 1];
    assert.equal(last.offset, halt.slotOffset);
    assert.equal(last.length, halt.slotLength);
    assert.equal(halt.paddingOnly, last.offset >= halt.proofBytes);
    if (halt.cut === 'padding')
        assert.ok(last.offset + last.length > halt.proofBytes);
    else {
        assert.equal(halt.cut, 'final-slot');
        assert.equal(halt.storedSlots, halt.totalSlots);
    }
};
