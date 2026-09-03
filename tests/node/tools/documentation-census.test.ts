import { describe, expect, it } from 'vitest';

import { compileCompletionPreparationModel } from '#tests/complete-preparation-model.js';
import { compileFullTallyResourceModel } from '#tests/full-tally-resource-model.js';
import { compileFullTallySecurityLedger } from '#tests/full-tally-security-ledger.js';
import {
    compileIndependentPaddedTallyModel,
    projectIndependentPaddedTallyWidth,
} from '#tests/padded-tally-transcript-model.js';
import {
    findFirstCensusMismatch,
    renderDocumentationCensus,
} from '#tools/ci/generate-documentation-census.js';

describe('documentation census generator', () => {
    const rendered = renderDocumentationCensus();

    it('renders deterministically with every owning section', () => {
        expect(renderDocumentationCensus()).toBe(rendered);
        for (const heading of [
            '## Canonical object lengths',
            '## Circuit and emitted object census by output width',
            '## Scalar command and checkpoint lengths by output width',
            '## Clean verified download by output width',
            '## Operation-key and KMAC census by output width',
            '## Preparation census',
            '## Maximum-width honest work vector',
            '## Maximum-width game census',
            '## Maximum-width exact statistical terms',
            '## Rejected 192-byte projection by output width',
        ]) {
            expect(rendered).toContain(`\n${heading}\n`);
        }
        expect(rendered).not.toMatch(/\d{4}-\d{2}-\d{2}T/u);
        expect(rendered.endsWith('\n')).toBe(true);
    });

    it('agrees across the independent models it renders', () => {
        const tally = compileIndependentPaddedTallyModel(10);
        const emitted = projectIndependentPaddedTallyWidth(tally, 40);
        const preparation = compileCompletionPreparationModel(tally);
        const ledger = compileFullTallySecurityLedger(10);
        const resource = compileFullTallyResourceModel(10, 10);
        expect(ledger.honestWork.activationChunkCorpusByteLength).toBe(
            resource.activationChunkCorpusByteLength,
        );
        expect(emitted.completeChunkCorpusByteLength).toBe(
            resource.activationChunkCorpusByteLength,
        );
        expect(emitted.maximumChunkEvaluationRequestByteLength).toBe(
            resource.maximumChunkEvaluationRequestByteLength,
        );
        expect(ledger.operation.generationKmacInvocationCount).toBe(
            tally.kmacCensus.generationCallCount,
        );
        expect(ledger.preparation.distinctDerivedSubkeyCount).toBe(
            preparation.streams.uniqueDerivedSubkeyCount,
        );
        expect(ledger.preparation.scalarAesBlockInvocationCount).toBe(
            preparation.streams.scalarAesInvocationCount,
        );
        for (const value of [
            resource.cleanVerifiedDownloadByteLength,
            emitted.maximumChunkEvaluationRequestByteLength,
            tally.kmacCensus.selectedEvaluationCallCount,
            preparation.streams.maximumDerivedSubkeyInvocationCount,
        ]) {
            expect(rendered).toContain(`\`${value.toLocaleString('en-US')}\``);
        }
    });

    it('locates the first stale line of a stored census', () => {
        expect(findFirstCensusMismatch(rendered, rendered)).toBeUndefined();
        expect(
            findFirstCensusMismatch(rendered.replace(/\n/gu, '\r\n'), rendered),
        ).toBeUndefined();
        const lines = rendered.split('\n');
        const target = lines.findIndex((line) => line.startsWith('| 10 |'));
        expect(target).toBeGreaterThan(0);
        lines[target] = `${lines[target] ?? ''} stale`;
        expect(findFirstCensusMismatch(lines.join('\n'), rendered)).toBe(
            target + 1,
        );
        expect(findFirstCensusMismatch(`${rendered}extra\n`, rendered)).toBe(
            lines.length,
        );
    });
});
