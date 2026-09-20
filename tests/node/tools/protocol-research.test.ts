import { describe, expect, it } from 'vitest';

import { sumProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import {
    selectProtocolResearchCase,
    selectPublicCompletionCase,
} from '#tools/ci/protocol-research-registry.js';

describe('guarded protocol research entry', () => {
    it('requires an explicit public case and a nonempty fixture', () => {
        for (const values of [
            [],
            ['available-records'],
            ['available-records', ''],
            ['unknown', 'fixture'],
            ['certificate-records', 'fixture'],
            ['terminal-records', 'fixture', ''],
            ['certificate-records', '', 'records'],
            ['terminal-records', 'fixture', 'records', 'extra'],
        ])
            expect(() => selectPublicCompletionCase(values)).toThrow();
        expect(
            selectPublicCompletionCase(['available-records', 'fixture']),
        ).toEqual({
            name: 'available-records',
            source: 'fixture',
            stage: 'terminal',
            completionDirectory: undefined,
        });
        for (const [name, stage] of [
            ['certificate-records', 'certificate'],
            ['terminal-records', 'terminal'],
        ]) {
            expect(
                selectPublicCompletionCase(['--', name, 'fixture', 'records']),
            ).toEqual({
                name,
                stage,
                source: 'fixture',
                completionDirectory: 'records',
            });
        }
    });
    it('refuses empty, unknown and ambiguous case selectors', () => {
        for (const values of [
            [],
            ['--'],
            ['unknown'],
            ['native-result', 'native-empty'],
        ]) {
            expect(() => selectProtocolResearchCase(values)).toThrow();
        }
        expect(selectProtocolResearchCase(['--', 'native-empty'])).toEqual({
            name: 'native-empty',
            execution: true,
            empty: true,
        });
        expect(selectProtocolResearchCase(['check']).execution).toBe(false);
    });

    it('charges descendants independent of enumeration order without charging unrelated processes', () => {
        const rows = [
            { identifier: 4, parent: 3, bytes: 40 },
            { identifier: 8, parent: 1, bytes: 800 },
            { identifier: 3, parent: 2, bytes: 30 },
            { identifier: 2, parent: 1, bytes: 20 },
        ];
        expect(sumProtocolProcessTree(2, rows)).toBe(90);
        expect(sumProtocolProcessTree(2, [...rows].reverse())).toBe(90);
        expect(sumProtocolProcessTree(5, rows)).toBeUndefined();
    });
});
