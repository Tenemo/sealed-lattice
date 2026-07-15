import { describe, expect, it } from 'vitest';

import { createTerminalLineFilter } from '#tools/ci/terminal-line-filter';

const keepUnlessMarkedDrop = (line: string): boolean => !line.includes('DROP');

describe('createTerminalLineFilter', () => {
    it('filters complete lines while preserving line endings', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('keep one\nDROP this\nkeep two\r\n')).toBe(
            'keep one\nkeep two\r\n',
        );
        expect(filter.flush()).toBe('');
    });

    it('reassembles split lines before deciding whether to keep them', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('kept li')).toBe('');
        expect(filter.push('ne\npartial DR')).toBe('kept line\n');
        expect(filter.push('OP rest\nkeep\n')).toBe('keep\n');
    });

    it.each([
        { expected: 'trailing', remainder: 'trailing' },
        { expected: '', remainder: 'DROP trailing' },
    ])(
        'applies the predicate to an unterminated remainder',
        ({ expected, remainder }) => {
            const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

            expect(filter.push(`complete\n${remainder}`)).toBe('complete\n');
            expect(filter.flush()).toBe(expected);
            expect(filter.flush()).toBe('');
        },
    );
});
