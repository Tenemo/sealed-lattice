import { describe, expect, it } from 'vitest';

import { createTerminalLineFilter } from '#tools/ci/terminal-line-filter';

const keepUnlessMarkedDrop = (line: string): boolean => !line.includes('DROP');

describe('createTerminalLineFilter', () => {
    it('passes kept lines and removes dropped lines within one chunk', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('keep one\nDROP this\nkeep two\n')).toBe(
            'keep one\nkeep two\n',
        );
        expect(filter.flush()).toBe('');
    });

    it('reassembles a kept line split across chunks before emitting it', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('kept li')).toBe('');
        expect(filter.push('ne here\n')).toBe('kept line here\n');
    });

    it('drops a filtered line even when its marker is split across chunks', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('partial DR')).toBe('');
        expect(filter.push('OP rest\nkeep\n')).toBe('keep\n');
    });

    it('holds an unterminated remainder until flush', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('done\ntrailing without newline')).toBe('done\n');
        expect(filter.flush()).toBe('trailing without newline');
    });

    it('applies the predicate to an unterminated remainder on flush', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('DROP trailing')).toBe('');
        expect(filter.flush()).toBe('');
    });

    it('preserves carriage returns in kept output but ignores them when filtering', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('DROP me\r\n')).toBe('');
        expect(filter.push('keep me\r\n')).toBe('keep me\r\n');
    });

    it('emits nothing for a chunk that contains no line break', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('no newline yet')).toBe('');
        expect(filter.flush()).toBe('no newline yet');
    });

    it('handles several lines plus a trailing partial in one chunk', () => {
        const filter = createTerminalLineFilter(keepUnlessMarkedDrop);

        expect(filter.push('a\nDROP b\nc\npartial')).toBe('a\nc\n');
        expect(filter.flush()).toBe('partial');
    });
});
