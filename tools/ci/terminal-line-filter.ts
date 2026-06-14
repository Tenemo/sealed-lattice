// A streaming line filter for terminal output. A child process emits output in
// arbitrary chunks that do not align to line boundaries, so deciding per line
// whether to echo a line to the terminal needs a small buffer that reassembles
// whole lines across chunks. `push` returns only the kept lines for the chunks
// seen so far; `flush` returns any final unterminated remainder. It is
// deliberately subtractive: a line is echoed unless `shouldWriteLine` returns
// false, so a wrong predicate can at worst leave an unwanted line in, never drop
// wanted output.

type TerminalLineFilter = {
    readonly push: (chunk: string) => string;
    readonly flush: () => string;
};

export const createTerminalLineFilter = (
    shouldWriteLine: (line: string) => boolean,
): TerminalLineFilter => {
    let pending = '';

    return {
        push: (chunk: string): string => {
            pending += chunk;
            let kept = '';
            let newlineIndex = pending.indexOf('\n');
            while (newlineIndex !== -1) {
                const lineWithBreak = pending.slice(0, newlineIndex + 1);
                if (shouldWriteLine(lineWithBreak.replace(/\r?\n$/, ''))) {
                    kept += lineWithBreak;
                }
                pending = pending.slice(newlineIndex + 1);
                newlineIndex = pending.indexOf('\n');
            }

            return kept;
        },
        flush: (): string => {
            if (pending.length === 0) {
                return '';
            }
            const remainder = pending;
            pending = '';

            return shouldWriteLine(remainder.replace(/\r?\n$/, ''))
                ? remainder
                : '';
        },
    };
};
