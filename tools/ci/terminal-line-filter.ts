import { createStreamingLineAccumulator } from './streaming-lines.js';

type TerminalLineFilter = {
    readonly push: (chunk: string) => string;
    readonly flush: () => string;
};

export const createTerminalLineFilter = (
    shouldWriteLine: (line: string) => boolean,
): TerminalLineFilter => {
    let kept = '';
    const lines = createStreamingLineAccumulator((line, lineBreak) => {
        if (shouldWriteLine(line)) kept += line + lineBreak;
    });

    return {
        push: (chunk: string): string => {
            kept = '';
            lines.push(chunk);
            return kept;
        },
        flush: (): string => {
            kept = '';
            lines.flush();
            return kept;
        },
    };
};
