type StreamingLineAccumulator = Readonly<{
    flush: () => void;
    pending: () => string;
    push: (chunk: string) => void;
    reset: () => void;
}>;

export const createStreamingLineAccumulator = (
    consumeLine: (line: string, lineBreak: string) => void,
): StreamingLineAccumulator => {
    let pending = '';

    const consumeCompleteLines = (): void => {
        let lineStart = 0;
        let characterIndex = 0;
        while (characterIndex < pending.length) {
            const character = pending[characterIndex];
            if (character === '\n') {
                consumeLine(pending.slice(lineStart, characterIndex), '\n');
                characterIndex += 1;
                lineStart = characterIndex;
                continue;
            }
            if (character === '\r') {
                if (characterIndex + 1 === pending.length) break;
                const isCrLf = pending[characterIndex + 1] === '\n';
                consumeLine(
                    pending.slice(lineStart, characterIndex),
                    isCrLf ? '\r\n' : '\r',
                );
                characterIndex += isCrLf ? 2 : 1;
                lineStart = characterIndex;
                continue;
            }
            characterIndex += 1;
        }
        pending = pending.slice(lineStart);
    };

    return {
        flush: () => {
            if (pending.length === 0) return;
            const remainder = pending;
            pending = '';
            if (remainder.endsWith('\r')) {
                consumeLine(remainder.slice(0, -1), '\r');
            } else {
                consumeLine(remainder, '');
            }
        },
        pending: () => pending,
        push: (chunk) => {
            pending += chunk;
            consumeCompleteLines();
        },
        reset: () => {
            pending = '';
        },
    };
};
