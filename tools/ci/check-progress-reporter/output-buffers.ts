const outputLineLimit = 80;
const ansiEscapePattern = new RegExp(
    String.raw`\u001B\[[0-?]*[ -/]*[@-~]`,
    'gu',
);

const sanitizeOutputLine = (line: string): string =>
    line.replace(ansiEscapePattern, '').trimEnd();

const formatBufferedOutputLine = (prefix: string, line: string): string => {
    const sanitizedLine = sanitizeOutputLine(line);

    return sanitizedLine.length === 0 ? '' : `${prefix} > ${sanitizedLine}`;
};

export class RecentOutputBuffer {
    readonly #limit: number;
    #lines: string[] = [];
    #pendingLine:
        | {
              readonly prefix: string;
              readonly text: string;
          }
        | undefined;

    constructor(limit = outputLineLimit) {
        this.#limit = limit;
    }

    append(prefix: string, chunk: string): void {
        const normalizedChunk = chunk
            .replace(/\r\n/gu, '\n')
            .replace(/\r/gu, '\n');
        if (normalizedChunk.length === 0) {
            return;
        }
        if (
            this.#pendingLine !== undefined &&
            this.#pendingLine.prefix !== prefix
        ) {
            this.#pushLine(this.#pendingLine.prefix, this.#pendingLine.text);
            this.#pendingLine = undefined;
        }

        const chunkLines = normalizedChunk.split('\n');
        const firstLine = chunkLines[0] ?? '';
        const firstLinePrefix = this.#pendingLine?.prefix ?? prefix;
        chunkLines[0] = `${this.#pendingLine?.text ?? ''}${firstLine}`;
        this.#pendingLine = undefined;

        for (const chunkLine of chunkLines.slice(0, -1)) {
            this.#pushLine(firstLinePrefix, chunkLine);
        }

        const trailingLine = chunkLines[chunkLines.length - 1] ?? '';
        if (trailingLine.length > 0) {
            this.#pendingLine = {
                prefix,
                text: trailingLine,
            };
        }
    }

    snapshot(limit = this.#limit): readonly string[] {
        const pendingLine =
            this.#pendingLine === undefined
                ? ''
                : formatBufferedOutputLine(
                      this.#pendingLine.prefix,
                      this.#pendingLine.text,
                  );
        const lines =
            pendingLine.length === 0
                ? this.#lines
                : [...this.#lines, pendingLine];

        return lines.slice(-limit);
    }

    #pushLine(prefix: string, line: string): void {
        const formattedLine = formatBufferedOutputLine(prefix, line);
        if (formattedLine.length === 0) {
            return;
        }

        this.#lines.push(formattedLine);
        if (this.#lines.length > this.#limit) {
            this.#lines = this.#lines.slice(-this.#limit);
        }
    }
}

export class OutputLineBuffer {
    #pendingLine = '';

    append(chunk: string, onLine: (line: string) => void): void {
        const normalizedChunk = chunk
            .replace(/\r\n/gu, '\n')
            .replace(/\r/gu, '\n');
        if (normalizedChunk.length === 0) {
            return;
        }

        const lines = `${this.#pendingLine}${normalizedChunk}`.split('\n');
        this.#pendingLine = lines.pop() ?? '';
        for (const line of lines) {
            onLine(line);
        }
    }

    flush(onLine: (line: string) => void): void {
        if (this.#pendingLine.length === 0) {
            return;
        }

        onLine(this.#pendingLine);
        this.#pendingLine = '';
    }
}
