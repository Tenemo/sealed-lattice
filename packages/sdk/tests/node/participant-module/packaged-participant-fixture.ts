import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

// The packaged participant module and worker, whose helper role runs on
// threads here as the page starts it beside an operation's worker in a
// cross-origin isolated browser.
export const distribution = new URL('../../../dist/', import.meta.url);

export const moduleBytes = await readFile(
    new URL('participant.wasm', distribution),
);

export const participantModule = await WebAssembly.compile(moduleBytes);

// The failure a call ends with, or undefined when it returns.
export const failureOf = (call: () => unknown) => {
    try {
        call();
    } catch (error) {
        return error;
    }
    return undefined;
};

// Enrollment inputs as the worker frames them. Every randomness request is
// answered from a SHAKE256 stream of the participant's name and the
// request's index, so an enrollment is a function of its inputs alone.
export const shake = (label: string, length: number) =>
    new Uint8Array(
        createHash('shake256', { outputLength: length }).update(label).digest(),
    );

export const payload = (length: number) =>
    length === 0
        ? new Uint8Array()
        : new Uint8Array(
              createHash('shake256', { outputLength: length })
                  .update(String(length))
                  .digest(),
          );
