import { describe, expect, it } from 'vitest';

import {
    writeInput,
    writeSetupInput,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    inputBuffers,
    type PublicInputCommand,
    publicInputCommands,
    drawArgument,
    writtenBytes,
} from '#packages/sdk/tests/node/participant-module/public-input-commands.js';
import {
    instantiate,
    shake,
    draws,
    call,
    minimumParticipants,
    joinInput,
    rosterBegin,
} from '#packages/sdk/tests/node/participant-module/public-input-fixture.js';

describe('participant module public input', () => {
    it('refuses arbitrary arguments and bytes at every command that reads public input, and the instance stays usable', async () => {
        const { module } = await instantiate();
        // Open roster verifications give the record commands a verifier to
        // refuse in.
        const begin = rosterBegin(minimumParticipants);
        writeInput(module, begin);
        expect(module.roster_begin(begin.length)).toBe(0);
        writeSetupInput(module, begin);
        expect(module.setup_roster_begin(begin.length)).toBe(0);
        // Writes the case's bytes up to its length, the last argument, and
        // expects the command to refuse.
        const refuses = (
            command: PublicInputCommand,
            values: readonly number[],
            label: string,
        ) => {
            const buffer = inputBuffers[command.buffer];
            const length =
                values.length === 0
                    ? 0
                    : Math.min(
                          values[values.length - 1],
                          buffer.capacity(module),
                          writtenBytes,
                      );
            // The pointer call may grow the memory, so the view is taken
            // after it.
            const pointer = buffer.pointer(module) >>> 0;
            if (length > 0)
                new Uint8Array(module.memory.buffer, pointer, length).set(
                    shake(label + '/bytes', length),
                );
            const result = call(module, command.name, values, label);
            // Empty cancellation discards tentative public input at a roster
            // position. Success is cleanup, not an accepted registration.
            const cancellation =
                (command.name === 'roster_record' ||
                    command.name === 'setup_roster_record') &&
                values[0] === 5 &&
                values[1] < minimumParticipants &&
                values[2] === 0;
            expect(
                cancellation
                    ? result === 0
                    : command.query === true
                      ? result === 0
                      : result === 1,
                `${label}: ${command.name}(${values.join(', ')}) returned ${String(result)}`,
            ).toBe(true);
        };
        for (const command of publicInputCommands) {
            const capacity = inputBuffers[command.buffer].capacity(module);
            for (let index = 0; index < 64; index += 1) {
                const label = command.name + '/' + String(index);
                const draw = draws(label);
                refuses(
                    command,
                    command.parameters.map((parameter) =>
                        drawArgument(parameter, draw, capacity),
                    ),
                    label,
                );
            }
        }
        // Every operation of a command that takes one, at each small length
        // a command may require exactly.
        for (const command of publicInputCommands)
            if (command.parameters[0] === 'operation')
                for (let operation = 0; operation < 32; operation += 1)
                    for (let length = 0; length <= 40; length += 1)
                        for (const index of [0, 1])
                            refuses(
                                command,
                                command.parameters.map((parameter) =>
                                    parameter === 'operation'
                                        ? operation
                                        : parameter === 'length'
                                          ? length
                                          : index,
                                ),
                                `${command.name}/operation/${String(operation)}/${String(length)}/${String(index)}`,
                            );
        const join = joinInput('First voter');
        writeInput(module, join);
        expect(module.validate_joiner(join.length)).toBe(0);
        writeInput(module, begin);
        expect(module.roster_begin(begin.length)).toBe(0);
        writeSetupInput(module, begin);
        expect(module.setup_roster_begin(begin.length)).toBe(0);
    });
});
