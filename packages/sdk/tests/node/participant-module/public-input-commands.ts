import type { ParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { type ModuleCommand } from '#packages/sdk/tests/node/participant-module/public-input-fixture.js';

// The module's input buffers and the commands that read public input from
// them. Every command refuses with one; a query answers zero when it refuses.
type InputBuffer = Readonly<{
    pointer: (module: ParticipantModule) => number;
    capacity: (module: ParticipantModule) => number;
}>;

export const inputBuffers = {
    session: {
        pointer: (module) => module.input_pointer(),
        capacity: (module) => module.input_capacity(),
    },
    ownRegistration: {
        pointer: (module) => module.own_registration_input_pointer(),
        capacity: (module) => module.own_registration_input_capacity(),
    },
    setup: {
        pointer: (module) => module.setup_input_pointer(),
        capacity: (module) => module.setup_input_capacity(),
    },
    close: {
        pointer: (module) => module.close_input_pointer(),
        capacity: (module) => module.close_input_capacity(),
    },
    ballotBody: {
        pointer: (module) => module.ballot_body_input_pointer(),
        capacity: (module) => module.ballot_body_input_capacity(),
    },
    evaluationTarget: {
        pointer: (module) => module.evaluation_target_input_pointer(),
        capacity: (module) => module.evaluation_target_input_capacity(),
    },
    completion: {
        pointer: (module) => module.completion_input_pointer(),
        capacity: (module) => module.completion_input_capacity(),
    },
} as const satisfies Record<string, InputBuffer>;

type Parameter = 'operation' | 'index' | 'length';

export type PublicInputCommand = Readonly<{
    name: ModuleCommand;
    buffer: keyof typeof inputBuffers;
    parameters: readonly Parameter[];
    query?: true;
}>;

export const publicInputCommands: readonly PublicInputCommand[] = [
    { name: 'validate_joiner', buffer: 'session', parameters: ['length'] },
    { name: 'roster_begin', buffer: 'session', parameters: ['length'] },
    {
        name: 'roster_record',
        buffer: 'session',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'roster_finish',
        buffer: 'session',
        parameters: [],
    },
    {
        name: 'verify_roster_signature',
        buffer: 'session',
        parameters: ['length'],
    },
    {
        name: 'participant_close_command',
        buffer: 'session',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'participant_finality_command',
        buffer: 'session',
        parameters: ['operation', 'length'],
    },
    {
        name: 'participant_release_command',
        buffer: 'session',
        parameters: ['operation', 'length'],
    },
    {
        name: 'own_registration_command',
        buffer: 'ownRegistration',
        parameters: ['operation', 'length'],
    },
    { name: 'setup_roster_begin', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_roster_record',
        buffer: 'setup',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'setup_roster_finish',
        buffer: 'setup',
        parameters: ['length'],
    },
    { name: 'setup_offer_begin', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_offer_source', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_source_range', buffer: 'setup', parameters: [] },
    {
        name: 'setup_selected_offer_source',
        buffer: 'setup',
        parameters: ['length'],
    },
    {
        name: 'setup_public_work',
        buffer: 'setup',
        parameters: ['operation', 'index', 'index', 'length'],
    },
    {
        name: 'setup_offer_polynomial',
        buffer: 'setup',
        parameters: ['index', 'index', 'length'],
    },
    {
        name: 'setup_offer_proof',
        buffer: 'setup',
        parameters: ['index', 'length'],
    },
    {
        name: 'setup_offer_finish',
        buffer: 'setup',
        parameters: [],
    },
    {
        name: 'setup_offer_available',
        buffer: 'setup',
        parameters: ['index', 'length'],
        query: true,
    },
    { name: 'setup_selection_build', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_selection_begin', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_selection_aggregate',
        buffer: 'setup',
        parameters: [],
    },
    {
        name: 'setup_begin_selected_offer',
        buffer: 'setup',
        parameters: ['index'],
    },
    {
        name: 'setup_begin_selected_offer_verification',
        buffer: 'setup',
        parameters: ['length'],
    },
    {
        name: 'setup_polynomial',
        buffer: 'setup',
        parameters: ['index', 'index', 'length'],
    },
    {
        name: 'setup_selected_offer_proof',
        buffer: 'setup',
        parameters: ['index', 'length'],
    },
    {
        name: 'setup_finish_selected_offer',
        buffer: 'setup',
        parameters: [],
    },
    {
        name: 'setup_selection_finish',
        buffer: 'setup',
        parameters: [],
    },
    { name: 'setup_endorsement', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_certificate_build', buffer: 'setup', parameters: [] },
    { name: 'setup_certificate', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_finish_certificate',
        buffer: 'setup',
        parameters: [],
    },
    {
        name: 'close_command',
        buffer: 'close',
        parameters: ['operation', 'length'],
    },
    {
        name: 'ballot_classification_begin',
        buffer: 'ballotBody',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_key_begin',
        buffer: 'ballotBody',
        parameters: ['index'],
    },
    {
        name: 'ballot_classification_key_chunk',
        buffer: 'ballotBody',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_key_finish',
        buffer: 'ballotBody',
        parameters: [],
    },
    {
        name: 'ballot_classification_chunk',
        buffer: 'ballotBody',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_finish',
        buffer: 'ballotBody',
        parameters: [],
    },
    {
        name: 'evaluation_target_command',
        buffer: 'evaluationTarget',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'completion_command',
        buffer: 'completion',
        parameters: ['operation', 'index', 'length'],
    },
];

// Values at and beyond the bounds the module checks, including those whose
// 32-bit sums wrap.
const boundaryValues = (capacity: number, signatureBytes: number) => [
    0,
    1,
    2,
    3,
    4,
    6,
    8,
    64,
    132,
    signatureBytes - 1,
    signatureBytes,
    signatureBytes + 1,
    4096,
    65_535,
    65_536,
    capacity - 1,
    capacity,
    capacity + 1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fff8,
    0xffff_ffff,
];

export const drawArgument = (
    parameter: Parameter,
    draw: (bound: number) => number,
    capacity: number,
    signatureBytes: number,
) => {
    const boundary = boundaryValues(capacity, signatureBytes);
    if (draw(2) === 0) return boundary[draw(boundary.length)];
    if (parameter === 'operation') return draw(32);
    return draw(parameter === 'length' ? capacity + 1 : 64);
};

// The bytes each case writes before its call; a longer length also reads
// what earlier cases left in the buffer.
export const writtenBytes = 16_384;
