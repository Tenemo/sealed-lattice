import { concatenate, encodeText, unsigned32 } from './bytes.js';

// The close log retains every close input the participant's state machine
// accepted, in arrival order. Before any input it holds its marker and no
// events.
export const collectingCloseState = () =>
    concatenate(encodeText('CST1'), unsigned32(0));
