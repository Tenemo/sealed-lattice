import type { ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import { closeFaultBallots } from '#tools/ci/participant-fault-close.js';
import { verifyFaultOutcome } from '#tools/ci/participant-fault-outcome.js';
import { prepareFaultCohort } from '#tools/ci/participant-fault-preparation.js';
import { registerFaultCohort } from '#tools/ci/participant-fault-registration.js';
import { releaseFaultTarget } from '#tools/ci/participant-fault-release.js';

// One ordered lifecycle retains the same participants and fault state through every stage.
export const runFaultSchedule = async (cohort: ParticipantCohort) => {
    const registered = await registerFaultCohort(cohort);
    const prepared = await prepareFaultCohort(cohort, registered);
    if (prepared === undefined) return;
    const closed = await closeFaultBallots(cohort, prepared);
    const released = await releaseFaultTarget(cohort, closed);
    await verifyFaultOutcome(cohort, registered, prepared, closed, released);
};
