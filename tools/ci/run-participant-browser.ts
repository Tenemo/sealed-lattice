import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    closeParticipantCohort,
    createCohortState,
    openParticipantCohort,
    participantBrowserSettings,
} from '#tools/ci/participant-browser-cohort.js';
import { runFaultSchedule } from '#tools/ci/participant-browser-fault-schedule.js';
import {
    participantBrowserUsage,
    selectParticipantBrowserOptions,
} from '#tools/ci/participant-browser-options.js';
import { runSingleRoster } from '#tools/ci/participant-browser-single-roster.js';
import { runTwoRosters } from '#tools/ci/participant-browser-two-rosters.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// Runs a browser cohort of the selected profile through the maintained
// participant runtime: each participant is its own origin with its own
// external Chrome profile, and a local relay only stores and serves the
// public records the participants publish. Participants never need to be
// online together, so none waits for another's browser: every participant
// whose inputs exist acts at once, in as many browsers as the host has room
// for, and a browser stays open between its participant's operations until
// another needs its room. A no-result run closes with one
// valid on-time ballot fewer than the minimum turnout, and with a corrupt
// participant's authentic invalid ballot on time when the profile tolerates
// one. An empty run closes with no ballot at all. A result run of a profile
// that tolerates two corrupt participants also closes without two honest
// ones: one departs after preparation and casts nothing, and the relay omits
// the other's on-time ballot. Another poll's passed cohort of the same
// profile, named by its run directory, supplies the records a relay view
// serves one participant as this poll's. A rosters run has a corrupt
// organizer complete a second roster of the same poll beside the first,
// each roster with the organizer as its only corrupt member, and serves each
// roster's records to a member of the other. A plain run carries one roster
// of honest participants through each stage once, with no crash, forgery or
// other roster. With --profile, Chrome records every operation's CPU samples,
// and their summary lies beside the run. With --base-port, the origins start
// at another port, so runs of other checkouts may run beside this one. With
// --memory-pressure, a plain run's second contributor first contributes in a
// browser that caps each WebAssembly memory below what its contribution
// needs, which must leave it pending rather than stopped, and its next visit
// completes the contribution. With --scalar, the origins are not isolated,
// so every operation uses one scalar worker without optional helpers. With
// --top-count=<count>, the poll requests that many ranked option identifiers.
// --setup-departure selects four participants and two options, removes honest
// eligible position one immediately after roster publication, and completes
// with positions zero, two and three, where corrupt position two cooperates.
// --unselected-checkpoint instead keeps all four original members available:
// position one endorses and activates the winning setup while its unused
// own contribution remains at the genuine first-oracle checkpoint.
// --departures has a plain run lose the profile's f tolerated members for
// good, spread from the roster's publication to the target vote, so the
// remaining n - f complete every later quorum and the result alone.
if (process.argv.includes('--help')) {
    console.log(participantBrowserUsage);
    process.exit(0);
}
const settings = participantBrowserSettings(
    selectParticipantBrowserOptions(process.argv.slice(2)),
);
const {
    commandLineArguments,
    mode,
    setupDeparture,
    unselectedCheckpoint,
    selectionFork,
    root,
} = settings;

await runWithLocalRunLog(
    {
        commandLineArguments,
        lanes: [
            'Participant runtime assembly',
            'Browser registration and roster agreement',
            'Browser setup contribution',
            'Browser setup verification',
            'Browser signed ballots',
            'Browser close responses',
            'Browser target votes',
            'Browser release shares',
            'Browser result',
            'Browser relay forgeries',
            'Browser records of another poll',
            'Browser altered and lost storage',
        ],
        scriptName: 'research:participant',
    },
    async (log) => {
        const releaseLock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        const state = createCohortState(settings, log);
        try {
            const cohort = await openParticipantCohort(settings, log, state);
            if (
                mode === 'plain' ||
                setupDeparture ||
                unselectedCheckpoint ||
                selectionFork
            )
                await runSingleRoster(cohort);
            else if (mode === 'rosters') await runTwoRosters(cohort);
            else await runFaultSchedule(cohort);
            await cohort.finishAllocation();
            state.cleanup.completed = true;
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            await closeParticipantCohort(state, log);
            await releaseLock();
        }
    },
);
