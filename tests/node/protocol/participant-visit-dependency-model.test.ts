import { describe, expect, it } from 'vitest';

import { compileParticipantVisitDependencyCensus } from '#tests/participant-visit-dependency-model.js';

describe('participant visit dependency model', () => {
    it('keeps the candidate at the mandatory ceiling but not the preference', () => {
        expect(compileParticipantVisitDependencyCensus()).toEqual({
            maximumPermittedVisitCount: 10,
            noResultVisitCount: 9,
            preferredVisitCount: 5,
            successfulResultVisitCount: 10,
            successfulResultStageCount: 10,
            withinMaximumVisitCount: true,
            withinPreferredVisitCount: false,
        });
    });
});
