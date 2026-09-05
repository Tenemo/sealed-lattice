import { describe, expect, it } from 'vitest';

import {
    compileCertificateCustodyCensus,
    runCertificateCustodyCounterexample,
} from '#tests/certificate-custody-model.js';

describe('certificate custody after disappearance', () => {
    it('distinguishes a quorum of signers from a recoverable complete certificate', () => {
        const stalled = runCertificateCustodyCounterexample(false);
        expect(stalled.fullCertificateExisted).toBe(true);
        expect(stalled.continuingHonestParticipants).toBe(4);
        expect(stalled.recoverableSignatures).toBe(4);
        expect(stalled.canRecoverCertificate).toBe(false);
        const delivered = runCertificateCustodyCounterexample(true);
        expect(delivered.recoverableSignatures).toBe(7);
        expect(delivered.canRecoverCertificate).toBe(true);
    });

    it('checks every named corruption, disappearance, and full-holder set', () => {
        const census = compileCertificateCustodyCensus();
        // C(10,3)=120 choices for each unavailable set and each complement
        // of a seven-position full-holder set.
        expect(census.checkedConfigurations).toBe(120 ** 3);
        expect(census.minimumSurvivingHonestFullHolders).toBe(
            census.fullHolderThreshold - 2 * census.corruptCount,
        );
        expect(census.minimumSurvivingHonestFullHolders).toBe(1);
    });
});
