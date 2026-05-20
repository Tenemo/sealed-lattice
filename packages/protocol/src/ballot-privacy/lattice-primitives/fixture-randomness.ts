import type { ShareCommitmentProfile } from '@sealed-lattice/types';

import type {
    BallotPrivacyRandomnessSource,
    ReceiverPayloadPlaintextWitness,
} from './primitive-contracts.js';
import { bytesToHex } from './primitive-contracts.js';
import { encodePayloadPlaintextBits } from './receiver-keys.js';

export const createFixtureRandomnessSource = (
    fixtureSeed: string,
): BallotPrivacyRandomnessSource => ({
    allowFixtureMode: true,
    fixtureSeed,
    kind: 'fixture',
});

export const assertNoFixtureRandomnessInProduction = (
    randomnessSource: BallotPrivacyRandomnessSource,
): void => {
    if (randomnessSource.kind === 'fixture') {
        throw new RangeError(
            'Deterministic fixture randomness is not accepted outside explicit test construction.',
        );
    }
};

export const encodeReceiverPayloadPlaintextForTests = (input: {
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
}): string =>
    bytesToHex(
        Uint8Array.from(
            encodePayloadPlaintextBits(
                input.plaintext,
                input.shareCommitmentProfile,
            ),
        ),
    );
