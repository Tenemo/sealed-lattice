import { deserialize } from 'node:v8';

import { inject } from 'vitest';

import {
    primeSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

const serialized = inject('supportedProfiles');
if (serialized !== undefined)
    primeSupportedProfiles(
        deserialize(
            Buffer.from(serialized, 'base64'),
        ) as readonly SupportedProfile[],
    );
