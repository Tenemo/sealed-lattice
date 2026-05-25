import { describe, expect, it } from 'vitest';

import {
    assertPinnedDigest,
    loadPinnedReference,
    verifyPinnedReferenceMetadata,
    verifyPinnedReference,
} from '#tools/lattigo-oracle/verify-lattigo-oracle';

describe('Lattigo oracle boundary tooling', () => {
    it('pins the reference while keeping it outside runtime evidence', async () => {
        const pinnedReference = await loadPinnedReference();
        const verification = await verifyPinnedReference();

        expect(pinnedReference.pinnedCommit).toBe(
            '5dbffbdea05394de2ca3a432ed5318aa832e3f40',
        );
        expect(pinnedReference.schemaVersion).toBe(1);
        expect(pinnedReference.goToolchain).toBe('go1.25.0');
        expect(pinnedReference.runtimeUse).toBe('forbidden');
        expect(pinnedReference.protocolEvidenceUse).toBe('forbidden');
        expect(verification.commandDigest).toBe(
            pinnedReference.oracleCommandDigest,
        );
        expect(verification.dockerfileDigest).toBe(
            pinnedReference.oracleDockerfileDigest,
        );
        expect(typeof verification.archivePresent).toBe('boolean');
        expect(typeof verification.checkoutPresent).toBe('boolean');
    });

    it('fails clearly when pinned metadata or digests drift', async () => {
        const pinnedReference = await loadPinnedReference();
        const goModule = `module sealed-lattice-lattigo-oracle\n\ngo 1.25.0\n`;
        const dockerfile = [
            `FROM ${pinnedReference.containerBaseImage}@${pinnedReference.containerBaseImageDigest}`,
            `COPY ${pinnedReference.archivePath} /workspace/${pinnedReference.archivePath}`,
            `RUN echo "${pinnedReference.archiveSha256}  /workspace/${pinnedReference.archivePath}" | sha256sum -c - && go mod download && go mod verify`,
            'CMD ["go", "run", "-mod=readonly", "."]',
            '',
        ].join('\n');

        expect(() =>
            verifyPinnedReferenceMetadata(
                {
                    ...pinnedReference,
                    schemaVersion: 2,
                },
                goModule,
                dockerfile,
            ),
        ).toThrow(/schema version/u);
        expect(() =>
            verifyPinnedReferenceMetadata(
                pinnedReference,
                `module sealed-lattice-lattigo-oracle\n\ngo 1.24.0\n`,
                dockerfile,
            ),
        ).toThrow(/go\.mod Go version/u);
        expect(() =>
            verifyPinnedReferenceMetadata(
                {
                    ...pinnedReference,
                    containerBaseImage: 'golang:1.24.0-bookworm',
                },
                goModule,
                dockerfile,
            ),
        ).toThrow(/must use Go 1\.25\.0/u);
        expect(() =>
            verifyPinnedReferenceMetadata(
                pinnedReference,
                goModule,
                dockerfile.replace(
                    pinnedReference.archiveSha256,
                    '0'.repeat(64),
                ),
            ),
        ).toThrow(/archive SHA-256/u);
        expect(() =>
            verifyPinnedReferenceMetadata(
                pinnedReference,
                goModule,
                dockerfile.replace(
                    `COPY ${pinnedReference.archivePath} /workspace/${pinnedReference.archivePath}`,
                    [
                        `COPY ${pinnedReference.archivePath} /workspace/${pinnedReference.archivePath}`,
                        `COPY ${pinnedReference.localCheckoutPath} /workspace/${pinnedReference.localCheckoutPath}`,
                    ].join('\n'),
                ),
            ),
        ).toThrow(/mutable local checkout/u);
        expect(() =>
            verifyPinnedReferenceMetadata(
                pinnedReference,
                goModule,
                dockerfile.replace(' && go mod verify', ''),
            ),
        ).toThrow(/go\.sum verification/u);
        expect(() =>
            assertPinnedDigest(
                'oracle command',
                'actual-digest',
                'expected-digest',
            ),
        ).toThrow(/actual actual-digest, expected expected-digest/u);
    });
});
