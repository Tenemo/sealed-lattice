import { describe, expect, expectTypeOf, it } from "vitest";

import {
    artifactKinds,
    distributionKinds,
    foundationObjectTypes,
    foundationProfile,
    foundationSchemaIdentifiers,
    isParticipantIdentity,
    parseParticipantIdentity,
    refusalReasonCodes,
    refusalReasons,
    stateCapabilityKinds,
    type ParticipantIdentity,
    type ProtocolHash,
} from "@sealed-lattice/types";

describe("foundation contract", () => {
    it("parses only the canonical participant identity string form", () => {
        const canonicalIdentities = [
            "0".repeat(128),
            "f".repeat(128),
            "0123456789abcdef".repeat(8),
        ];
        for (const canonicalIdentity of canonicalIdentities) {
            const identity = parseParticipantIdentity(canonicalIdentity);
            const compatibleProtocolHash: ProtocolHash = identity;

            expect(identity).toBe(canonicalIdentity);
            expect(compatibleProtocolHash).toBe(canonicalIdentity);
            expect(isParticipantIdentity(identity)).toBe(true);
            expectTypeOf(identity).toEqualTypeOf<ParticipantIdentity>();
        }
        expectTypeOf<ProtocolHash>().not.toMatchTypeOf<ParticipantIdentity>();
    });

    it("refuses malformed and noncanonical participant identities", () => {
        const canonicalIdentity = "a".repeat(128);
        const invalidIdentities: readonly unknown[] = [
            "",
            canonicalIdentity.slice(1),
            `${canonicalIdentity}0`,
            `A${canonicalIdentity.slice(1)}`,
            `g${canonicalIdentity.slice(1)}`,
            ` ${canonicalIdentity.slice(1)}`,
            `${canonicalIdentity.slice(0, -1)}\n`,
            ` ${canonicalIdentity}`,
            `${canonicalIdentity}\n`,
            `ａ${canonicalIdentity.slice(1)}`,
            0,
            undefined,
            {},
        ];

        for (const invalidIdentity of invalidIdentities) {
            expect(isParticipantIdentity(invalidIdentity)).toBe(false);
            expect(() => parseParticipantIdentity(invalidIdentity)).toThrow(
                /128 lowercase hexadecimal/u,
            );
        }
    });

    it("keeps the refusal wire codes closed, unique, and contiguous", () => {
        const codes = refusalReasons.map(
            (refusalReason) => refusalReasonCodes[refusalReason],
        );

        expect(codes).toEqual(
            Array.from(
                { length: refusalReasons.length },
                (_, index) => index + 1,
            ),
        );
        expect(new Set(codes).size).toBe(codes.length);
        expect(refusalReasonCodes.consumedState).toBe(0x000d);
    });

    it("pins a state quorum that preserves an honest lock after the recovery loss budget", () => {
        const quorumIntersection =
            2 * foundationProfile.stateWitnessQuorum -
            (foundationProfile.participantCount - 1);
        const honestIntersectionAfterStaticFaults =
            quorumIntersection - foundationProfile.activeFaultBound;
        const stableHonestLocksAfterOneAdditionalLoss =
            honestIntersectionAfterStaticFaults - 1;

        expect(quorumIntersection).toBe(5);
        expect(honestIntersectionAfterStaticFaults).toBe(2);
        expect(stableHonestLocksAfterOneAdditionalLoss).toBeGreaterThanOrEqual(
            1,
        );
    });

    it("does not reuse a schema or object-family identifier", () => {
        const schemaIdentifiers = Object.values(foundationSchemaIdentifiers);
        const objectTypes = Object.values(foundationObjectTypes);

        expect(new Set(schemaIdentifiers).size).toBe(schemaIdentifiers.length);
        expect(new Set(objectTypes).size).toBe(objectTypes.length);
        expect(Math.max(...objectTypes)).toBeLessThan(0x0100);
        expect(Math.min(...schemaIdentifiers)).toBeGreaterThan(0);
    });

    it("pins the assigned distribution and artifact registries", () => {
        expect(distributionKinds).toEqual({
            ternary: 1,
            centeredBinomial: 2,
        });
        expect(artifactKinds).toEqual({
            encoderAndBallotLayout: 1,
            verifiableSecretSharingProfile: 2,
            latticeCommitmentProfile: 3,
            proofProfileSet: 4,
            evaluatorProgramSet: 5,
            targetDecryptionProfile: 6,
        });
        expect(stateCapabilityKinds).toEqual({
            ballotCandidateList: 1,
            finalitySignature: 2,
            targetRelease: 3,
        });
    });

    it("freezes every runtime registry and profile", () => {
        for (const registry of [
            refusalReasons,
            refusalReasonCodes,
            foundationProfile,
            foundationSchemaIdentifiers,
            foundationObjectTypes,
            distributionKinds,
            artifactKinds,
            stateCapabilityKinds,
        ]) {
            expect(Object.isFrozen(registry)).toBe(true);
            expect(Reflect.set(registry, "unexpected", 1)).toBe(false);
        }
    });
});
