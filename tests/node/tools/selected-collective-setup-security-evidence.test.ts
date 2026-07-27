import { readFile } from 'node:fs/promises';

import { beforeAll, describe, expect, it } from 'vitest';

import {
    buildSelectedCollectiveSetupSecurityEvidence,
    canonicalJsonSha256,
    parseJsonValue,
    requireSelectedCollectiveSetupSecurityClosure,
    selectedCollectiveSetupSecurityEvidencePath,
    validateSelectedCollectiveSetupSecurityEvidence,
    type JsonValue,
} from '#tools/ci/selected-collective-setup-security-evidence';

const requireRecord = (value: unknown): Record<string, unknown> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('Expected an object in the test record.');
    }
    return value as Record<string, unknown>;
};

const requireArray = (value: unknown): unknown[] => {
    if (!Array.isArray(value)) {
        throw new Error('Expected an array in the test record.');
    }
    return value;
};

const hostileRecord = (
    evidence: JsonValue,
    mutate: (record: Record<string, unknown>) => void,
): JsonValue => {
    const record = structuredClone(evidence) as Record<string, unknown>;
    mutate(record);
    delete record.recordSha256;
    record.recordSha256 = canonicalJsonSha256(record as JsonValue);
    return record as JsonValue;
};

describe('Selected collective-setup security evidence', () => {
    let checkedEvidence: JsonValue;
    let expectedEvidence: JsonValue;

    beforeAll(async () => {
        checkedEvidence = parseJsonValue(
            await readFile(selectedCollectiveSetupSecurityEvidencePath, 'utf8'),
        );
        const productionAuthority = requireRecord(checkedEvidence)
            .productionAuthority as JsonValue;
        expectedEvidence =
            await buildSelectedCollectiveSetupSecurityEvidence(
                productionAuthority,
            );
    });

    it('binds the exact production roster, corruption subsets, proof inventory, samples, and witness joins', () => {
        const summary = validateSelectedCollectiveSetupSecurityEvidence(
            checkedEvidence,
            expectedEvidence,
        );
        expect(summary).toEqual({
            assumptionLeafCount: 6,
            corruptionSubsetCount: 176,
            logicalRelationInstanceCount: 129,
            physicalProofApplicationCount: 73,
            readyForClosure: false,
            unresolvedNonAssumptionLeaves: [
                'commonConstructionKnowledgeSoundness',
                'commonConstructionQromTransform',
                'commonConstructionMaskingCorrespondence',
                'setupFamilySimulationComposition',
                'collectiveSetupHybridComposition',
            ],
        });

        const record = requireRecord(checkedEvidence);
        const authority = requireRecord(record.productionAuthority);
        expect(authority.profile).toEqual({
            participantCount: 10,
            activeFaultBound: 3,
            reconstructionThreshold: 4,
            finalityQuorum: 7,
            stateWitnessQuorum: 7,
            optionCount: 20,
            polynomialDegree: 32_768,
            plaintextModulus: 257,
        });
        expect(authority.proofInventoryTotals).toEqual({
            physicalProofApplicationCount: 73,
            logicalRelationInstanceCount: 129,
        });
        expect(
            requireArray(authority.corruptionClasses).flatMap((value) =>
                requireArray(requireRecord(value).corruptionSubsets),
            ),
        ).toHaveLength(176);
        expect(
            requireArray(authority.relationPlanBindings).flatMap((value) =>
                requireArray(requireRecord(value).variants),
            ),
        ).toHaveLength(29);
        expect(requireArray(record.witnessJoins)).toHaveLength(5);
        expect(
            requireRecord(record.jointSetupSampleHybridReduction).status,
        ).toBe('resolved');
        expect(
            requireRecord(record.selectedSetupCorrectnessImport).status,
        ).toBe('resolved');
        expect(requireArray(record.constructionEvidenceImports)).toHaveLength(
            3,
        );
    });

    it('keeps the security review fail-closed without minting protocol authority', () => {
        expect(() =>
            requireSelectedCollectiveSetupSecurityClosure(
                checkedEvidence,
                expectedEvidence,
            ),
        ).toThrow(
            'Collective-setup security closure is blocked by: commonConstructionKnowledgeSoundness',
        );
        const closure = requireRecord(requireRecord(checkedEvidence).closure);
        expect(closure).toMatchObject({
            status: 'blocked',
            authorizationEffect: 'none',
            capabilityMintingEffect: 'none',
        });
        expect(JSON.stringify(checkedEvidence)).not.toContain('VerifiedSetup');
    });

    it('refuses stale source and production relation-plan hashes', () => {
        const staleSource = hostileRecord(checkedEvidence, (record) => {
            const sourceAuthority = requireArray(record.sourceAuthority);
            requireRecord(sourceAuthority[0]).sha256 = '00'.repeat(32);
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                staleSource,
                expectedEvidence,
            ),
        ).toThrow('The collective-setup source authority is stale.');

        const wrongPlanHash = hostileRecord(checkedEvidence, (record) => {
            const authority = requireRecord(record.productionAuthority);
            const bindings = requireArray(authority.relationPlanBindings);
            requireRecord(bindings[0]).canonicalPlanHash = '00'.repeat(64);
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongPlanHash,
                expectedEvidence,
            ),
        ).toThrow('The production-derived authority snapshot is stale.');

        const wrongVariantHash = hostileRecord(checkedEvidence, (record) => {
            const authority = requireRecord(record.productionAuthority);
            const bindings = requireArray(authority.relationPlanBindings);
            const variants = requireArray(requireRecord(bindings[0]).variants);
            requireRecord(variants[0]).canonicalVariantHash = 'ff'.repeat(64);
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongVariantHash,
                expectedEvidence,
            ),
        ).toThrow('The production-derived authority snapshot is stale.');
    });

    it('refuses missing or cyclic reductions and unresolved leaves relabeled as complete', () => {
        const missingReduction = hostileRecord(checkedEvidence, (record) => {
            requireArray(record.reductionDag).pop();
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingReduction,
                expectedEvidence,
            ),
        ).toThrow('Reduction DAG node catalog is incomplete');

        const cyclicReduction = hostileRecord(checkedEvidence, (record) => {
            const nodes = requireArray(record.reductionDag);
            requireRecord(nodes[0]).dependencies = [
                'collectiveSetupHybridComposition',
            ];
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                cyclicReduction,
                expectedEvidence,
            ),
        ).toThrow('reordered, or cyclic dependency');

        const overstatedReduction = hostileRecord(checkedEvidence, (record) => {
            const nodes = requireArray(record.reductionDag);
            const commonProofNode = nodes
                .map((value) => requireRecord(value))
                .find(
                    (node) =>
                        node.identifier ===
                        'commonConstructionKnowledgeSoundness',
                );
            if (commonProofNode === undefined) {
                throw new Error('Expected common-proof obligation.');
            }
            commonProofNode.status = 'resolved';
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                overstatedReduction,
                expectedEvidence,
            ),
        ).toThrow('unresolved non-assumption reduction catalog');

        const overstatedConstructionImport = hostileRecord(
            checkedEvidence,
            (record) => {
                const imports = requireArray(
                    record.constructionEvidenceImports,
                );
                requireRecord(imports[0]).observedStatus = 'resolved';
                requireRecord(imports[0]).checkedArtifactDigest = '00'.repeat(
                    64,
                );
            },
        );
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                overstatedConstructionImport,
                expectedEvidence,
            ),
        ).toThrow('common-construction evidence import is stale or overstated');
    });

    it('refuses numeric estimator costs disguised as reduction advantages', () => {
        const numericAdvantage = hostileRecord(checkedEvidence, (record) => {
            const nodes = requireArray(record.reductionDag);
            requireRecord(nodes[0]).advantageExpression =
                'two_to_the_minus_123_bits';
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                numericAdvantage,
                expectedEvidence,
            ),
        ).toThrow(
            'Numeric estimator bit costs may not be used as reduction advantages.',
        );

        const numericLedger = hostileRecord(checkedEvidence, (record) => {
            const ledgers = requireArray(record.residualLedgers);
            const rows = requireArray(requireRecord(ledgers[0]).rows);
            requireRecord(rows[0]).symbolicTerm = 'securityBits123';
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                numericLedger,
                expectedEvidence,
            ),
        ).toThrow(
            'Numeric estimator bit costs may not appear in a residual ledger.',
        );

        const numericHybrid = hostileRecord(checkedEvidence, (record) => {
            const hybridGames = requireArray(record.hybridGames);
            requireRecord(hybridGames[1]).transitionAdvantage =
                'estimator_security_bits_123';
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                numericHybrid,
                expectedEvidence,
            ),
        ).toThrow(
            'Numeric estimator bit costs may not be used as hybrid advantages.',
        );
    });

    it('refuses missing corruption, abort, resume, witness, sample, basis, and multiplicity coverage', () => {
        const missingCorruption = hostileRecord(checkedEvidence, (record) => {
            const game = requireRecord(record.game);
            const corruptionModel = requireRecord(game.corruptionModel);
            const classes = requireArray(
                corruptionModel.exactSubsetsByCorruptionCount,
            );
            requireArray(requireRecord(classes[3]).subsets).pop();
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingCorruption,
                expectedEvidence,
            ),
        ).toThrow('omits or alters a static corruption case');

        const missingAbort = hostileRecord(checkedEvidence, (record) => {
            const schedule = requireRecord(record.protocolSchedule);
            requireArray(schedule.abortCases).pop();
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingAbort,
                expectedEvidence,
            ),
        ).toThrow('Abort-case catalog is incomplete');

        const missingResumeBinding = hostileRecord(
            checkedEvidence,
            (record) => {
                const schedule = requireRecord(record.protocolSchedule);
                requireArray(schedule.resumeBindings).pop();
            },
        );
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingResumeBinding,
                expectedEvidence,
            ),
        ).toThrow('authenticated-resume binding catalog is incomplete');

        const missingHybrid = hostileRecord(checkedEvidence, (record) => {
            requireArray(record.hybridGames).pop();
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingHybrid,
                expectedEvidence,
            ),
        ).toThrow('Hybrid-game catalog is incomplete');

        const unmatchedHybridReduction = hostileRecord(
            checkedEvidence,
            (record) => {
                const hybridGames = requireArray(record.hybridGames);
                requireRecord(hybridGames[1]).transitionReduction =
                    'missingReduction';
            },
        );
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                unmatchedHybridReduction,
                expectedEvidence,
            ),
        ).toThrow('hybrid-game transition references a missing reduction');

        const missingWitnessJoin = hostileRecord(checkedEvidence, (record) => {
            requireArray(record.witnessJoins).pop();
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingWitnessJoin,
                expectedEvidence,
            ),
        ).toThrow('Witness-join catalog is incomplete');

        const missingSampleCorrelation = hostileRecord(
            checkedEvidence,
            (record) => {
                const sampleRelations = requireRecord(record.sampleRelations);
                requireArray(sampleRelations.correlations).pop();
            },
        );
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                missingSampleCorrelation,
                expectedEvidence,
            ),
        ).toThrow('Sample-correlation catalog is incomplete');

        const wrongBasis = hostileRecord(checkedEvidence, (record) => {
            const sampleRelations = requireRecord(record.sampleRelations);
            const bases = requireArray(sampleRelations.orderedBases);
            requireRecord(bases[1]).specialPrimeCount = 2;
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongBasis,
                expectedEvidence,
            ),
        ).toThrow('security evidence is stale or altered');

        const wrongMultiplicity = hostileRecord(checkedEvidence, (record) => {
            const inventory = requireArray(record.proofInventory);
            requireRecord(inventory[8]).logicalRelationInstanceCount = 59;
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongMultiplicity,
                expectedEvidence,
            ),
        ).toThrow('security proof multiplicities are stale or altered');

        const splitJointHybrid = hostileRecord(checkedEvidence, (record) => {
            const reduction = requireRecord(
                record.jointSetupSampleHybridReduction,
            );
            const groups = requireArray(reduction.replacementGroups);
            requireRecord(groups[1]).sourceRelationCount = 239;
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                splitJointHybrid,
                expectedEvidence,
            ),
        ).toThrow('joint setup-sample hybrid reduction is stale or incomplete');
    });

    it('refuses malformed production samples, commitments, and record framing', () => {
        const wrongSampleCount = hostileRecord(checkedEvidence, (record) => {
            const authority = requireRecord(record.productionAuthority);
            const sampleCensus = requireRecord(authority.sampleCensus);
            const summary = requireRecord(sampleCensus.summary);
            summary.completePublicRelationCount = 672;
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongSampleCount,
                expectedEvidence,
            ),
        ).toThrow('public-sample census is stale or altered');

        const wrongAnchorIndices = hostileRecord(checkedEvidence, (record) => {
            const authority = requireRecord(record.productionAuthority);
            const topology = requireRecord(authority.witnessCommitmentTopology);
            topology.anchorCommitmentDataPrimeIndices = [0, 1, 3];
        });
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongAnchorIndices,
                expectedEvidence,
            ),
        ).toThrow('witness commitment topology is stale');

        const wrongCorrectnessMargin = hostileRecord(
            checkedEvidence,
            (record) => {
                const authority = requireRecord(record.productionAuthority);
                const correctness = requireRecord(authority.setupCorrectness);
                const margins = requireArray(
                    correctness.collectivePublicKeyMinimumCenteredMargins,
                );
                margins[0] = 0;
            },
        );
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongCorrectnessMargin,
                expectedEvidence,
            ),
        ).toThrow('setup correctness authority is stale or incomplete');

        const wrongDigest = structuredClone(checkedEvidence) as Record<
            string,
            unknown
        >;
        wrongDigest.recordSha256 = '00'.repeat(32);
        expect(() =>
            validateSelectedCollectiveSetupSecurityEvidence(
                wrongDigest as JsonValue,
                expectedEvidence,
            ),
        ).toThrow('evidence digest does not match');
    });
});
