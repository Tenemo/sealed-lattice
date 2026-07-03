import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    acceptedSetupCheckpointSourcePaths,
    authoritativeCommandLanesForLane,
    automaticTestThreadKnobForLane,
    automaticTrusteeProofBatchKnobForLane,
    cargoTestArgumentsForFocusedFilter,
    cargoTestArgumentsForLane,
    finalPackageCheckpointStoreIsWarmForInputs,
    heavyAcceptedSetupFinalPackageTestPattern,
    heavyAcceptedSetupTestPattern,
    newestModificationTimeMillisecondsUnder,
    normalizeFocusedTestFilter,
    parseRustKernelAcceptedSetupArguments,
} from '#tools/ci/run-rust-kernel-accepted-setup-tests';

describe('Rust accepted setup runner arguments', () => {
    it('runs the full accepted setup lane by default', () => {
        expect(parseRustKernelAcceptedSetupArguments([])).toEqual({
            focused: false,
            lane: 'all',
            mode: 'accelerated',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('accepts an explicit CI prove-fresh mode', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--ci'])).toEqual({
            focused: false,
            lane: 'all',
            mode: 'ci',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('accepts the split package-script lanes through an explicit lane argument', () => {
        expect(
            parseRustKernelAcceptedSetupArguments(['--lane', 'fast']),
        ).toEqual({
            focused: false,
            lane: 'fast',
            mode: 'accelerated',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
        expect(
            parseRustKernelAcceptedSetupArguments([
                '--lane=final-package',
                '--ci',
            ]),
        ).toEqual({
            focused: false,
            lane: 'final-package',
            mode: 'ci',
            testFilters: [heavyAcceptedSetupFinalPackageTestPattern],
        });
    });

    it('expands the full authoritative lane into the two split lanes', () => {
        expect(authoritativeCommandLanesForLane('all')).toEqual([
            'fast',
            'final-package',
        ]);
        expect(authoritativeCommandLanesForLane('fast')).toEqual(['fast']);
        expect(authoritativeCommandLanesForLane('final-package')).toEqual([
            'final-package',
        ]);
    });

    it('caps final package libtest concurrency without slowing the fast lane', () => {
        expect(automaticTestThreadKnobForLane('fast', 3)).toEqual({
            source: 'memory-bounded',
            value: '3',
        });
        expect(automaticTestThreadKnobForLane('final-package', 3)).toEqual({
            source: 'final-package fixture cap',
            value: '1',
        });
        expect(automaticTestThreadKnobForLane('final-package', 1)).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
        expect(
            automaticTestThreadKnobForLane('final-package', 3, 'accelerated'),
        ).toEqual({
            source: 'memory-bounded',
            value: '3',
        });
    });

    it('caps final package prover concurrency without slowing the fast lane', () => {
        expect(automaticTrusteeProofBatchKnobForLane('fast', 5)).toEqual({
            source: 'memory-bounded',
            value: '5',
        });
        expect(
            automaticTrusteeProofBatchKnobForLane('final-package', 5),
        ).toEqual({
            source: 'final-package prover cap',
            value: '1',
        });
        expect(
            automaticTrusteeProofBatchKnobForLane('final-package', 1),
        ).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
        expect(
            automaticTrusteeProofBatchKnobForLane(
                'final-package',
                5,
                'accelerated',
            ),
        ).toEqual({
            source: 'local final-package workstation cap',
            value: '3',
        });
    });

    it('requires a current completion manifest before final package checkpoints are warm', () => {
        const completionManifestProofFamilyCounts = new Map([
            ['same-secret-anchor-proof-material', 4],
            ['public-key-share-proof-material', 9],
            ['trustee-evaluation-key-anchor-proof-material', 6],
            ['trustee-evaluation-key-proof-material', 10],
        ]);
        const completeCurrentProofFamilyCounts = new Map([
            ['same-secret-anchor-proof-material', 4],
            ['public-key-share-proof-material', 9],
            ['trustee-evaluation-key-anchor-proof-material', 6],
            ['trustee-evaluation-key-proof-material', 10],
        ]);

        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: undefined,
                completionManifestProofFamilyCounts: undefined,
                proofFamilyCounts: completeCurrentProofFamilyCounts,
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(false);
        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: 90,
                completionManifestProofFamilyCounts,
                proofFamilyCounts: completeCurrentProofFamilyCounts,
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(false);
        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: 100,
                completionManifestProofFamilyCounts,
                proofFamilyCounts: new Map([
                    ['same-secret-anchor-proof-material', 4],
                    ['public-key-share-proof-material', 8],
                    ['trustee-evaluation-key-anchor-proof-material', 6],
                    ['trustee-evaluation-key-proof-material', 10],
                ]),
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(false);
        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: 100,
                completionManifestProofFamilyCounts: new Map([
                    ['same-secret-anchor-proof-material', 4],
                    ['public-key-share-proof-material', 0],
                    ['trustee-evaluation-key-anchor-proof-material', 6],
                    ['trustee-evaluation-key-proof-material', 10],
                ]),
                proofFamilyCounts: completeCurrentProofFamilyCounts,
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(false);
        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: 110,
                completionManifestProofFamilyCounts,
                proofFamilyCounts: completeCurrentProofFamilyCounts,
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(true);
    });

    it('keeps final package checkpoints cold until the transported trustee proof store is complete', () => {
        const completionManifestProofFamilyCounts = new Map([
            ['same-secret-anchor-proof-material', 4],
            ['public-key-share-proof-material', 9],
            ['trustee-evaluation-key-anchor-proof-material', 6],
            ['trustee-evaluation-key-proof-material', 10],
        ]);

        expect(
            finalPackageCheckpointStoreIsWarmForInputs({
                completionManifestModifiedAtMilliseconds: 110,
                completionManifestProofFamilyCounts,
                proofFamilyCounts: new Map([
                    ['same-secret-anchor-proof-material', 4],
                    ['public-key-share-proof-material', 9],
                    ['trustee-evaluation-key-anchor-proof-material', 6],
                    ['trustee-evaluation-key-proof-material', 9],
                ]),
                sourceNewestModificationTimeMilliseconds: 100,
            }),
        ).toBe(false);
    });

    it('tracks the full kernel source tree for final package checkpoint staleness', () => {
        expect(acceptedSetupCheckpointSourcePaths()).toContain(
            path.resolve(
                process.cwd(),
                'crates',
                'sealed-lattice-kernel',
                'src',
            ),
        );
    });

    it('ignores files that disappear during source modification-time scanning', () => {
        const rootPath = path.resolve('kernel-source');
        const childPath = path.join(rootPath, 'child.rs');
        const deletedPath = path.join(rootPath, 'deleted.rs');

        const directoryEntry = (
            name: string,
            type: 'directory' | 'file',
        ): {
            readonly isDirectory: () => boolean;
            readonly isFile: () => boolean;
            readonly name: string;
        } => ({
            isDirectory: () => type === 'directory',
            isFile: () => type === 'file',
            name,
        });

        expect(
            newestModificationTimeMillisecondsUnder(rootPath, {
                readDirectory: () => [
                    directoryEntry('child.rs', 'file'),
                    directoryEntry('deleted.rs', 'file'),
                ],
                statPath: (filePath) => {
                    if (filePath === deletedPath) {
                        throw new Error('file disappeared');
                    }

                    return {
                        isDirectory: () => filePath === rootPath,
                        isFile: () => filePath === childPath,
                        mtimeMs: filePath === childPath ? 250 : 100,
                    };
                },
            }),
        ).toBe(250);
    });

    it('treats one positional filter as a focused local run', () => {
        expect(parseRustKernelAcceptedSetupArguments(['one_test'])).toEqual({
            focused: true,
            lane: 'all',
            mode: 'accelerated',
            testFilters: ['one_test'],
        });
    });

    it('normalizes Rust file paths into focused module filters', () => {
        expect(
            normalizeFocusedTestFilter('evaluation_key_share_proofs.rs'),
        ).toBe('evaluation_key_share_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/evaluation_key_share_proofs.rs',
            ),
        ).toBe('evaluation_key_share_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates\\sealed-lattice-kernel\\src\\bgv\\setup\\tests\\accepted_setup\\evaluation_key_share_proofs.rs',
            ),
        ).toBe('evaluation_key_share_proofs');
    });

    it('ignores the package-manager argument separator', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--'])).toEqual({
            focused: false,
            lane: 'all',
            mode: 'accelerated',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('rejects ambiguous or unsupported arguments', () => {
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['one_test', 'another_test']),
        ).toThrow('Focused accepted-setup runs accept one test or file filter');
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['--unsupported']),
        ).toThrow('Unknown argument: --unsupported');
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['--lane', 'unsupported']),
        ).toThrow('Invalid accepted-setup lane');
    });

    it('skips final package tests only in the fast lane', () => {
        expect(cargoTestArgumentsForLane('fast', '4')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupTestPattern,
            '--',
            '--ignored',
            '--nocapture',
            '--skip',
            heavyAcceptedSetupFinalPackageTestPattern,
            '--test-threads',
            '4',
        ]);
        expect(cargoTestArgumentsForLane('final-package', '2')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupFinalPackageTestPattern,
            '--',
            '--ignored',
            '--nocapture',
            '--test-threads',
            '2',
        ]);
    });

    it('builds focused cargo arguments from one normalized filter', () => {
        expect(
            cargoTestArgumentsForFocusedFilter(
                'evaluation_key_share_proofs',
                '3',
            ),
        ).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            'evaluation_key_share_proofs',
            '--',
            '--ignored',
            '--show-output',
            '--test-threads',
            '3',
        ]);
    });
});
