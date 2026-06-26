import { deriveProtocolHash } from '@sealed-lattice/crypto';

import { setupProfileId, targetDecryptionProfileId } from './constants.js';
import {
    acceptedCertificateTemplate,
    keySwitchComponentPolynomialCount,
    moduliBitLengthSum,
    modulusProductDecimal,
} from './field-helpers.js';
import {
    galoisScheduleEntries,
    relinearizationScheduleEntries,
} from './profile-derivations.js';
import type {
    BgvHeSecurityCertificate,
    BgvHeSecurityCertificateBody,
    BgvRnsProfileForCertificates,
    CollectiveBgvSetupProfileForCertificates,
} from './types.js';

function heLatticeEstimatorRows(
    largestExposedModulusBits: number,
    extendedUtilityCeilLog2Product: number,
): Record<string, unknown> {
    return {
        targetClassicalSecurityBits: 128,
        currentQDataCenteredBinomialEta2: {
            modulusCeilLog2: largestExposedModulusBits,
            modulusLog2: '798.9999986033129',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            weakestAttack: 'bdd',
            weakestAttackCostLog2: '139.4001063588318',
            marginTo128Bits: '11.400106358831806',
            attackRows: {
                bdd: {
                    beta: 366,
                    d: 63_227,
                    eta: 384,
                    redLog2: '139.39921967040428',
                    ropLog2: '139.4001063588318',
                    svpLog2: '128.73161153136738',
                },
                dual: {
                    beta: 366,
                    d: 65_530,
                    m: 32_762,
                    memLog2: '90.37705181996229',
                    ropLog2: '140.47325808846173',
                },
                dualHybrid: {
                    NLog2: '80.18959703594362',
                    beta: 365,
                    betaPrime: 393,
                    guessLog2: '117.74355809224927',
                    m: 32_768,
                    p: 3,
                    redLog2: '140.18579512701064',
                    ropLog2: '140.1857953801665',
                    t: 50,
                    zeta: 10,
                },
                usvp: {
                    beta: 366,
                    d: 63_501,
                    redLog2: '139.40549445792695',
                    ropLog2: '139.40549445792695',
                },
            },
        },
        currentQDataCenteredBinomialEta2Adps16QuantumSieveContext: {
            modulusCeilLog2: largestExposedModulusBits,
            modulusLog2: '798.9999986033129',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            costModel: 'ADPS16(mode=quantum)',
            rowScope:
                'quantum-leaning context only; setup/evaluator closure remains the currentQDataCenteredBinomialEta2 RC.MATZOV classical row',
            weakestAttack: 'usvp',
            weakestAttackCostLog2: '96.99000000000001',
            marginToConventional128Bits: '-31.00999999999999',
            attackRows: {
                bdd: {
                    beta: 366,
                    d: 65_430,
                    eta: 300,
                    redLog2: '96.99000000000001',
                    ropLog2: '96.99000941740931',
                    svpLog2: '79.765',
                },
                dual: {
                    beta: 366,
                    d: 65_530,
                    m: 32_762,
                    memLog2: '84.46069989939393',
                    ropLog2: '96.99000000001034',
                },
                dualHybrid: {
                    NLog2: '48.16476026937466',
                    beta: 366,
                    betaPrime: 366,
                    guessLog2: '58.94118627285865',
                    m: 32_768,
                    p: 4,
                    redLog2: '96.99000000000001',
                    ropLog2: '96.99000000000508',
                    t: 20,
                    zeta: 0,
                },
                usvp: {
                    beta: 366,
                    d: 63_501,
                    redLog2: '96.99000000000001',
                    ropLog2: '96.99000000000001',
                },
            },
        },
        qExtendedIfExposedCenteredBinomialEta2: {
            modulusCeilLog2: extendedUtilityCeilLog2Product,
            modulusLog2: '845.9999984306585',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            weakestAttack: 'bdd',
            weakestAttackCostLog2: '131.11460628721997',
            marginTo128Bits: '3.1146062872199707',
            attackRows: {
                bdd: {
                    beta: 336,
                    d: 64_462,
                    eta: 363,
                    redLog2: '131.10972612858453',
                    ropLog2: '131.11460628721997',
                    svpLog2: '122.9045442832175',
                },
                dual: {
                    beta: 337,
                    d: 65_564,
                    m: 32_796,
                    memLog2: '84.67213625284322',
                    ropLog2: '132.45608835425',
                },
                dualHybrid: {
                    NLog2: '60.30328853382016',
                    beta: 336,
                    betaPrime: 366,
                    guessLog2: '113.5119952129881',
                    m: 32_768,
                    p: 3,
                    redLog2: '132.16825194866956',
                    ropLog2: '132.16825544072498',
                    t: 60,
                    zeta: 0,
                },
                usvp: {
                    beta: 337,
                    d: 62_812,
                    redLog2: '131.34923816206893',
                    ropLog2: '131.34923816206893',
                },
            },
        },
        boundaryTwoPower868CenteredBinomialEta2: {
            modulusCeilLog2: 868,
            modulusLog2: '868',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            weakestAttack: 'bdd',
            weakestAttackCostLog2: '127.7592570356635',
            marginTo128Bits: '-0.24074296433650488',
            attackRows: {
                bdd: {
                    beta: 324,
                    d: 63_226,
                    eta: 347,
                    redLog2: '127.75695346642212',
                    ropLog2: '127.7592570356635',
                    svpLog2: '118.46742571024016',
                },
                dual: {
                    beta: 324,
                    d: 65_537,
                    m: 32_769,
                    memLog2: '82.13417521526284',
                    ropLog2: '128.87901754413153',
                },
                dualHybrid: {
                    NLog2: '72.61043145128764',
                    beta: 324,
                    betaPrime: 355,
                    guessLog2: '108.42320411937244',
                    m: 32_768,
                    p: 2,
                    redLog2: '128.87816375885674',
                    ropLog2: '128.87816476258922',
                    t: 70,
                    zeta: 10,
                },
                usvp: {
                    beta: 324,
                    d: 63_577,
                    redLog2: '127.76498148379801',
                    ropLog2: '127.76498148379801',
                },
            },
        },
        boundaryTwoPower881CenteredBinomialEta2: {
            modulusCeilLog2: 881,
            modulusLog2: '881',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            weakestAttack: 'bdd',
            weakestAttackCostLog2: '125.81720263568408',
            marginTo128Bits: '-2.182797364315917',
            attackRows: {
                bdd: {
                    beta: 317,
                    d: 63_100,
                    eta: 339,
                    redLog2: '125.81529996026482',
                    ropLog2: '125.81720263568408',
                    svpLog2: '116.2497302156383',
                },
                dual: {
                    beta: 317,
                    d: 65_544,
                    m: 32_776,
                    memLog2: '80.65294349588433',
                    ropLog2: '126.87161921853478',
                },
                dualHybrid: {
                    NLog2: '70.99118991845761',
                    beta: 317,
                    betaPrime: 348,
                    guessLog2: '108.3971451508635',
                    m: 32_768,
                    p: 2,
                    redLog2: '126.87064652111765',
                    ropLog2: '126.8706504847732',
                    t: 70,
                    zeta: 10,
                },
                usvp: {
                    beta: 317,
                    d: 63_413,
                    redLog2: '125.8224745402732',
                    ropLog2: '125.8224745402732',
                },
            },
        },
        bcc25ReferenceTwoPower868Gaussian319: {
            modulusCeilLog2: 868,
            modulusLog2: '868',
            secretDistribution: 'ND.Ternary',
            errorDistribution: 'ND.DiscreteGaussian(3.19)',
            sampleModel: 'm=+Infinity',
            weakestAttack: 'bdd',
            weakestAttackCostLog2: '128.03348894742626',
            marginTo128Bits: '0.03348894742626385',
            attackRows: {
                bdd: {
                    beta: 325,
                    d: 63_105,
                    eta: 348,
                    redLog2: '128.03118054543432',
                    ropLog2: '128.03348894742626',
                    svpLog2: '118.74467872376368',
                },
                dual: {
                    beta: 325,
                    d: 65_542,
                    m: 32_774,
                    memLog2: '82.34573343101653',
                    ropLog2: '129.16612496596844',
                },
                dualHybrid: {
                    NLog2: '71.73765769917073',
                    beta: 325,
                    betaPrime: 356,
                    guessLog2: '108.4057194955841',
                    m: 32_768,
                    p: 2,
                    redLog2: '129.16522477458807',
                    ropLog2: '129.16522558730748',
                    t: 70,
                    zeta: 10,
                },
                usvp: {
                    beta: 325,
                    d: 63_434,
                    redLog2: '128.038721279717',
                    ropLog2: '128.038721279717',
                },
            },
        },
    };
}

const bgvHeSecurityCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificateBody => {
    const dataPrimes = bgvProfile.profile.dataPrimes;
    const dataPrimeProductDecimal = modulusProductDecimal(dataPrimes);
    const largestExposedModulusBits = moduliBitLengthSum(dataPrimes);
    const extendedUtilityCeilLog2Product = moduliBitLengthSum([
        ...dataPrimes,
        bgvProfile.profile.specialPrime,
    ]);
    const acceptedRelinearizationKeyPolynomials =
        keySwitchComponentPolynomialCount(
            relinearizationScheduleEntries(setupProfile),
        );
    const acceptedGaloisKeyPolynomials = keySwitchComponentPolynomialCount(
        galoisScheduleEntries(setupProfile),
    );

    return {
        objectType: 'BgvHeSecurityCertificate',
        objectVersion: 1,
        setupProfileId,
        profileId: bgvProfile.profile.profileId,
        backendProfileId: bgvProfile.profile.backendProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        qShareHash: setupProfile.qShareHash,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        evaluatorKeyScheduleProfileHash:
            setupProfile.evaluatorKeyScheduleProfileHash,
        assessedRing: {
            polynomialDegree: bgvProfile.profile.polynomialDegree,
            plaintextModulus: bgvProfile.profile.plaintextModulus,
            dataBasisId: bgvProfile.profile.dataBasisId,
            dataPrimeCount: dataPrimes.length,
            dataPrimeProductDecimal,
            dataPrimeCeilLog2Product: largestExposedModulusBits,
            qSharePrimeCount: dataPrimes.length,
            qSharePrimeProductDecimal: dataPrimeProductDecimal,
            qShareCeilLog2Product: largestExposedModulusBits,
            specialPrime: bgvProfile.profile.specialPrime,
            extendedUtilityCeilLog2Product,
            largestExposedBasisClass: 'Q_data',
            largestExposedModulusBits,
        },
        secretDistribution: {
            distributionKind: 'standard-ternary-collective-secret',
            support: [-1, 0, 1],
            isPlainDenseTernary: true,
            estimatorModel: 'HE-standard-ternary',
            source: 'recipient-verified-VSS same-secret commitments',
        },
        errorDistribution: {
            distributionKind: 'centered-binomial-eta2',
            support: [-2, -1, 0, 1, 2],
            keySwitchNoiseDistribution: 'centered-binomial-eta2',
        },
        publicSampleAccounting: {
            publicKeyCrpPolynomials: 1,
            publicKeyShareCount: setupProfile.participantCount,
            acceptedRelinearizationKeyPolynomials,
            acceptedGaloisKeyPolynomials,
            scheduledRelinearizationLevelCount:
                relinearizationScheduleEntries(setupProfile).length,
            scheduledGaloisKeyCount: galoisScheduleEntries(setupProfile).length,
        },
        publishedReferenceRows: {
            bcc25TernaryGaussian319Category128: {
                source: 'BCC25 Security Guidelines Table 5.2',
                costModel: 'RC.MATZOV',
                secretDistribution: 'uniform ternary',
                errorDistribution: 'Gaussian sigma=3.19',
                polynomialDegree: 32_768,
                targetClassicalSecurityBits: 128,
                maximumLogQ: 868,
                largestExposedModulusBits,
                tableMarginBits: Math.max(868 - largestExposedModulusBits, 0),
                rowScope:
                    'published context only; current centered-binomial-eta2 closure is the latticeEstimatorRows.currentQDataCenteredBinomialEta2 row',
            },
        },
        estimatorBinding: {
            tool: 'Lattice Estimator',
            toolVersion:
                'malb/lattice-estimator@27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5',
            estimatorRepository: 'https://github.com/malb/lattice-estimator',
            estimatorCommit: '27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5',
            estimatorDefaultCostModel: 'RC.MATZOV',
            sageRuntime: 'SageMath 10.9',
            dockerImage: 'sagemath/sagemath:latest',
            command: 'pnpm exec tsx ./tools/ci/run-he-lattice-estimator.ts',
            estimatorOutputCanonicalization:
                'recursively sorted JSON object keys, two-space indentation, trailing newline',
            estimatorOutputCanonicalSha256:
                '1ec69c0642e6fcabe486dbc8b33ce2cad00289c629cf7405d154d94aed94f399',
            securityEstimatorInputHash: bgvProfile.securityEstimatorInputHash,
            secretModel: 'ND.Ternary',
            errorModel: 'ND.CenteredBinomial(2)',
            sampleModel: 'm=+Infinity',
            largestExposedBasisClass: 'Q_data',
            largestExposedModulusBits,
            utilityExtendedBasisBits: extendedUtilityCeilLog2Product,
        },
        latticeEstimatorRows: heLatticeEstimatorRows(
            largestExposedModulusBits,
            extendedUtilityCeilLog2Product,
        ),
        targetDecryptionProfileBinding: {
            targetDecryptionProfileId,
        },
    };
};

export const createBgvHeSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificate => {
    const template = acceptedCertificateTemplate(
        setupProfile,
        'heSecurityCertificate',
        'BgvHeSecurityCertificate',
        'heSecurityCertificateHash',
        'BGVHeSecurityCertificateHash',
    );
    if (template !== null) {
        return template as BgvHeSecurityCertificate;
    }

    const certificateBody = bgvHeSecurityCertificateBody(
        setupProfile,
        bgvProfile,
    );

    return {
        ...certificateBody,
        heSecurityCertificateHash: deriveProtocolHash(
            'BGVHeSecurityCertificateHash',
            certificateBody,
        ),
    };
};
