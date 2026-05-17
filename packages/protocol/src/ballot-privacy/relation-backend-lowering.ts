import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { ProtocolDigest, RefusalRecord } from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle/field.js';

import {
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyScoreBucketCount,
    getBallotPrivacyEncodedShareVectorWidth,
    getBallotPrivacyScalarCoordinateIndex,
    getBallotPrivacyScoreBucketCoordinateIndex,
} from './encoded-share-layout.js';
import {
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
} from './lattice-primitives.js';
import {
    compileBallotPrivacyRelation,
    type BallotPrivacyRelationCompilerInput,
} from './relation-compiler.js';

const relationStatementFormat =
    'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1';
const relationStatementDigestPurpose =
    'ballot-privacy-linear-relation-statement-v1';
const backendStatementFormat = 'SparseSignedIntegerBackendStatement-v1';
const backendStatementDigestPurpose = 'ballot-privacy-backend-statement-v1';
const explicitBackendMatrixDigestPurpose =
    'ballot-privacy-backend-explicit-matrix-v1';
const explicitBackendTargetVectorDigestPurpose =
    'ballot-privacy-backend-explicit-target-vector-v1';
const digestExpandedBackendMatrixDigestPurpose =
    'ballot-privacy-backend-digest-expanded-matrix-v1';
const digestExpandedBackendTargetVectorDigestPurpose =
    'ballot-privacy-backend-digest-expanded-target-vector-v1';
const backendMatrixDigestPurpose = 'ballot-privacy-backend-matrix-v1';
const backendTargetVectorDigestPurpose =
    'ballot-privacy-backend-target-vector-v1';
const backendBoundsDigestPurpose = 'ballot-privacy-backend-bounds-v1';
const backendProofComponentsDigestPurpose =
    'ballot-privacy-backend-proof-components-v1';
const shareCommitmentModulus = '18446744069414584321';
const shareCommitmentModuleRank = 4;
const shareCommitmentModuleDegree = 256;
const shareCommitmentOpeningDimension = 64;
const shareCommitmentOpeningInfinityNormBound = 1_024;
const receiverEncryptionModulus = 12_289;
const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionShortVectorInfinityNormBound = 2;

type ReceiverReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
};

type ReceiverPublicKeyReference = ReceiverReference & {
    readonly keyMaterialDigest?: ProtocolDigest;
    readonly publicMatrixSeedDigest?: ProtocolDigest;
    readonly receiverPublicKeyDigest: ProtocolDigest;
};

type ReceiverPayloadReference = ReceiverReference & {
    readonly ciphertextBodyDigest?: ProtocolDigest;
    readonly ciphertextChunkDigest?: ProtocolDigest;
    readonly ciphertextChunkCount?: number;
    readonly plaintextBitLength?: number;
    readonly receiverPayloadDigest: ProtocolDigest;
    readonly receiverPayloadCiphertextRoot: ProtocolDigest;
};

type ShareCommitmentReference = ReceiverReference & {
    readonly commitmentBodyDigest?: ProtocolDigest;
    readonly commitmentPolynomialVector?: readonly (readonly string[])[];
    readonly commitmentPolynomialVectorDigest?: ProtocolDigest;
    readonly shareCommitmentDigest: ProtocolDigest;
};

export type BallotPrivacyRelationBackendPublicContext = {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly actionContextDigest: ProtocolDigest;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly receiverKeyRoot: ProtocolDigest;
    readonly receiverKeyProofRoot: ProtocolDigest;
    readonly receiverPublicKeys: readonly ReceiverPublicKeyReference[];
    readonly receiverPayloads: readonly ReceiverPayloadReference[];
    readonly shareCommitments: readonly ShareCommitmentReference[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly ballotProofProfileDigest: ProtocolDigest;
    readonly scoreMembershipProfileDigest: ProtocolDigest;
    readonly ballotScoreEncodingProfileDigest: ProtocolDigest;
    readonly ballotShareLayoutProfileDigest: ProtocolDigest;
    readonly aggregateInputEncodingProfileDigest: ProtocolDigest;
    readonly encodedShareVectorLayoutDigest: ProtocolDigest;
    readonly encodedAggregateLayoutDigest: ProtocolDigest;
    readonly shareCommitmentMessageBoundCertDigest: ProtocolDigest;
};

type BallotPrivacyLinearRelationVariableRole =
    | 'ScalarScoreConstant'
    | 'ScoreBucketConstant'
    | 'ShamirCoefficient'
    | 'ReceiverShare'
    | 'ShamirQuotient'
    | 'ReceiverPayloadPlaintextShare'
    | 'ReceiverPayloadPlaintextOpening'
    | 'ShareCommitmentOpening'
    | 'ReceiverEncryptionRandomness'
    | 'ReceiverEncryptionNoise';

type BallotPrivacyLinearRelationVariable = {
    readonly variableName: string;
    readonly variableRole: BallotPrivacyLinearRelationVariableRole;
    readonly encodedCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly scoreBucketValue?: number;
    readonly coefficientDegree?: number;
    readonly openingCoordinateIndex?: number;
    readonly receiverRosterPosition?: number;
};

type BallotPrivacyLinearRelationTerm = {
    readonly coefficient: number;
    readonly variableName: string;
};

type BallotPrivacyLinearRelationRowKind =
    | 'OneHotSum'
    | 'ScalarScoreConsistency'
    | 'ShamirEvaluationQuotient'
    | 'ShareCommitmentEquation'
    | 'ReceiverPayloadSharePlaintextBinding'
    | 'ReceiverPayloadOpeningPlaintextBinding';

type BallotPrivacyLinearRelationRow = {
    readonly rowName: string;
    readonly rowKind: BallotPrivacyLinearRelationRowKind;
    readonly modulus: 65537;
    readonly terms: readonly BallotPrivacyLinearRelationTerm[];
    readonly target: number;
    readonly encodedCoordinateIndex?: number;
    readonly openingCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly receiverRosterPosition?: number;
};

type BallotPrivacyLinearRelationBoundKind =
    | 'Boolean'
    | 'CanonicalFieldElement'
    | 'SignedIntegerAbsoluteBound';

type BallotPrivacyLinearRelationBound = {
    readonly boundName: string;
    readonly boundKind: BallotPrivacyLinearRelationBoundKind;
    readonly variableNames: readonly string[];
    readonly minimum?: number;
    readonly maximum?: number;
    readonly absoluteMaximum?: number;
};

type BallotPrivacyAlgebraicRelationRowKind =
    | 'ShareCommitmentEquation'
    | 'ReceiverPayloadEncryptionEquation'
    | 'ReceiverKeyBinding';

type BallotPrivacyAlgebraicRelationRow = {
    readonly rowName: string;
    readonly rowKind: BallotPrivacyAlgebraicRelationRowKind;
    readonly modulus: number | string;
    readonly equationCount: number;
    readonly shareCommitmentPolynomialVector?: readonly (readonly string[])[];
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly targetDigest: ProtocolDigest;
    readonly publicInputDigests: Record<string, ProtocolDigest>;
    readonly variableNames: readonly string[];
};

type BallotPrivacyBackendStatementVariableColumn =
    BallotPrivacyLinearRelationVariable & {
        readonly columnIndex: number;
    };

type BallotPrivacyBackendStatementTerm = {
    readonly coefficient: string;
    readonly columnIndex: number;
    readonly variableName: string;
};

type BallotPrivacyBackendStatementExplicitRow = {
    readonly rowIndex: number;
    readonly rowKind: BallotPrivacyLinearRelationRowKind;
    readonly rowName: string;
    readonly modulus: string;
    readonly target: string;
    readonly terms: readonly BallotPrivacyBackendStatementTerm[];
};

type BallotPrivacyBackendStatementRowBatch =
    | {
          readonly batchKind: 'ExplicitSparseRows';
          readonly batchName:
              | 'encoded_score_field_rows'
              | 'share_commitment_equation_rows'
              | 'receiver_payload_plaintext_binding_rows';
          readonly matrixDigest: ProtocolDigest;
          readonly modulus: string;
          readonly rowCount: number;
          readonly rowKind:
              | 'EncodedScoreFieldRows'
              | 'ShareCommitmentEquationRows'
              | 'ReceiverPayloadPlaintextBindingRows';
          readonly rowOffset: number;
          readonly rows: readonly BallotPrivacyBackendStatementExplicitRow[];
          readonly targetVectorDigest: ProtocolDigest;
          readonly variableColumnIndices: readonly number[];
      }
    | {
          readonly batchKind: 'DigestExpandedRows';
          readonly batchName: string;
          readonly coefficientExpansionDomain: string;
          readonly matrixDigest: ProtocolDigest;
          readonly modulus: string;
          readonly publicInputDigests: Record<string, ProtocolDigest>;
          readonly receiverIdentity: string;
          readonly receiverRosterPosition: number;
          readonly rowCount: number;
          readonly rowKind: BallotPrivacyAlgebraicRelationRowKind;
          readonly rowOffset: number;
          readonly sourceAlgebraicRowName: string;
          readonly targetDigest: ProtocolDigest;
          readonly targetExpansionDomain: string;
          readonly targetVectorDigest: ProtocolDigest;
          readonly variableColumnIndices: readonly number[];
      };

type BallotPrivacyBackendStatementBound = Omit<
    BallotPrivacyLinearRelationBound,
    'absoluteMaximum' | 'maximum' | 'minimum'
> & {
    readonly absoluteMaximum?: string;
    readonly maximum?: string;
    readonly minimum?: string;
    readonly variableColumnIndices: readonly number[];
};

export type BallotPrivacyBackendProofComponentId =
    | 'score-and-shamir-field-component'
    | 'payload-plaintext-field-component'
    | 'share-commitment-component'
    | 'receiver-encryption-component'
    | 'receiver-key-binding-component';

export type BallotPrivacyBackendProofComponent = {
    readonly componentDigest: ProtocolDigest;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly coefficientModulus: string;
    readonly proofLoweringStatus:
        | 'explicitRowsAvailable'
        | 'digestExpandedRowsPending';
    readonly rowBatchNames: readonly string[];
    readonly rowCount: number;
    readonly rowKinds: readonly string[];
    readonly variableColumnCount: number;
    readonly variableColumnIndices: readonly number[];
};

export type BallotPrivacyProofBackendStatement = {
    readonly objectType: 'BallotPrivacyProofBackendStatement';
    readonly objectVersion: 1;
    readonly backendStatementDigest: ProtocolDigest;
    readonly backendStatementFormat: typeof backendStatementFormat;
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly sourceRelationStatementFormat: typeof relationStatementFormat;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly shareVectorWidth: number;
    readonly encodedCoordinateCount: number;
    readonly fieldModulus: 65537;
    readonly columnCount: number;
    readonly rowCount: number;
    readonly explicitRowCount: number;
    readonly digestExpandedRowCount: number;
    readonly variableColumns: readonly BallotPrivacyBackendStatementVariableColumn[];
    readonly rowBatches: readonly BallotPrivacyBackendStatementRowBatch[];
    readonly bounds: readonly BallotPrivacyBackendStatementBound[];
    readonly proofComponents: readonly BallotPrivacyBackendProofComponent[];
    readonly proofComponentsDigest: ProtocolDigest;
    readonly matrixDigest: ProtocolDigest;
    readonly targetVectorDigest: ProtocolDigest;
    readonly boundsDigest: ProtocolDigest;
};

export type BallotPrivacyLoweredLinearRelationStatement = {
    readonly objectType: 'BallotPrivacyLinearRelationStatement';
    readonly objectVersion: 1;
    readonly relationStatementFormat: typeof relationStatementFormat;
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly relationStatementDigest: ProtocolDigest;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly shareVectorWidth: number;
    readonly encodedCoordinateCount: number;
    readonly fieldModulus: 65537;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly variables: readonly BallotPrivacyLinearRelationVariable[];
    readonly linearRows: readonly BallotPrivacyLinearRelationRow[];
    readonly algebraicRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly backendStatement: BallotPrivacyProofBackendStatement;
};

export type BallotPrivacyRelationBackendLoweringResult =
    | {
          readonly ok: true;
          readonly statement: BallotPrivacyLoweredLinearRelationStatement;
      }
    | {
          readonly ok: false;
          readonly refusedObjects: readonly RefusalRecord[];
          readonly unresolvedReason: 'BallotPrivacyRelationInvalid';
      };

type VariableRegistry = {
    readonly add: (
        variable: BallotPrivacyLinearRelationVariable,
    ) => BallotPrivacyLinearRelationVariable;
    readonly values: () => readonly BallotPrivacyLinearRelationVariable[];
};

const createVariableRegistry = (): VariableRegistry => {
    const variablesByName = new Map<
        string,
        BallotPrivacyLinearRelationVariable
    >();

    return {
        add: (variable) => {
            const existingVariable = variablesByName.get(variable.variableName);
            if (existingVariable !== undefined) {
                return existingVariable;
            }
            variablesByName.set(variable.variableName, variable);

            return variable;
        },
        values: () => [...variablesByName.values()],
    };
};

const scalarConstantVariableName = (optionIndex: number): string =>
    `option_${optionIndex + 1}_scalar_constant`;

const scoreBucketConstantVariableName = (
    optionIndex: number,
    scoreBucketValue: number,
): string => `option_${optionIndex + 1}_score_bucket_${scoreBucketValue}`;

const shamirCoefficientVariableName = (
    encodedCoordinateIndex: number,
    coefficientDegree: number,
): string =>
    `encoded_coordinate_${encodedCoordinateIndex}_coefficient_degree_${coefficientDegree}`;

const receiverShareVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_share`;

const shamirQuotientVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_quotient`;

const shareCommitmentOpeningVariableName = (
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_share_commitment_opening_coordinate_${openingCoordinateIndex}`;

const receiverPayloadPlaintextShareVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_share`;

const receiverPayloadPlaintextOpeningVariableName = (
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}`;

const receiverEncryptionRandomnessVariableName = (
    receiverRosterPosition: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_randomness`;

const receiverEncryptionNoiseVariableName = (
    receiverRosterPosition: number,
): string => `receiver_${receiverRosterPosition}_receiver_encryption_noise`;

const addScalarConstantVariable = (
    registry: VariableRegistry,
    optionIndex: number,
): string => {
    const encodedCoordinateIndex =
        getBallotPrivacyScalarCoordinateIndex(optionIndex);

    return registry.add({
        encodedCoordinateIndex,
        optionIndex,
        variableName: scalarConstantVariableName(optionIndex),
        variableRole: 'ScalarScoreConstant',
    }).variableName;
};

const addScoreBucketConstantVariable = (
    registry: VariableRegistry,
    optionIndex: number,
    scoreBucketValue: number,
): string => {
    const encodedCoordinateIndex = getBallotPrivacyScoreBucketCoordinateIndex(
        optionIndex,
        scoreBucketValue,
    );

    return registry.add({
        encodedCoordinateIndex,
        optionIndex,
        scoreBucketValue,
        variableName: scoreBucketConstantVariableName(
            optionIndex,
            scoreBucketValue,
        ),
        variableRole: 'ScoreBucketConstant',
    }).variableName;
};

const addShamirCoefficientVariable = (
    registry: VariableRegistry,
    encodedCoordinateIndex: number,
    coefficientDegree: number,
): string =>
    registry.add({
        coefficientDegree,
        encodedCoordinateIndex,
        variableName: shamirCoefficientVariableName(
            encodedCoordinateIndex,
            coefficientDegree,
        ),
        variableRole: 'ShamirCoefficient',
    }).variableName;

const addReceiverShareVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverShareVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ReceiverShare',
    }).variableName;

const addShamirQuotientVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: shamirQuotientVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ShamirQuotient',
    }).variableName;

const addShareCommitmentOpeningVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    registry.add({
        openingCoordinateIndex,
        receiverRosterPosition,
        variableName: shareCommitmentOpeningVariableName(
            receiverRosterPosition,
            openingCoordinateIndex,
        ),
        variableRole: 'ShareCommitmentOpening',
    }).variableName;

const addReceiverPayloadPlaintextShareVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextShareVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextShare',
    }).variableName;

const addReceiverPayloadPlaintextOpeningVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    registry.add({
        openingCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextOpeningVariableName(
            receiverRosterPosition,
            openingCoordinateIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextOpening',
    }).variableName;

const addReceiverEncryptionRandomnessVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): string =>
    registry.add({
        receiverRosterPosition,
        variableName: receiverEncryptionRandomnessVariableName(
            receiverRosterPosition,
        ),
        variableRole: 'ReceiverEncryptionRandomness',
    }).variableName;

const addReceiverEncryptionNoiseVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): string =>
    registry.add({
        receiverRosterPosition,
        variableName: receiverEncryptionNoiseVariableName(
            receiverRosterPosition,
        ),
        variableRole: 'ReceiverEncryptionNoise',
    }).variableName;

const getEncodedCoordinateOptionIndex = (
    encodedCoordinateIndex: number,
): number =>
    Math.floor(
        encodedCoordinateIndex / ballotPrivacyEncodedCoordinatesPerOption,
    );

const buildMembershipRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];

    for (
        let optionIndex = 0;
        optionIndex < input.optionCount;
        optionIndex += 1
    ) {
        const scoreBucketVariableNames = Array.from(
            { length: ballotPrivacyScoreBucketCount },
            (_unusedValue, scoreBucketOffset) =>
                addScoreBucketConstantVariable(
                    registry,
                    optionIndex,
                    scoreBucketOffset + 1,
                ),
        );
        const scalarVariableName = addScalarConstantVariable(
            registry,
            optionIndex,
        );

        rows.push({
            modulus: fieldModulus,
            optionIndex,
            rowKind: 'OneHotSum',
            rowName: `option_${optionIndex + 1}_one_hot_sum`,
            target: 1,
            terms: scoreBucketVariableNames.map((variableName) => ({
                coefficient: 1,
                variableName,
            })),
        });
        rows.push({
            modulus: fieldModulus,
            optionIndex,
            rowKind: 'ScalarScoreConsistency',
            rowName: `option_${optionIndex + 1}_scalar_score_consistency`,
            target: 0,
            terms: [
                {
                    coefficient: 1,
                    variableName: scalarVariableName,
                },
                ...scoreBucketVariableNames.map(
                    (variableName, scoreBucketOffset) => ({
                        coefficient: -(scoreBucketOffset + 1),
                        variableName,
                    }),
                ),
            ],
        });
    }

    return rows;
};

const fieldPower = (
    receiverRosterPosition: number,
    coefficientDegree: number,
): number => {
    let accumulatedPower = 1;
    for (
        let multipliedDegree = 0;
        multipliedDegree < coefficientDegree;
        multipliedDegree += 1
    ) {
        accumulatedPower =
            (accumulatedPower * receiverRosterPosition) % fieldModulus;
    }

    return accumulatedPower;
};

const buildShamirRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    for (
        let receiverRosterPosition = 1;
        receiverRosterPosition <= input.rosterSize;
        receiverRosterPosition += 1
    ) {
        for (
            let encodedCoordinateIndex = 0;
            encodedCoordinateIndex < encodedCoordinateCount;
            encodedCoordinateIndex += 1
        ) {
            const optionIndex = getEncodedCoordinateOptionIndex(
                encodedCoordinateIndex,
            );
            const constantVariableName =
                encodedCoordinateIndex %
                    ballotPrivacyEncodedCoordinatesPerOption ===
                0
                    ? addScalarConstantVariable(registry, optionIndex)
                    : addScoreBucketConstantVariable(
                          registry,
                          optionIndex,
                          encodedCoordinateIndex %
                              ballotPrivacyEncodedCoordinatesPerOption,
                      );
            const coefficientTerms = Array.from(
                { length: input.pvssThreshold - 1 },
                (_unusedValue, coefficientOffset) => {
                    const coefficientDegree = coefficientOffset + 1;

                    return {
                        coefficient: fieldPower(
                            receiverRosterPosition,
                            coefficientDegree,
                        ),
                        variableName: addShamirCoefficientVariable(
                            registry,
                            encodedCoordinateIndex,
                            coefficientDegree,
                        ),
                    };
                },
            );
            const receiverShareName = addReceiverShareVariable(
                registry,
                receiverRosterPosition,
                encodedCoordinateIndex,
            );
            const quotientName = addShamirQuotientVariable(
                registry,
                receiverRosterPosition,
                encodedCoordinateIndex,
            );

            rows.push({
                encodedCoordinateIndex,
                modulus: fieldModulus,
                optionIndex,
                receiverRosterPosition,
                rowKind: 'ShamirEvaluationQuotient',
                rowName: `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_shamir_evaluation`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName: constantVariableName,
                    },
                    ...coefficientTerms,
                    {
                        coefficient: -1,
                        variableName: receiverShareName,
                    },
                    {
                        coefficient: -fieldModulus,
                        variableName: quotientName,
                    },
                ],
            });
        }
    }

    return rows;
};

const buildReceiverPayloadPlaintextBindingRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    for (const receiver of input.receivers) {
        const receiverRosterPosition = receiver.receiverRosterPosition;

        for (
            let encodedCoordinateIndex = 0;
            encodedCoordinateIndex < encodedCoordinateCount;
            encodedCoordinateIndex += 1
        ) {
            rows.push({
                encodedCoordinateIndex,
                modulus: fieldModulus,
                optionIndex: getEncodedCoordinateOptionIndex(
                    encodedCoordinateIndex,
                ),
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadSharePlaintextBinding',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_share_binding`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName: addReceiverPayloadPlaintextShareVariable(
                            registry,
                            receiverRosterPosition,
                            encodedCoordinateIndex,
                        ),
                    },
                    {
                        coefficient: -1,
                        variableName: addReceiverShareVariable(
                            registry,
                            receiverRosterPosition,
                            encodedCoordinateIndex,
                        ),
                    },
                ],
            });
        }

        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < shareCommitmentOpeningDimension;
            openingCoordinateIndex += 1
        ) {
            rows.push({
                modulus: fieldModulus,
                openingCoordinateIndex,
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadOpeningPlaintextBinding',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}_binding`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName:
                            addReceiverPayloadPlaintextOpeningVariable(
                                registry,
                                receiverRosterPosition,
                                openingCoordinateIndex,
                            ),
                    },
                    {
                        coefficient: -1,
                        variableName: addShareCommitmentOpeningVariable(
                            registry,
                            receiverRosterPosition,
                            openingCoordinateIndex,
                        ),
                    },
                ],
            });
        }
    }

    return rows;
};

const receiverReferenceKey = (receiver: ReceiverReference): string =>
    `${receiver.receiverRosterPosition}:${receiver.receiverIdentity}`;

const referencesByReceiver = <Reference extends ReceiverReference>(
    references: readonly Reference[],
): ReadonlyMap<string, Reference> =>
    new Map(
        references.map((reference) => [
            receiverReferenceKey(reference),
            reference,
        ]),
    );

const receiverShareVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateCount: number,
): readonly string[] =>
    Array.from({ length: encodedCoordinateCount }, (_unusedValue, index) =>
        addReceiverShareVariable(registry, receiverRosterPosition, index),
    );

const receiverOpeningVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): readonly string[] =>
    Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, openingCoordinateIndex) =>
            addShareCommitmentOpeningVariable(
                registry,
                receiverRosterPosition,
                openingCoordinateIndex,
            ),
    );

const receiverPayloadPlaintextShareVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateCount: number,
): readonly string[] =>
    Array.from({ length: encodedCoordinateCount }, (_unusedValue, index) =>
        addReceiverPayloadPlaintextShareVariable(
            registry,
            receiverRosterPosition,
            index,
        ),
    );

const receiverPayloadPlaintextOpeningVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): readonly string[] =>
    Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, openingCoordinateIndex) =>
            addReceiverPayloadPlaintextOpeningVariable(
                registry,
                receiverRosterPosition,
                openingCoordinateIndex,
            ),
    );

const deriveAlgebraicTargetDigest = (
    purpose: string,
    payload: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload,
        purpose,
    });

const decimalString = (value: bigint | number | string): string =>
    String(value);

const shareCommitmentBigIntModulus = BigInt(shareCommitmentModulus);

const canonicalShareCommitmentCoefficient = (value: bigint): string => {
    const reducedValue =
        ((value % shareCommitmentBigIntModulus) +
            shareCommitmentBigIntModulus) %
        shareCommitmentBigIntModulus;

    return reducedValue.toString();
};

const parseShareCommitmentPolynomialVector = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly receiverRosterPosition: number;
}): readonly (readonly bigint[])[] => {
    if (input.commitmentPolynomialVector.length !== shareCommitmentModuleRank) {
        throw new RangeError(
            `Receiver ${input.receiverRosterPosition} share commitment vector does not use the frozen module rank.`,
        );
    }

    return input.commitmentPolynomialVector.map(
        (commitmentPolynomial, vectorIndex) => {
            if (commitmentPolynomial.length !== shareCommitmentModuleDegree) {
                throw new RangeError(
                    `Receiver ${input.receiverRosterPosition} share commitment polynomial ${vectorIndex} does not use the frozen module degree.`,
                );
            }

            return commitmentPolynomial.map((coefficient, coefficientIndex) => {
                if (!/^(?:0|[1-9][0-9]*)$/u.test(coefficient)) {
                    throw new RangeError(
                        `Receiver ${input.receiverRosterPosition} share commitment coefficient ${vectorIndex}:${coefficientIndex} is not a canonical decimal integer.`,
                    );
                }
                const parsedCoefficient = BigInt(coefficient);
                if (parsedCoefficient >= shareCommitmentBigIntModulus) {
                    throw new RangeError(
                        `Receiver ${input.receiverRosterPosition} share commitment coefficient ${vectorIndex}:${coefficientIndex} is outside the commitment modulus.`,
                    );
                }

                return parsedCoefficient;
            });
        },
    );
};

const deriveBackendDigest = (
    purpose: string,
    payload: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload,
        purpose,
    });

const createVariableColumnLookup = (
    variables: readonly BallotPrivacyLinearRelationVariable[],
): ReadonlyMap<string, number> =>
    new Map(
        variables.map((variable, columnIndex) => [
            variable.variableName,
            columnIndex,
        ]),
    );

const requireColumnIndex = (
    columnLookup: ReadonlyMap<string, number>,
    variableName: string,
): number => {
    const columnIndex = columnLookup.get(variableName);
    if (columnIndex === undefined) {
        throw new RangeError(
            `Backend relation lowering is missing variable column ${variableName}.`,
        );
    }

    return columnIndex;
};

const backendVariableColumns = (
    variables: readonly BallotPrivacyLinearRelationVariable[],
): readonly BallotPrivacyBackendStatementVariableColumn[] =>
    variables.map((variable, columnIndex) => ({
        ...variable,
        columnIndex,
    }));

const backendTermsForLinearRow = (
    row: BallotPrivacyLinearRelationRow,
    columnLookup: ReadonlyMap<string, number>,
): readonly BallotPrivacyBackendStatementTerm[] =>
    row.terms.map((term) => ({
        coefficient: decimalString(term.coefficient),
        columnIndex: requireColumnIndex(columnLookup, term.variableName),
        variableName: term.variableName,
    }));

const buildExplicitSparseRowBatch = (input: {
    readonly batchName:
        | 'encoded_score_field_rows'
        | 'share_commitment_equation_rows'
        | 'receiver_payload_plaintext_binding_rows';
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowKind:
        | 'EncodedScoreFieldRows'
        | 'ShareCommitmentEquationRows'
        | 'ReceiverPayloadPlaintextBindingRows';
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyLinearRelationRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const rows = input.rows.map((row, rowIndex) => ({
        modulus: decimalString(row.modulus),
        rowIndex,
        rowKind: row.rowKind,
        rowName: row.rowName,
        target: decimalString(row.target),
        terms: backendTermsForLinearRow(row, input.columnLookup),
    }));
    const variableColumnIndices = [
        ...new Set(
            rows.flatMap((row) => row.terms.map((term) => term.columnIndex)),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);

    return {
        batchKind: 'ExplicitSparseRows',
        batchName: input.batchName,
        matrixDigest: deriveBackendDigest(explicitBackendMatrixDigestPurpose, {
            rows: rows.map(({ rowIndex, rowKind, rowName, terms }) => ({
                rowIndex,
                rowKind,
                rowName,
                terms,
            })),
        }),
        modulus: decimalString(fieldModulus),
        rowCount: rows.length,
        rowKind: input.rowKind,
        rowOffset: input.rowOffset,
        rows,
        targetVectorDigest: deriveBackendDigest(
            explicitBackendTargetVectorDigestPurpose,
            {
                targets: rows.map(({ rowIndex, rowKind, rowName, target }) => ({
                    rowIndex,
                    rowKind,
                    rowName,
                    target,
                })),
            },
        ),
        variableColumnIndices,
    };
};

const shareCommitmentMessageCoefficient = (input: {
    readonly messageMatrixPolynomial: readonly bigint[];
    readonly outputCoefficientIndex: number;
    readonly shareCoordinateIndex: number;
}): string => {
    if (input.outputCoefficientIndex >= input.shareCoordinateIndex) {
        return canonicalShareCommitmentCoefficient(
            input.messageMatrixPolynomial[
                input.outputCoefficientIndex - input.shareCoordinateIndex
            ] ?? 0n,
        );
    }

    return canonicalShareCommitmentCoefficient(
        -(
            input.messageMatrixPolynomial[
                shareCommitmentModuleDegree +
                    input.outputCoefficientIndex -
                    input.shareCoordinateIndex
            ] ?? 0n
        ),
    );
};

const shareCommitmentOpeningCoefficient = (input: {
    readonly randomnessMatrixPolynomial: readonly bigint[];
    readonly outputCoefficientIndex: number;
}): string =>
    canonicalShareCommitmentCoefficient(
        input.randomnessMatrixPolynomial[input.outputCoefficientIndex] ?? 0n,
    );

const buildShareCommitmentEquationRows = (input: {
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly shareCommitmentRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly shareVectorWidth: number;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
}): readonly BallotPrivacyBackendStatementExplicitRow[] => {
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        input.shareCommitmentProfileDigest,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        input.shareCommitmentProfileDigest,
    );
    const rows: BallotPrivacyBackendStatementExplicitRow[] = [];

    for (const shareCommitmentRow of input.shareCommitmentRows) {
        if (shareCommitmentRow.shareCommitmentPolynomialVector === undefined) {
            continue;
        }
        const commitmentPolynomialVector = parseShareCommitmentPolynomialVector(
            {
                commitmentPolynomialVector:
                    shareCommitmentRow.shareCommitmentPolynomialVector,
                receiverRosterPosition:
                    shareCommitmentRow.receiverRosterPosition,
            },
        );
        const shareVariableNames = Array.from(
            { length: input.shareVectorWidth },
            (_unusedValue, encodedCoordinateIndex) =>
                receiverShareVariableName(
                    shareCommitmentRow.receiverRosterPosition,
                    encodedCoordinateIndex,
                ),
        );
        const openingVariableNames = Array.from(
            { length: shareCommitmentOpeningDimension },
            (_unusedValue, openingCoordinateIndex) =>
                shareCommitmentOpeningVariableName(
                    shareCommitmentRow.receiverRosterPosition,
                    openingCoordinateIndex,
                ),
        );

        for (
            let commitmentVectorIndex = 0;
            commitmentVectorIndex < shareCommitmentModuleRank;
            commitmentVectorIndex += 1
        ) {
            const messageMatrixPolynomial =
                messageMatrix[commitmentVectorIndex] ?? [];
            const randomnessMatrixRow =
                randomnessMatrix[commitmentVectorIndex] ?? [];
            for (
                let commitmentCoefficientIndex = 0;
                commitmentCoefficientIndex < shareCommitmentModuleDegree;
                commitmentCoefficientIndex += 1
            ) {
                const shareTerms = shareVariableNames.map(
                    (variableName, shareCoordinateIndex) => ({
                        coefficient: shareCommitmentMessageCoefficient({
                            messageMatrixPolynomial,
                            outputCoefficientIndex: commitmentCoefficientIndex,
                            shareCoordinateIndex,
                        }),
                        columnIndex: requireColumnIndex(
                            input.columnLookup,
                            variableName,
                        ),
                        variableName,
                    }),
                );
                const openingTerms = openingVariableNames.map(
                    (variableName, openingCoordinateIndex) => ({
                        coefficient: shareCommitmentOpeningCoefficient({
                            outputCoefficientIndex: commitmentCoefficientIndex,
                            randomnessMatrixPolynomial:
                                randomnessMatrixRow[openingCoordinateIndex] ??
                                [],
                        }),
                        columnIndex: requireColumnIndex(
                            input.columnLookup,
                            variableName,
                        ),
                        variableName,
                    }),
                );
                rows.push({
                    modulus: shareCommitmentModulus,
                    rowIndex: rows.length,
                    rowKind: 'ShareCommitmentEquation',
                    rowName: `receiver_${shareCommitmentRow.receiverRosterPosition}_share_commitment_vector_${commitmentVectorIndex}_coefficient_${commitmentCoefficientIndex}_equation`,
                    target: canonicalShareCommitmentCoefficient(
                        commitmentPolynomialVector[commitmentVectorIndex]?.[
                            commitmentCoefficientIndex
                        ] ?? 0n,
                    ),
                    terms: [...shareTerms, ...openingTerms],
                });
            }
        }
    }

    return rows;
};

const buildExplicitShareCommitmentRowBatch = (input: {
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyBackendStatementExplicitRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const variableColumnIndices = [
        ...new Set(
            input.rows.flatMap((row) =>
                row.terms.map((term) => term.columnIndex),
            ),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);

    return {
        batchKind: 'ExplicitSparseRows',
        batchName: 'share_commitment_equation_rows',
        matrixDigest: deriveBackendDigest(explicitBackendMatrixDigestPurpose, {
            rows: input.rows.map(({ rowIndex, rowKind, rowName, terms }) => ({
                rowIndex,
                rowKind,
                rowName,
                terms,
            })),
        }),
        modulus: shareCommitmentModulus,
        rowCount: input.rows.length,
        rowKind: 'ShareCommitmentEquationRows',
        rowOffset: input.rowOffset,
        rows: input.rows,
        targetVectorDigest: deriveBackendDigest(
            explicitBackendTargetVectorDigestPurpose,
            {
                targets: input.rows.map(
                    ({ rowIndex, rowKind, rowName, target }) => ({
                        rowIndex,
                        rowKind,
                        rowName,
                        target,
                    }),
                ),
            },
        ),
        variableColumnIndices,
    };
};

const buildDigestExpandedRowBatch = (input: {
    readonly algebraicRow: BallotPrivacyAlgebraicRelationRow;
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowOffset: number;
}): BallotPrivacyBackendStatementRowBatch => {
    const variableColumnIndices = input.algebraicRow.variableNames.map(
        (variableName) => requireColumnIndex(input.columnLookup, variableName),
    );
    const coefficientExpansionDomain = `sealed.vote/internal/ballot-privacy/${input.algebraicRow.rowKind}/coefficient-expansion-v1`;
    const targetExpansionDomain = `sealed.vote/internal/ballot-privacy/${input.algebraicRow.rowKind}/target-expansion-v1`;
    const expansionPayload = {
        coefficientExpansionDomain,
        modulus: decimalString(input.algebraicRow.modulus),
        publicInputDigests: input.algebraicRow.publicInputDigests,
        receiverIdentity: input.algebraicRow.receiverIdentity,
        receiverRosterPosition: input.algebraicRow.receiverRosterPosition,
        rowCount: input.algebraicRow.equationCount,
        rowKind: input.algebraicRow.rowKind,
        sourceAlgebraicRowName: input.algebraicRow.rowName,
        targetDigest: input.algebraicRow.targetDigest,
        targetExpansionDomain,
        variableColumnIndices,
    };

    return {
        batchKind: 'DigestExpandedRows',
        batchName: `${input.algebraicRow.rowName}_backend_rows`,
        coefficientExpansionDomain,
        matrixDigest: deriveBackendDigest(
            digestExpandedBackendMatrixDigestPurpose,
            expansionPayload,
        ),
        modulus: decimalString(input.algebraicRow.modulus),
        publicInputDigests: input.algebraicRow.publicInputDigests,
        receiverIdentity: input.algebraicRow.receiverIdentity,
        receiverRosterPosition: input.algebraicRow.receiverRosterPosition,
        rowCount: input.algebraicRow.equationCount,
        rowKind: input.algebraicRow.rowKind,
        rowOffset: input.rowOffset,
        sourceAlgebraicRowName: input.algebraicRow.rowName,
        targetDigest: input.algebraicRow.targetDigest,
        targetExpansionDomain,
        targetVectorDigest: deriveBackendDigest(
            digestExpandedBackendTargetVectorDigestPurpose,
            expansionPayload,
        ),
        variableColumnIndices,
    };
};

const buildBackendBounds = (input: {
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly columnLookup: ReadonlyMap<string, number>;
}): readonly BallotPrivacyBackendStatementBound[] =>
    input.bounds.map((bound) => {
        const backendBound: BallotPrivacyBackendStatementBound = {
            boundKind: bound.boundKind,
            boundName: bound.boundName,
            variableColumnIndices: bound.variableNames.map((variableName) =>
                requireColumnIndex(input.columnLookup, variableName),
            ),
            variableNames: bound.variableNames,
        };

        if (bound.absoluteMaximum !== undefined) {
            return {
                ...backendBound,
                absoluteMaximum: decimalString(bound.absoluteMaximum),
            };
        }
        if (bound.minimum !== undefined && bound.maximum !== undefined) {
            return {
                ...backendBound,
                maximum: decimalString(bound.maximum),
                minimum: decimalString(bound.minimum),
            };
        }

        return backendBound;
    });

const componentIdForBatch = (
    batch: BallotPrivacyBackendStatementRowBatch,
): BallotPrivacyBackendProofComponentId => {
    if (batch.rowKind === 'EncodedScoreFieldRows') {
        return 'score-and-shamir-field-component';
    }
    if (batch.rowKind === 'ReceiverPayloadPlaintextBindingRows') {
        return 'payload-plaintext-field-component';
    }
    if (
        batch.rowKind === 'ShareCommitmentEquation' ||
        batch.rowKind === 'ShareCommitmentEquationRows'
    ) {
        return 'share-commitment-component';
    }
    if (batch.rowKind === 'ReceiverPayloadEncryptionEquation') {
        return 'receiver-encryption-component';
    }

    return 'receiver-key-binding-component';
};

export const ballotPrivacyBackendProofComponentOrder: readonly BallotPrivacyBackendProofComponentId[] =
    [
        'score-and-shamir-field-component',
        'payload-plaintext-field-component',
        'share-commitment-component',
        'receiver-encryption-component',
        'receiver-key-binding-component',
    ];

const buildBackendProofComponents = (
    rowBatches: readonly BallotPrivacyBackendStatementRowBatch[],
): readonly BallotPrivacyBackendProofComponent[] => {
    const batchesByComponent = new Map<
        BallotPrivacyBackendProofComponentId,
        BallotPrivacyBackendStatementRowBatch[]
    >();
    for (const rowBatch of rowBatches) {
        const componentId = componentIdForBatch(rowBatch);
        const componentBatches = batchesByComponent.get(componentId) ?? [];
        componentBatches.push(rowBatch);
        batchesByComponent.set(componentId, componentBatches);
    }
    const proofComponents: BallotPrivacyBackendProofComponent[] = [];

    for (const componentId of ballotPrivacyBackendProofComponentOrder) {
        const componentBatches = batchesByComponent.get(componentId) ?? [];
        if (componentBatches.length === 0) {
            continue;
        }
        const variableColumnIndices = [
            ...new Set(
                componentBatches.flatMap(
                    (batch) => batch.variableColumnIndices,
                ),
            ),
        ].sort(
            (leftColumnIndex, rightColumnIndex) =>
                leftColumnIndex - rightColumnIndex,
        );
        const coefficientModuli = new Set(
            componentBatches.map((batch) => batch.modulus),
        );
        if (coefficientModuli.size !== 1) {
            throw new RangeError(
                'Backend proof component batches must share one modulus.',
            );
        }
        const proofLoweringStatus: BallotPrivacyBackendProofComponent['proofLoweringStatus'] =
            componentBatches.every(
                (batch) => batch.batchKind === 'ExplicitSparseRows',
            )
                ? 'explicitRowsAvailable'
                : 'digestExpandedRowsPending';
        const componentPayload: Omit<
            BallotPrivacyBackendProofComponent,
            'componentDigest'
        > = {
            coefficientModulus: componentBatches[0]?.modulus ?? '',
            componentId,
            proofLoweringStatus,
            rowBatchNames: componentBatches.map((batch) => batch.batchName),
            rowCount: componentBatches.reduce(
                (rowCount, batch) => rowCount + batch.rowCount,
                0,
            ),
            rowKinds: [
                ...new Set(componentBatches.map((batch) => batch.rowKind)),
            ],
            variableColumnCount: variableColumnIndices.length,
            variableColumnIndices,
        };

        proofComponents.push({
            ...componentPayload,
            componentDigest: deriveBackendDigest(
                backendProofComponentsDigestPurpose,
                componentPayload,
            ),
        });
    }

    return proofComponents;
};

const buildBackendStatement = (input: {
    readonly algebraicRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly encodedCoordinateCount: number;
    readonly linearRows: readonly BallotPrivacyLinearRelationRow[];
    readonly optionCount: number;
    readonly pvssThreshold: number;
    readonly rosterSize: number;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly shareVectorWidth: number;
    readonly variables: readonly BallotPrivacyLinearRelationVariable[];
}): BallotPrivacyProofBackendStatement => {
    const columnLookup = createVariableColumnLookup(input.variables);
    const scoreAndShamirRows = input.linearRows.filter((row) =>
        [
            'OneHotSum',
            'ScalarScoreConsistency',
            'ShamirEvaluationQuotient',
        ].includes(row.rowKind),
    );
    const payloadPlaintextBindingRows = input.linearRows.filter((row) =>
        [
            'ReceiverPayloadSharePlaintextBinding',
            'ReceiverPayloadOpeningPlaintextBinding',
        ].includes(row.rowKind),
    );
    const explicitScoreFieldRowBatch = buildExplicitSparseRowBatch({
        batchName: 'encoded_score_field_rows',
        columnLookup,
        rowKind: 'EncodedScoreFieldRows',
        rowOffset: 0,
        rows: scoreAndShamirRows,
    });
    const explicitPayloadPlaintextRowBatch = buildExplicitSparseRowBatch({
        batchName: 'receiver_payload_plaintext_binding_rows',
        columnLookup,
        rowKind: 'ReceiverPayloadPlaintextBindingRows',
        rowOffset: explicitScoreFieldRowBatch.rowCount,
        rows: payloadPlaintextBindingRows,
    });
    const shareCommitmentRowsWithPublicVectors = input.algebraicRows.filter(
        (algebraicRow) =>
            algebraicRow.rowKind === 'ShareCommitmentEquation' &&
            algebraicRow.shareCommitmentPolynomialVector !== undefined,
    );
    const explicitShareCommitmentRows = buildShareCommitmentEquationRows({
        columnLookup,
        shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        shareCommitmentRows: shareCommitmentRowsWithPublicVectors,
        shareVectorWidth: input.shareVectorWidth,
    });
    const explicitShareCommitmentRowBatch =
        explicitShareCommitmentRows.length > 0
            ? buildExplicitShareCommitmentRowBatch({
                  rowOffset:
                      explicitScoreFieldRowBatch.rowCount +
                      explicitPayloadPlaintextRowBatch.rowCount,
                  rows: explicitShareCommitmentRows,
              })
            : undefined;
    const explicitBatches = [
        explicitScoreFieldRowBatch,
        explicitPayloadPlaintextRowBatch,
        ...(explicitShareCommitmentRowBatch === undefined
            ? []
            : [explicitShareCommitmentRowBatch]),
    ] as const;
    let nextRowOffset = explicitBatches.reduce(
        (rowCount, batch) => rowCount + batch.rowCount,
        0,
    );
    const digestExpandedBatches = input.algebraicRows
        .filter(
            (algebraicRow) =>
                algebraicRow.rowKind !== 'ShareCommitmentEquation' ||
                algebraicRow.shareCommitmentPolynomialVector === undefined,
        )
        .map((algebraicRow) => {
            const batch = buildDigestExpandedRowBatch({
                algebraicRow,
                columnLookup,
                rowOffset: nextRowOffset,
            });
            nextRowOffset += batch.rowCount;

            return batch;
        });
    const rowBatches = [...explicitBatches, ...digestExpandedBatches] as const;
    const backendBounds = buildBackendBounds({
        bounds: input.bounds,
        columnLookup,
    });
    const proofComponents = buildBackendProofComponents(rowBatches);
    const explicitRowCount = explicitBatches.reduce(
        (rowCount, batch) => rowCount + batch.rowCount,
        0,
    );
    const digestExpandedRowCount = digestExpandedBatches.reduce(
        (rowCount, batch) => rowCount + batch.rowCount,
        0,
    );
    const matrixDigest = deriveBackendDigest(backendMatrixDigestPurpose, {
        rowBatches: rowBatches.map((batch) => ({
            batchKind: batch.batchKind,
            batchName: batch.batchName,
            matrixDigest: batch.matrixDigest,
            rowCount: batch.rowCount,
            rowKind: batch.rowKind,
            rowOffset: batch.rowOffset,
        })),
    });
    const targetVectorDigest = deriveBackendDigest(
        backendTargetVectorDigestPurpose,
        {
            rowBatches: rowBatches.map((batch) => ({
                batchKind: batch.batchKind,
                batchName: batch.batchName,
                rowCount: batch.rowCount,
                rowKind: batch.rowKind,
                rowOffset: batch.rowOffset,
                targetVectorDigest: batch.targetVectorDigest,
            })),
        },
    );
    const boundsDigest = deriveBackendDigest(backendBoundsDigestPurpose, {
        bounds: backendBounds,
    });
    const proofComponentsDigest = deriveBackendDigest(
        backendProofComponentsDigestPurpose,
        {
            proofComponents,
        },
    );
    const backendStatementPayload: Omit<
        BallotPrivacyProofBackendStatement,
        'backendStatementDigest'
    > = {
        backendStatementFormat,
        bounds: backendBounds,
        boundsDigest,
        columnCount: input.variables.length,
        digestExpandedRowCount,
        encodedCoordinateCount: input.encodedCoordinateCount,
        explicitRowCount,
        fieldModulus,
        matrixDigest,
        objectType: 'BallotPrivacyProofBackendStatement',
        objectVersion: 1,
        optionCount: input.optionCount,
        proofComponents,
        proofComponentsDigest,
        pvssThreshold: input.pvssThreshold,
        relationLabel: 'BallotPrivacyPvssRelation',
        rosterSize: input.rosterSize,
        rowBatches,
        rowCount: explicitRowCount + digestExpandedRowCount,
        shareVectorWidth: input.shareVectorWidth,
        sourceRelationStatementFormat: relationStatementFormat,
        targetVectorDigest,
        variableColumns: backendVariableColumns(input.variables),
    };

    return {
        ...backendStatementPayload,
        backendStatementDigest: deriveBackendDigest(
            backendStatementDigestPurpose,
            backendStatementPayload,
        ),
    };
};

const resolveCiphertextChunkCount = (
    receiverPayload: ReceiverPayloadReference | undefined,
): number => receiverPayload?.ciphertextChunkCount ?? 1;

const buildAlgebraicRows = (
    input: {
        readonly publicContext: BallotPrivacyRelationBackendPublicContext;
        readonly relationInput: BallotPrivacyRelationCompilerInput;
    },
    registry: VariableRegistry,
): readonly BallotPrivacyAlgebraicRelationRow[] => {
    const rows: BallotPrivacyAlgebraicRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.relationInput.optionCount,
    );
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );
    const payloadsByReceiver = referencesByReceiver(
        input.publicContext.receiverPayloads,
    );
    const commitmentsByReceiver = referencesByReceiver(
        input.publicContext.shareCommitments,
    );

    for (const receiver of input.relationInput.receivers) {
        const receiverKey = receiverReferenceKey(receiver);
        const publicKey = publicKeysByReceiver.get(receiverKey);
        const receiverPayload = payloadsByReceiver.get(receiverKey);
        const shareCommitment = commitmentsByReceiver.get(receiverKey);
        const receiverRosterPosition = receiver.receiverRosterPosition;
        const shareVariableNames = receiverShareVariableNames(
            registry,
            receiverRosterPosition,
            encodedCoordinateCount,
        );
        const openingVariableNames = receiverOpeningVariableNames(
            registry,
            receiverRosterPosition,
        );
        const payloadPlaintextShareVariableNames =
            receiverPayloadPlaintextShareVariableNames(
                registry,
                receiverRosterPosition,
                encodedCoordinateCount,
            );
        const payloadPlaintextOpeningVariableNames =
            receiverPayloadPlaintextOpeningVariableNames(
                registry,
                receiverRosterPosition,
            );
        const encryptionRandomnessVariableName =
            addReceiverEncryptionRandomnessVariable(
                registry,
                receiverRosterPosition,
            );
        const encryptionNoiseVariableName = addReceiverEncryptionNoiseVariable(
            registry,
            receiverRosterPosition,
        );
        const shareCommitmentPublicInputs = {
            commitmentBodyDigest:
                shareCommitment?.commitmentBodyDigest ??
                shareCommitment?.shareCommitmentDigest ??
                input.publicContext.shareCommitmentProfileDigest,
            commitmentPolynomialVectorDigest:
                shareCommitment?.commitmentPolynomialVectorDigest ??
                shareCommitment?.shareCommitmentDigest ??
                input.publicContext.shareCommitmentProfileDigest,
            shareCommitmentDigest:
                shareCommitment?.shareCommitmentDigest ??
                input.publicContext.shareCommitmentProfileDigest,
            shareCommitmentProfileDigest:
                input.publicContext.shareCommitmentProfileDigest,
        };
        const receiverPayloadPublicInputs = {
            ciphertextBodyDigest:
                receiverPayload?.ciphertextBodyDigest ??
                receiverPayload?.receiverPayloadDigest ??
                input.publicContext.receiverEncryptionProfileDigest,
            ciphertextChunkDigest:
                receiverPayload?.ciphertextChunkDigest ??
                receiverPayload?.receiverPayloadCiphertextRoot ??
                input.publicContext.receiverEncryptionProfileDigest,
            receiverPayloadCiphertextRoot:
                receiverPayload?.receiverPayloadCiphertextRoot ??
                input.publicContext.receiverEncryptionProfileDigest,
            receiverPayloadDigest:
                receiverPayload?.receiverPayloadDigest ??
                input.publicContext.receiverEncryptionProfileDigest,
        };
        const receiverKeyPublicInputs = {
            keyMaterialDigest:
                publicKey?.keyMaterialDigest ??
                publicKey?.receiverPublicKeyDigest ??
                input.publicContext.receiverKeyRoot,
            publicMatrixSeedDigest:
                publicKey?.publicMatrixSeedDigest ??
                publicKey?.receiverPublicKeyDigest ??
                input.publicContext.receiverKeyRoot,
            receiverKeyProofRoot: input.publicContext.receiverKeyProofRoot,
            receiverKeyRoot: input.publicContext.receiverKeyRoot,
            receiverPublicKeyDigest:
                publicKey?.receiverPublicKeyDigest ??
                input.publicContext.receiverKeyRoot,
        };
        const ciphertextChunkCount =
            resolveCiphertextChunkCount(receiverPayload);

        rows.push({
            equationCount:
                shareCommitmentModuleRank * shareCommitmentModuleDegree,
            modulus: shareCommitmentModulus,
            publicInputDigests: shareCommitmentPublicInputs,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ShareCommitmentEquation',
            rowName: `receiver_${receiverRosterPosition}_share_commitment_equation`,
            ...(shareCommitment?.commitmentPolynomialVector === undefined
                ? {}
                : {
                      shareCommitmentPolynomialVector:
                          shareCommitment.commitmentPolynomialVector,
                  }),
            targetDigest: deriveAlgebraicTargetDigest(
                'ballot-privacy-share-commitment-equation-target-v1',
                {
                    receiverIdentity: receiver.receiverIdentity,
                    receiverRosterPosition,
                    shareCommitmentPublicInputs,
                },
            ),
            variableNames: [...shareVariableNames, ...openingVariableNames],
        });
        rows.push({
            equationCount:
                ciphertextChunkCount *
                (receiverEncryptionModuleRank + 1) *
                receiverEncryptionModuleDegree,
            modulus: receiverEncryptionModulus,
            publicInputDigests: {
                ...receiverPayloadPublicInputs,
                ...receiverKeyPublicInputs,
            },
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ReceiverPayloadEncryptionEquation',
            rowName: `receiver_${receiverRosterPosition}_receiver_payload_encryption_equation`,
            targetDigest: deriveAlgebraicTargetDigest(
                'ballot-privacy-receiver-payload-encryption-equation-target-v1',
                {
                    ciphertextChunkCount,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverKeyPublicInputs,
                    receiverPayloadPublicInputs,
                    receiverRosterPosition,
                },
            ),
            variableNames: [
                ...payloadPlaintextShareVariableNames,
                ...payloadPlaintextOpeningVariableNames,
                encryptionRandomnessVariableName,
                encryptionNoiseVariableName,
            ],
        });
        rows.push({
            equationCount:
                receiverEncryptionModuleRank * receiverEncryptionModuleDegree,
            modulus: receiverEncryptionModulus,
            publicInputDigests: receiverKeyPublicInputs,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ReceiverKeyBinding',
            rowName: `receiver_${receiverRosterPosition}_receiver_key_binding`,
            targetDigest: deriveAlgebraicTargetDigest(
                'ballot-privacy-receiver-key-binding-target-v1',
                {
                    receiverIdentity: receiver.receiverIdentity,
                    receiverKeyPublicInputs,
                    receiverRosterPosition,
                },
            ),
            variableNames: [],
        });
    }

    return rows;
};

const calculateCertifiedShamirQuotientBound = (input: {
    readonly pvssThreshold: number;
}): number => {
    const maximumFieldRepresentative = fieldModulus - 1;
    const maximumEvaluationBeforeReduction =
        maximumFieldRepresentative +
        (input.pvssThreshold - 1) *
            maximumFieldRepresentative *
            maximumFieldRepresentative;
    const maximumNumeratorMagnitude =
        maximumEvaluationBeforeReduction + maximumFieldRepresentative;

    return Math.ceil(maximumNumeratorMagnitude / fieldModulus);
};

const buildBounds = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationBound[] => {
    const bounds: BallotPrivacyLinearRelationBound[] = [];
    const scoreBucketBounds: BallotPrivacyLinearRelationBound[] = [];
    const scalarFieldVariables: string[] = [];
    const coefficientFieldVariables: string[] = [];
    const receiverShareFieldVariables: string[] = [];
    const quotientVariables: string[] = [];
    const receiverPayloadPlaintextShareFieldVariables: string[] = [];
    const receiverPayloadPlaintextOpeningVariables: string[] = [];
    const shareCommitmentOpeningVariables: string[] = [];
    const receiverEncryptionRandomnessVariables: string[] = [];
    const receiverEncryptionNoiseVariables: string[] = [];

    for (const variable of registry.values()) {
        if (variable.variableRole === 'ScoreBucketConstant') {
            scoreBucketBounds.push({
                boundKind: 'Boolean',
                boundName: `${variable.variableName}_boolean`,
                maximum: 1,
                minimum: 0,
                variableNames: [variable.variableName],
            });
        } else if (variable.variableRole === 'ScalarScoreConstant') {
            scalarFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ShamirCoefficient') {
            coefficientFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverShare') {
            receiverShareFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ShamirQuotient') {
            quotientVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverPayloadPlaintextShare') {
            receiverPayloadPlaintextShareFieldVariables.push(
                variable.variableName,
            );
        } else if (
            variable.variableRole === 'ReceiverPayloadPlaintextOpening'
        ) {
            receiverPayloadPlaintextOpeningVariables.push(
                variable.variableName,
            );
        } else if (variable.variableRole === 'ShareCommitmentOpening') {
            shareCommitmentOpeningVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionRandomness') {
            receiverEncryptionRandomnessVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionNoise') {
            receiverEncryptionNoiseVariables.push(variable.variableName);
        }
    }

    bounds.push(...scoreBucketBounds);
    for (const [boundName, variableNames] of [
        ['scalar_score_constants_canonical', scalarFieldVariables],
        ['shamir_coefficients_canonical', coefficientFieldVariables],
        ['receiver_shares_canonical', receiverShareFieldVariables],
        [
            'receiver_payload_plaintext_shares_canonical',
            receiverPayloadPlaintextShareFieldVariables,
        ],
    ] as const) {
        bounds.push({
            boundKind: 'CanonicalFieldElement',
            boundName,
            maximum: fieldModulus - 1,
            minimum: 0,
            variableNames,
        });
    }
    bounds.push({
        absoluteMaximum: calculateCertifiedShamirQuotientBound(input),
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'shamir_quotients_certified_absolute_bound',
        variableNames: quotientVariables,
    });
    bounds.push({
        absoluteMaximum: shareCommitmentOpeningInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'share_commitment_openings_certified_absolute_bound',
        variableNames: shareCommitmentOpeningVariables,
    });
    bounds.push({
        absoluteMaximum: shareCommitmentOpeningInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName:
            'receiver_payload_plaintext_openings_certified_absolute_bound',
        variableNames: receiverPayloadPlaintextOpeningVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_randomness_certified_absolute_bound',
        variableNames: receiverEncryptionRandomnessVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_noise_certified_absolute_bound',
        variableNames: receiverEncryptionNoiseVariables,
    });

    return bounds;
};

const deriveRelationStatementDigest = (
    statementPayload: Omit<
        BallotPrivacyLoweredLinearRelationStatement,
        'relationStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: relationStatementDigestPurpose,
        statementPayload,
    });

export const lowerBallotPrivacyRelationToBackendStatement = (input: {
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
}): BallotPrivacyRelationBackendLoweringResult => {
    const relationCompilation = compileBallotPrivacyRelation(
        input.relationInput,
    );

    if (!relationCompilation.ok) {
        return relationCompilation;
    }

    const registry = createVariableRegistry();
    const linearRows = [
        ...buildMembershipRows(input.relationInput, registry),
        ...buildShamirRows(input.relationInput, registry),
        ...buildReceiverPayloadPlaintextBindingRows(
            input.relationInput,
            registry,
        ),
    ];
    const algebraicRows = buildAlgebraicRows(input, registry);
    const bounds = buildBounds(input.relationInput, registry);
    const variables = registry.values();
    const backendStatement = buildBackendStatement({
        algebraicRows,
        bounds,
        encodedCoordinateCount: relationCompilation.encodedCoordinateCount,
        linearRows,
        optionCount: relationCompilation.optionCount,
        pvssThreshold: relationCompilation.pvssThreshold,
        rosterSize: relationCompilation.rosterSize,
        shareCommitmentProfileDigest:
            input.publicContext.shareCommitmentProfileDigest,
        shareVectorWidth: relationCompilation.shareVectorWidth,
        variables,
    });
    const statementPayload: Omit<
        BallotPrivacyLoweredLinearRelationStatement,
        'relationStatementDigest'
    > = {
        algebraicRows,
        backendStatement,
        bounds,
        encodedCoordinateCount: relationCompilation.encodedCoordinateCount,
        fieldModulus,
        linearRows,
        objectType: 'BallotPrivacyLinearRelationStatement',
        objectVersion: 1,
        optionCount: relationCompilation.optionCount,
        publicContext: input.publicContext,
        pvssThreshold: relationCompilation.pvssThreshold,
        relationLabel: relationCompilation.relationLabel,
        relationStatementFormat,
        rosterSize: relationCompilation.rosterSize,
        shareVectorWidth: relationCompilation.shareVectorWidth,
        variables,
    };

    return {
        ok: true,
        statement: {
            ...statementPayload,
            relationStatementDigest:
                deriveRelationStatementDigest(statementPayload),
        },
    };
};
