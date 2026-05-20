import type { VariableRegistry } from './backend-contracts.js';
import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentOpeningDimension,
} from './backend-contracts.js';
import {
    addReceiverEncryptionFirstNoiseVariable,
    addReceiverEncryptionRandomnessVariable,
    addReceiverEncryptionSecondNoiseVariable,
    addReceiverPayloadPlaintextOpeningBitVariable,
    addReceiverPayloadPlaintextOpeningVariable,
    addReceiverPayloadPlaintextShareBitVariable,
    addReceiverPayloadPlaintextShareVariable,
    addReceiverShareVariable,
    addShareCommitmentOpeningVariable,
} from './relation-row-builders.js';

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

const receiverPayloadPlaintextBitVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    shareVectorWidth: number,
    plaintextBitLength: number,
): readonly string[] =>
    Array.from(
        { length: plaintextBitLength },
        (_unusedValue, plaintextBitIndex) => {
            const shareBitCount =
                shareVectorWidth * receiverShareRepresentativeBitLength;
            if (plaintextBitIndex < shareBitCount) {
                return addReceiverPayloadPlaintextShareBitVariable(
                    registry,
                    receiverRosterPosition,
                    Math.floor(
                        plaintextBitIndex /
                            receiverShareRepresentativeBitLength,
                    ),
                    plaintextBitIndex % receiverShareRepresentativeBitLength,
                );
            }

            const openingBitIndex = plaintextBitIndex - shareBitCount;

            return addReceiverPayloadPlaintextOpeningBitVariable(
                registry,
                receiverRosterPosition,
                shareVectorWidth,
                Math.floor(
                    openingBitIndex / receiverOpeningRandomnessBitLength,
                ),
                openingBitIndex % receiverOpeningRandomnessBitLength,
            );
        },
    );

const receiverEncryptionVariableNames = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    ciphertextChunkCount: number,
): readonly string[] => {
    const variableNames: string[] = [];
    for (
        let chunkIndex = 0;
        chunkIndex < ciphertextChunkCount;
        chunkIndex += 1
    ) {
        for (
            let vectorIndex = 0;
            vectorIndex < receiverEncryptionModuleRank;
            vectorIndex += 1
        ) {
            for (
                let coefficientIndex = 0;
                coefficientIndex < receiverEncryptionModuleDegree;
                coefficientIndex += 1
            ) {
                variableNames.push(
                    addReceiverEncryptionRandomnessVariable(
                        registry,
                        receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                        coefficientIndex,
                    ),
                );
                variableNames.push(
                    addReceiverEncryptionFirstNoiseVariable(
                        registry,
                        receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                        coefficientIndex,
                    ),
                );
            }
        }
        for (
            let coefficientIndex = 0;
            coefficientIndex < receiverEncryptionModuleDegree;
            coefficientIndex += 1
        ) {
            variableNames.push(
                addReceiverEncryptionSecondNoiseVariable(
                    registry,
                    receiverRosterPosition,
                    chunkIndex,
                    coefficientIndex,
                ),
            );
        }
    }

    return variableNames;
};

export {
    receiverShareVariableNames,
    receiverOpeningVariableNames,
    receiverPayloadPlaintextShareVariableNames,
    receiverPayloadPlaintextOpeningVariableNames,
    receiverPayloadPlaintextBitVariableNames,
    receiverEncryptionVariableNames,
};
