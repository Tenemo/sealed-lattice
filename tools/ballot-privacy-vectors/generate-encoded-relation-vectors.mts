import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildEncodedBallotRelationVectorCases } from "./encoded-relation-vectors/case-builders.mjs";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const outputPath = path.resolve(
    repoRoot,
    "test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json",
);

const main = async (): Promise<void> => {
    const cases = buildEncodedBallotRelationVectorCases();
    const vectorFile = {
        cases,
        generatedBy:
            "tsx --tsconfig tsconfig.base.json tools/ballot-privacy-vectors/generate-encoded-relation-vectors.mts",
        generationStatus: "generated",
        objectType: "BallotPrivacyEncodedBallotLinearRelationVectors",
        objectVersion: 1,
        profileId: "encoded-ballot-linear-relation-v1",
        requiredCaseNames: cases.map((vectorCase) => vectorCase.caseName),
        statementFormat: "SparseIntegerRowsModuloGF65537WithBoundGadgets-v1",
    };

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(vectorFile)}\n`);
};

void main();
