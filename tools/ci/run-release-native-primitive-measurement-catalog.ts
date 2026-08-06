import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { runWithLocalRunLog } from "./local-run-log.js";
import {
    parseReleaseNativePrimitiveMeasurementOutput,
    primitiveMeasurementCaseCatalog,
    validateReleaseNativePrimitiveMeasurementEvidence,
    type PrimitiveMeasurementRecord,
} from "./primitive-measurement-evidence.js";

type JsonObject = Record<string, unknown>;

const isJsonObject = (value: unknown): value is JsonObject =>
    typeof value === "object" && value !== null && !Array.isArray(value);

const readCompletedFocusedRun = async (
    runDirectoryArgument: string,
): Promise<
    Readonly<{ record: PrimitiveMeasurementRecord; runDirectoryPath: string }>
> => {
    const runDirectoryPath = path.resolve(process.cwd(), runDirectoryArgument);
    const summary = JSON.parse(
        await readFile(path.join(runDirectoryPath, "summary.json"), "utf8"),
    ) as unknown;
    if (
        !isJsonObject(summary) ||
        summary.exitCode !== 0 ||
        summary.diagnosticFailureCount !== 0 ||
        summary.resultClassification !== "completed" ||
        summary.scriptName !== "test:rust:kernel:measurements" ||
        typeof summary.runDirectoryPath !== "string" ||
        path.resolve(summary.runDirectoryPath).toLocaleLowerCase() !==
            runDirectoryPath.toLocaleLowerCase()
    ) {
        throw new Error(
            `Primitive measurement run ${runDirectoryPath} did not complete cleanly.`,
        );
    }
    const outputEvidence = parseReleaseNativePrimitiveMeasurementOutput(
        await readFile(path.join(runDirectoryPath, "output.log"), "utf8"),
        false,
    );
    const attachmentPath = path.join(
        runDirectoryPath,
        "attachments",
        "primitive-measurements",
        "release-native-focused-primitive-measurement.json",
    );
    const attachmentEvidence =
        validateReleaseNativePrimitiveMeasurementEvidence(
            JSON.parse(await readFile(attachmentPath, "utf8")) as unknown,
            false,
        );
    if (JSON.stringify(outputEvidence) !== JSON.stringify(attachmentEvidence)) {
        throw new Error(
            `Primitive measurement run ${runDirectoryPath} output and attachment differ.`,
        );
    }
    return Object.freeze({
        record: outputEvidence.primitiveCases[0],
        runDirectoryPath,
    });
};

export const runReleaseNativePrimitiveMeasurementCatalog =
    async (): Promise<void> => {
        const commandArguments = process.argv
            .slice(2)
            .filter((argument) => argument !== "--");
        await runWithLocalRunLog(
            {
                commandLineArguments: commandArguments,
                lanes: ["Release-native primitive measurement catalog"],
                scriptName:
                    "test:evidence:release-native-primitive-measurements",
            },
            async (runLog) => {
                if (
                    commandArguments.length !==
                    primitiveMeasurementCaseCatalog.length
                ) {
                    throw new Error(
                        `Release-native primitive measurement catalog assembly requires ${String(primitiveMeasurementCaseCatalog.length)} focused run directories in case order.`,
                    );
                }
                const sourceRuns = await Promise.all(
                    commandArguments.map(readCompletedFocusedRun),
                );
                const evidence =
                    validateReleaseNativePrimitiveMeasurementEvidence(
                        {
                            primitiveCases: sourceRuns.map(
                                (source) => source.record,
                            ),
                            schemaVersion: 1,
                        },
                        true,
                    );
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    "attachments",
                    "primitive-measurements",
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const attachmentFilePath = path.join(
                    attachmentDirectoryPath,
                    "release-native-primitive-measurements.json",
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(evidence, undefined, 2)}\n`,
                    "utf8",
                );
                runLog.writeEvent({
                    details: {
                        attachmentFilePath,
                        sourceRunDirectoryPaths: sourceRuns.map(
                            (source) => source.runDirectoryPath,
                        ),
                    },
                    eventType:
                        "release-native-primitive-measurement-catalog-written",
                });
                runLog.writeCombinedOutput(
                    `Release-native primitive measurement catalog completed; evidence: ${attachmentFilePath}\n`,
                );
            },
        );
    };

if (import.meta.main) {
    void runReleaseNativePrimitiveMeasurementCatalog();
}
