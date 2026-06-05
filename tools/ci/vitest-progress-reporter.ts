import type {
    Reporter,
    TestCase,
    TestModule,
    TestSpecification,
} from 'vitest/node';

type ProgressCount = {
    readonly completed: number;
    readonly total?: number;
};

type VitestProgressEvent = {
    readonly files: ProgressCount;
    readonly tests: ProgressCount;
    readonly tool: 'vitest';
};

const progressEventPrefix = 'sealed-lattice-progress ';

const emitProgressEvent = (event: VitestProgressEvent): void => {
    process.stdout.write(`${progressEventPrefix}${JSON.stringify(event)}\n`);
};

export default class SealedLatticeVitestProgressReporter implements Reporter {
    #completedFileCount = 0;
    #completedTestIds = new Set<string>();
    #completedTestModuleIds = new Set<string>();
    #collectedTestIds = new Set<string>();
    #testFileCount = 0;

    onTestRunStart(specifications: readonly TestSpecification[]): void {
        this.#testFileCount = specifications.length;
        this.#emit();
    }

    onTestModuleCollected(testModule: TestModule): void {
        this.#collectTestModule(testModule);
        this.#emit();
    }

    onTestModuleEnd(testModule: TestModule): void {
        this.#collectTestModule(testModule);
        if (!this.#completedTestModuleIds.has(testModule.id)) {
            this.#completedTestModuleIds.add(testModule.id);
            this.#completedFileCount += 1;
        }
        this.#emit();
    }

    onTestCaseResult(testCase: TestCase): void {
        this.#collectedTestIds.add(testCase.id);
        this.#completedTestIds.add(testCase.id);
        this.#emit();
    }

    onTestRunEnd(testModules: readonly TestModule[]): void {
        for (const testModule of testModules) {
            this.#collectTestModule(testModule);
        }
        this.#emit();
    }

    #collectTestModule(testModule: TestModule): void {
        for (const testCase of testModule.children.allTests()) {
            this.#collectedTestIds.add(testCase.id);
        }
    }

    #emit(): void {
        emitProgressEvent({
            files: {
                completed: this.#completedFileCount,
                total: this.#testFileCount,
            },
            tests: {
                completed: this.#completedTestIds.size,
                total: this.#collectedTestIds.size,
            },
            tool: 'vitest',
        });
    }
}
