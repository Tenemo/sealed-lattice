import {
    reductionConstructorDimensions,
    reductionConstructorModuli,
    reductionConstructorOperands,
} from './constructor-operands.js';

// Pure arithmetic for the audited reduction algorithms. Operands describe
// literal instruction banks, worst-path counts and named data extents.
// No run subtotal or security verdict is accepted as an operand.
const ceiling = (value: bigint, divisor: bigint) =>
    (value + divisor - 1n) / divisor;
const sum = (values: bigint[]) =>
    values.reduce((left, right) => left + right, 0n);
const maximum = (values: bigint[]) =>
    values.reduce((left, right) => (left > right ? left : right));
const length = (value: bigint) => BigInt(value.toString(2).length);
type InstructionBank = {
    instructions: bigint;
    registers: bigint;
    maximumEventGap: bigint;
};

// Retain the independently priced source-recovery envelope. The packed
// decoder's literal table and complete loop bounds are checked beneath it.
export const sourceRecoveryAllowance = (degree: bigint) => ({
    events: 16n * degree * (256n + 256n) + 16n * 4096n + 16n * 256n + 1024n,
    spanBits: 480n * degree + 2n * 4096n + 32n * 256n,
});

// The constructor's populations per original honest credential: one source
// statement per family, one recipient-key statement, three proof scopes with
// their role statements and descriptors, one early source recovery per roster
// position and one first prescribed release. The preparation-ledger test
// checks each against its count at every supported profile.
export const reductionConstructorOrigins = {
    sourceStatements: reductionConstructorDimensions.sourceFamilies,
    recipientKeyStatements: 1n,
    proofScopes: 3n,
    earlySourceRecoveries: reductionConstructorDimensions.participants,
    firstPrescribedReleases: 1n,
} as const;

// The most bits one payload pass of the caller moves. The security-ledger
// test checks every payload class against it.
export const callerPassPayloadBits = 1n << 41n;

// Descriptor geometry: three full trees, then every halving tree down to
// four leaves. Framing, salt and query work retain the old overbounds. The
// serialized proof of a descriptor is a payload class of the caller.
export const reductionDescriptorGeometry = (() => {
    const {
        degree,
        maximumColumns,
        maximumLookups,
        maximumOracles,
        pricedQueries,
    } = reductionConstructorDimensions;
    const domain = 4n * degree;
    const depth = length(domain) - 1n,
        rounds = depth + 2n,
        units = maximumColumns + maximumLookups + maximumOracles + 32n,
        prefix = 1n << 24n,
        roleBytes = 1024n,
        framing = 1n << 16n;
    const trees = [domain, domain, domain];
    for (let size = domain / 2n; size >= 4n; size /= 2n) trees.push(size);
    const leaves = sum(trees),
        treeCount = BigInt(trees.length),
        inner = leaves - treeCount,
        rowBits = 384n * (units + 8n),
        inputBits = 1n << 40n;
    const proofBits =
        inputBits +
        (1n << 16n) +
        1024n * rounds +
        512n * treeCount +
        2n * pricedQueries * treeCount * (32n + rowBits + 1024n + 512n * depth);
    return {
        depth,
        rounds,
        units,
        prefix,
        roleBytes,
        framing,
        trees,
        leaves,
        treeCount,
        inner,
        rowBits,
        inputBits,
        proofBits,
    } as const;
})();

export const compileReductionConstructorPrice = (honestRegistrations = 20n) => {
    const operands = reductionConstructorOperands,
        origins = reductionConstructorOrigins;
    if (honestRegistrations < 1n)
        throw new RangeError(
            'The original credential population must be positive.',
        );
    const {
        metadataBits,
        degree,
        maximumColumns,
        maximumLookups,
        pricedQueries,
        sourceFamilies,
        participants,
        gadgets,
        selectedContributors,
    } = reductionConstructorDimensions;
    const domain = 4n * degree;
    const banks = operands.banks;
    const access = (width: bigint = metadataBits) =>
        4096n * (metadataBits + 1n) ** 2n +
        256n * (metadataBits + 1n) * (width + 1n);
    const step = (bank: InstructionBank, rows = 0n) =>
        1024n *
            (bank.instructions + bank.registers + rows + 1n) *
            metadataBits +
        256n * metadataBits ** 2n;
    const table = (bank: InstructionBank) =>
        (32n * bank.instructions + bank.registers + 32n) * metadataBits;
    const gap = (bank: InstructionBank) => bank.maximumEventGap;
    const events = (
        bank: InstructionBank,
        count: bigint,
        bits = 0n,
        final = true,
    ) =>
        table(bank) +
        (count + BigInt(final)) * gap(bank) * step(bank) +
        count * access() +
        8n * bits;
    const span = (bits: bigint, passes: bigint) => {
        const chunks = ceiling(bits, metadataBits) + passes;
        return (
            passes * table(banks.span) +
            (2n * chunks + passes) * gap(banks.span) * step(banks.span) +
            2n * chunks * access()
        );
    };
    const extensionGates = 32n * (256n * 129n ** 2n + 128n * 129n);
    const fieldConstructionWork =
        (1n << 22n) * (metadataBits + 1n) ** 2n * (9n * extensionGates + 1n);
    const fieldReplayWork =
        (64n * metadataBits + 1n) * extensionGates + 64n * metadataBits;
    const fieldTransferWork = 3n * access(384n) + 8n * 384n;
    const fieldOperationWork = fieldReplayWork + fieldTransferWork;
    const transform = (size: bigint, inverse = false) => {
        const depth = length(size) - 1n;
        return (
            depth +
            2n +
            (depth ? depth + 1n : 0n) +
            (depth * (depth - 1n)) / 2n +
            2n * depth +
            2n * size * depth +
            (inverse ? 3n * depth + size : 0n)
        );
    };
    const transformEvents = (size: bigint) => {
        const depth = length(size) - 1n;
        return (
            128n * size * (depth + 1n) +
            128n * (depth + 1n) ** 2n +
            16n * 129n +
            512n
        );
    };
    const fieldProgram = (
        bank: InstructionBank,
        fieldOperations: bigint,
        eventCount: bigint,
    ) =>
        table(bank) +
        fieldOperations * fieldOperationWork +
        (eventCount + 1n) * gap(bank) * step(bank) +
        eventCount * access(384n);

    // Complete coherent lookup generation, scanned segment mapping, emitted
    // descriptions, forward/reverse replay and clean response copying.
    const routeComponent = (
        kind: 'lookup' | 'overlay' | 'normalizer' | 'namespace',
        gates: bigint,
        outputs: bigint,
        rows: bigint,
        fresh: bigint,
        executed: bigint,
    ) => {
        const bank = banks[kind],
            word = step(bank, rows);
        const instructions =
            gap(bank) *
            (3n * gates + 2n * outputs + 3n * rows + 8n * metadataBits + 3n);
        const segments = kind === 'lookup' ? 8n * rows + 8n : 16n;
        return (
            table(bank) +
            rows * metadataBits +
            word * instructions +
            (3n * metadataBits + 2n) * gates +
            metadataBits * outputs +
            256n * (rows + 1n) * word +
            8192n * (segments + 1n) * metadataBits ** 2n * (gates + outputs) +
            (3n * metadataBits + 3n) * executed +
            fresh +
            64n * metadataBits * (executed + 1n) +
            executed
        );
    };
    const queryBankRows = [
        3n * gadgets,
        1n,
        2n,
        (4n * degree) / 4096n,
        3n * honestRegistrations,
    ];
    const lookup = sum(
        queryBankRows.map((rows) =>
            routeComponent(
                'lookup',
                19n * rows,
                1n,
                rows,
                1n + 12n * rows,
                38n * rows,
            ),
        ),
    );
    const queryCoefficient =
        lookup +
        6n *
            routeComponent(
                'overlay',
                14n * metadataBits + 11n,
                1n,
                0n,
                8n * metadataBits + 9n,
                2n * (14n * metadataBits + 11n) + 1n,
            ) +
        routeComponent('normalizer', 15n, 1n, 0n, 12n, 30n) +
        routeComponent('namespace', 8n, 12n, 0n, 15n, 16n) +
        1024n * metadataBits +
        16n * 38400n;

    // Common initialization has no honestRegistrations-dependent origin population. Work uses
    // the wider accepted sampling envelope, including conditional fibres.
    const { shareModulus, auxiliaryModulus, sourceSampleBits } =
        reductionConstructorModuli;
    const fibreBits = (modulus: bigint, bits: bigint) =>
        length(ceiling(1n << bits, modulus)) + 512n;
    const fixedSample = 64n * ceiling(length(shareModulus) + 256n, 64n);
    const groups = [
        {
            count: 3n * gadgets,
            degree: degree,
            sample: 1280n,
            limbs: 16n,
            random: 833n,
            draw: 1536n,
        },
        {
            count: 1n,
            degree: degree,
            sample: fixedSample,
            limbs: ceiling(length(shareModulus), 64n),
            random: fibreBits(shareModulus, fixedSample),
            draw: 64n * ceiling(length(shareModulus) + 512n, 64n),
        },
        {
            count: 2n,
            degree: 4096n,
            sample: fixedSample,
            limbs: 1n,
            random: fibreBits(auxiliaryModulus, fixedSample),
            draw: 576n,
        },
        {
            count: (4n * degree) / 4096n,
            degree: 4096n,
            sample: sourceSampleBits,
            limbs: 1n,
            random: fibreBits(auxiliaryModulus, sourceSampleBits),
            draw: sourceSampleBits,
        },
    ];
    const records = sum(groups.map((group) => group.count)),
        initialized = sum(
            groups.map((group) => group.count * group.degree * group.sample),
        );
    // Each current label has at most 512 bits. This is a small independent
    // overcharge over the literal older label inventory, not a hash shortcut.
    const commonRecords =
        span(
            initialized + 512n * records + 16n * metadataBits * (records + 1n),
            8n,
        ) +
        (1n << 20n) *
            (metadataBits + 1n) ** 2n *
            (records + 1n) *
            (512n + metadataBits);
    const wideFibre = (
        count: bigint,
        limbs: bigint,
        bits: bigint,
        random: bigint,
    ) => {
        const words = bits / 64n;
        return (
            64n * (bits + 1n) * (limbs + words + 1n) +
            count *
                64n *
                ((random + 1n) * (words + 1n) +
                    (limbs + 1n) * (words + 1n) +
                    limbs +
                    words +
                    1n) +
            1024n
        );
    };
    const sourceFibreRandom = fibreBits(auxiliaryModulus, sourceSampleBits);
    const sourceFibre =
        4n *
            events(
                banks.sourceFibre,
                64n * (sourceSampleBits + 9n + 1n) +
                    degree * 32n * (sourceFibreRandom + 1n) * 10n,
                degree * (64n + sourceFibreRandom + sourceSampleBits) +
                    4n * sourceSampleBits,
            ) +
        8n * degree * sourceFibreRandom;
    const fibres =
        sum(
            groups
                .slice(0, 3)
                .map(
                    (group) =>
                        group.count *
                        (events(
                            banks.wideFibre,
                            wideFibre(
                                group.degree,
                                group.limbs,
                                group.sample,
                                group.random,
                            ),
                            group.degree *
                                (64n * group.limbs +
                                    group.random +
                                    group.sample) +
                                16n * (group.sample + 64n * group.limbs),
                        ) +
                            2n * group.degree * group.random),
                ),
        ) + sourceFibre;
    const residueEvents = (count: bigint, bits: bigint, limbs: bigint) =>
        64n + count * (16n * (bits + 1n) * (limbs + 1n) + 32n);
    const commonUniform = sum(
        groups.map(
            (group) =>
                group.count *
                (events(
                    banks.residue,
                    residueEvents(group.degree, group.draw, group.limbs),
                    group.degree * (group.draw + 64n * group.limbs) +
                        128n * group.limbs,
                ) +
                    2n * group.degree * group.draw),
        ),
    );
    const matrices = (2n * degree) / 4096n + 1n,
        keyRandom = 64n * 256n + 160n * matrices * 4096n;
    const auxiliaryKey =
        events(
            banks.auxiliaryKey,
            64n * (4096n + 256n + 1n) +
                32n * matrices * 4096n * (256n + 128n) +
                1024n,
            128n * matrices * 4096n +
                keyRandom +
                127n * 160n +
                2n * 4096n +
                32n * 256n,
        ) +
        2n * keyRandom;
    const commonInitialization =
        commonRecords + fibres + commonUniform + auxiliaryKey;

    // Original caller: four adapters per retained instruction; three per
    // fixed factory object. Each adapter has 512 fields and one 8-pass effect.
    const factoryObjects =
            (sourceFamilies + 20n + 3n * participants) * honestRegistrations +
            1n,
        caller = operands.caller;
    const recipeWords = 8n * caller.commands,
        registerWords = caller.registerWords,
        preparedWords = recipeWords + registerWords;
    const callerStep = step(banks.caller),
        preparation =
            2n * preparedWords * metadataBits +
            16n * preparedWords * (callerStep + access());
    const eventWork =
        2n * table(banks.caller) +
        preparation +
        caller.field.steps * callerStep +
        caller.field.spanAccesses * access();
    const payload = callerPassPayloadBits,
        chunks = ceiling(payload, metadataBits);
    const passWork =
        (caller.prefix.base.steps + chunks * caller.prefix.perChunk.steps) *
            callerStep +
        (caller.prefix.base.spanAccesses +
            chunks * caller.prefix.perChunk.spanAccesses) *
            access();
    const meterWords = 2n * banks.meter.registers + 16n,
        meterTable = 2n * table(banks.meter);
    const meterWork =
        meterTable +
        banks.meter.instructions * step(banks.meter) +
        16n * meterWords * (step(banks.meter) + access());
    const keyFixed =
        table(banks.wrappingKeys) +
        33n * gap(banks.wrappingKeys) * step(banks.wrappingKeys) +
        32n * access();
    const keyNormalization =
        table(banks.span) +
        5n * gap(banks.span) * step(banks.span) +
        4n * access() +
        514n;
    const keyRow =
        (28n * 256n + 64n) *
            (gap(banks.wrappingKeys) * step(banks.wrappingKeys) + access()) +
        keyNormalization;
    const controllerInitialization = (64n * 65536n + 32n) * metadataBits;
    const callerFixed =
        controllerInitialization +
        3n * factoryObjects * 513n * eventWork +
        24n * factoryObjects * passWork +
        meterWork;
    const callerSlope =
        1n +
        4n * 513n * eventWork +
        32n * passWork +
        keyFixed +
        keyRow +
        2048n +
        meterWork;

    // Authentication literal frame parts and chain counts are independent
    // operands; all first signatures and the full tree are charged at each honestRegistrations.
    const auth = operands.authentication;
    const authenticationPrice = (
        bank: InstructionBank,
        counts: Partial<Record<keyof typeof auth.frames, bigint>>,
    ) => {
        const entries = Object.entries(counts) as [
            keyof typeof auth.frames,
            bigint,
        ][];
        const calls = sum(Object.values(counts));
        const inputs = sum(
            entries.map(([name, count]) => count * auth.frames[name].inputBits),
        );
        const permutations = sum(
            entries.map(
                ([name, count]) =>
                    count * (auth.frames[name].inputBits / 1088n + 1n),
            ),
        );
        const eventCount = 16n * ceiling(inputs, 64n) + 128n * calls + 65536n;
        const authenticationPreparation =
            480000n +
            2n *
                ceiling(240000n, metadataBits) *
                (gap(bank) * step(bank) + access());
        return {
            calls,
            work:
                events(bank, eventCount) +
                authenticationPreparation +
                38400n * permutations,
            traffic: inputs + calls * (1024n + 2n * metadataBits + 1n),
        };
    };
    const authTree = authenticationPrice(auth.tree, {
        secret: 12n * 131n,
        chain: 12n * 131n * 15n,
        leaf: 12n,
        unused: 4n,
        node: 15n,
    });
    const authSign = authenticationPrice(auth.signature, {
        message: 1n,
        secret: 131n,
        chain: 15n * 131n,
    });
    const authentication =
        honestRegistrations *
        (authTree.work +
            12n * authSign.work +
            queryCoefficient * (authTree.traffic + 12n * authSign.traffic));

    // Joined statements. The worst-path rows come from counted-loop analysis
    // over complete inlined programs; they include both challenge alternatives.
    const statementRows = operands.statements.map((row) => {
        const inputs = row.inputBits,
            outputs = row.outputBits,
            owned = row.ownedBits,
            fields = row.fieldOperations;
        const initialization =
            (64n * metadataBits + 16n) *
            (owned +
                inputs +
                outputs +
                table(row) +
                (row.registers + row.inputs) * metadataBits);
        const work =
            initialization +
            row.steps * step(row) +
            row.accesses * access(384n) +
            span(2n * (inputs + outputs), 64n) +
            (fields ? fieldConstructionWork + fields * fieldOperationWork : 0n);
        return {
            work,
            count: row.count,
            footprint: inputs + outputs + owned + table(row),
        };
    });
    const componentWork = sum(statementRows.map((row) => row.work * row.count)),
        footprint = sum(statementRows.map((row) => row.footprint * row.count));
    const sourceScan =
            21n *
            (honestRegistrations + 1n) *
            (sourceFamilies + 1n) *
            (16n * (gadgets + 20n + 32n) * degree * 2209n +
                2048n +
                8n * metadataBits),
        dispatch = 65536n * (gadgets + 20n + sourceFamilies + 64n);
    const outerStep =
        1024n * (65536n + 512n + 1n) * metadataBits + 256n * metadataBits ** 2n;
    const outer =
        span(16n * (sourceScan + footprint), 65536n) +
        (64n * metadataBits + 16n) *
            (sourceScan + footprint + dispatch * metadataBits) +
        dispatch * (outerStep + access());
    const statementOrigins =
            (origins.sourceStatements +
                origins.recipientKeyStatements +
                origins.proofScopes) *
                honestRegistrations +
            1n,
        statements = statementOrigins * (componentWork + outer),
        statementCalls = 3n * gadgets + (4n * degree) / 4096n + 8n;
    const statementTraffic =
            statementCalls *
            (1024n + degree * 1280n + 2n * metadataBits + 513n),
        statementRouting =
            statementOrigins * queryCoefficient * statementTraffic;

    const {
        rounds,
        units,
        prefix,
        roleBytes,
        framing,
        trees,
        leaves,
        inner,
        rowBits,
        inputBits,
        proofBits,
    } = reductionDescriptorGeometry;
    const retained =
        leaves * (rowBits + 1024n) +
        512n * (leaves + inner) +
        rounds * (2n * prefix + 1024n) +
        proofBits +
        inputBits +
        prefix +
        2n * leaves +
        (1n << 16n) * (units + 1n);
    const keyBits = 8n * (4n + 30n + 16n + roleBytes + 64n + prefix / 8n + 4n),
        first = 8n * ((maximumColumns + 1n) * 16n + 48n),
        second = 8n * ((maximumLookups + 2n) * 48n);
    const queryClasses = [
        [domain, first + 1024n + framing, 512n],
        [domain, second + 1024n + framing, 512n],
        [leaves - 2n * domain, 384n + 1024n + framing, 512n],
        [inner, 1024n + framing, 512n],
        [rounds, 2n * prefix + framing * (units + 1n), 512n],
        [rounds, prefix + framing, prefix],
        [rounds + 1n, keyBits, prefix],
        [2n, inputBits + framing * (units + 1n), 512n],
        [1n, proofBits + inputBits + framing, 512n],
    ];
    const descriptorQueries = sum(queryClasses.map((row) => row[0])),
        inputTraffic = sum(queryClasses.map((row) => row[0] * row[1])),
        outputTraffic = sum(queryClasses.map((row) => row[0] * row[2]));
    const descriptorTraffic =
        inputTraffic +
        outputTraffic +
        (2n * metadataBits + 513n) * descriptorQueries;
    const descriptorRouting =
        3n * honestRegistrations * queryCoefficient * descriptorTraffic;
    const serialization = sum(
        trees.map((size, index) => {
            const width = index === 0 ? first : index === 1 ? second : 384n,
                selected =
                    2n * pricedQueries < size ? 2n * pricedQueries : size,
                height = length(size) - 1n;
            const copying =
                ceiling(2n * size, metadataBits) +
                selected *
                    (ceiling(width, metadataBits) +
                        ceiling(1024n, metadataBits) +
                        height * ceiling(512n, metadataBits));
            return (
                table(banks.multiproof) +
                32n *
                    ((2n * pricedQueries + 1n) ** 2n +
                        (selected + 1n) * (height + 1n) +
                        copying +
                        1n) *
                    (gap(banks.multiproof) * step(banks.multiproof) + access())
            );
        }),
    );
    const shell =
        (1n << 24n) *
        (metadataBits + 1n) ** 2n *
        (inputTraffic +
            2n * outputTraffic +
            metadataBits * descriptorQueries +
            3n *
                honestRegistrations *
                (rounds + 1n) *
                (keyBits + prefix + metadataBits) +
            retained +
            inputBits +
            (1n << 16n) * (units + 1n));
    const descriptorPermutations = sum(
        queryClasses.map(
            ([count, input, output]) =>
                2n *
                count *
                (ceiling(input + 6n, 1088n) + ceiling(2n * output, 1088n) + 2n),
        ),
    );
    const polynomialBits =
        64n * 128n * units * degree + 384n * (24n * degree + 9n);
    const polynomialCore =
        fieldConstructionWork +
        4n *
            units *
            (fieldProgram(
                banks.transform,
                transform(degree, true),
                transformEvents(degree),
            ) +
                fieldProgram(
                    banks.product,
                    2n * transform(domain) + transform(domain, true) + domain,
                    3n * transformEvents(domain) + 128n * domain + 1024n,
                ) +
                fieldProgram(
                    banks.evaluation,
                    transform(domain) + 2n * domain,
                    transformEvents(domain) + 128n * domain + 1024n,
                )) +
        table(banks.linear) +
        (12n * 128n + 256n) * units * degree * fieldOperationWork +
        (64n * (12n * 128n + 256n) * units * degree + 128n) *
            (gap(banks.linear) * step(banks.linear) + access(384n)) +
        span(128n * units * degree * 384n, 48n * units) +
        (4n * units + 64n) * table(banks.roots) +
        256n *
            (4n * units + 64n) *
            (fieldOperationWork +
                64n * (gap(banks.roots) * step(banks.roots) + access(384n))) +
        8n * polynomialBits;
    const limbs = ceiling(1024n, 96n),
        fixedTerms =
            4n * gadgets * (limbs + 1n) +
            3n * gadgets +
            participants * (9n + 12n) +
            10n,
        publicPolynomials = 7n * gadgets + 3n * participants + 1n + 8n,
        mappingPairs =
            (participants + 4n) * maximumColumns +
            14n * gadgets +
            6n * participants +
            32n,
        totalTerms = fixedTerms + publicPolynomials;
    const affineFields =
        16n *
        (publicPolynomials * degree * (2n * ceiling(1024n, 16n) + 12n) +
            publicPolynomials * (6n * degree + 1n) +
            fixedTerms * (4n * degree + 64n) +
            4n * degree * (totalTerms + mappingPairs + 1n) +
            64n * totalTerms +
            maximumColumns * transform(degree, true) +
            21n *
                (1n +
                    transform(degree / 2n, true) +
                    2n * (length(degree) - 1n) +
                    degree) +
            21n * 8n * degree +
            128n *
                metadataBits *
                (fixedTerms +
                    publicPolynomials +
                    maximumColumns +
                    participants * 7n +
                    1n) +
            32n * participants * 7n * degree);
    const affineBanks = [
            banks.affine,
            banks.transform,
            banks.plaintext,
            banks.packing,
            banks.linear,
        ],
        affineEvents = 64n * affineFields + 21n * (64n * degree + 64n) + 128n;
    const constantGates = 65536n * 1025n ** 2n,
        affineBuild =
            (1n << 22n) *
            (metadataBits + 1n) ** 2n *
            (3n * (6n * extensionGates + constantGates) + 1n);
    const affineValues =
        4n *
            128n *
            (affineFields +
                (publicPolynomials +
                    fixedTerms +
                    2n * maximumColumns +
                    20n +
                    64n) *
                    degree +
                1n) +
        256n * 1025n ** 2n;
    const affineChunks =
        ceiling(affineValues + (1n << 46n), metadataBits) + 64n;
    const affineWork =
        affineBuild +
        affineFields * fieldOperationWork +
        affineEvents *
            maximum(affineBanks.map((bank) => gap(bank) * step(bank))) +
        sum(affineBanks.map(table)) +
        (sum(affineBanks.map((bank) => bank.registers)) + 64n) *
            metadataBits *
            (affineFields + 1n) +
        2n * affineChunks * (gap(banks.span) * step(banks.span) + access()) +
        (64n * metadataBits + 1n) * constantGates +
        64n * metadataBits;
    const descriptors =
        origins.proofScopes *
        honestRegistrations *
        (polynomialCore +
            affineWork +
            serialization +
            shell +
            38400n * descriptorPermutations +
            2n * (1024n * leaves + 1024n * rounds + prefix));

    const earlySourceRecovery =
        origins.earlySourceRecoveries *
        honestRegistrations *
        (events(
            banks.sourceRecovery,
            sourceRecoveryAllowance(degree).events,
            sourceRecoveryAllowance(degree).spanBits,
            false,
        ) +
            events(
                banks.sourceCoordinate,
                64n * degree * (1024n + 4n) * (16n + 2n) + 1024n,
                3n * degree * 16n * 64n +
                    32n * degree +
                    32n * 1024n +
                    4n * 16n * 64n,
                false,
            ) +
            events(
                banks.residue,
                residueEvents(degree, 2048n, 16n),
                degree * (2048n + 1024n) + 2048n,
            ));
    const width = 2n * 1024n + length(degree) + 64n,
        recoveryArithmeticConstruction =
            (1n << 22n) *
            (metadataBits + 1n) ** 2n *
            ((1n << 16n) * (width + 1n) ** 2n +
                (1n << 12n) * (width + 1n) ** 2n +
                1n);
    const recoveryRows = Object.fromEntries(
        Object.entries(operands.recovery).map(([name, row]) => {
            const input = row.inputBits,
                output = row.outputBits,
                owned = row.ownedBits;
            return [
                name,
                {
                    work:
                        fieldConstructionWork +
                        (64n * metadataBits + 16n) *
                            (owned +
                                input +
                                output +
                                table(row) +
                                row.registers * metadataBits) +
                        row.steps * step(row) +
                        row.events * access(384n) +
                        row.fieldOperations * fieldOperationWork +
                        span(2n * (input + output), row.passes),
                    footprint:
                        input +
                        output +
                        owned +
                        (32n * row.instructions + 2n * row.registers + 32n) *
                            metadataBits,
                },
            ];
        }),
    );
    const recoveryScan =
            21n *
            (honestRegistrations + 1n) *
            19n *
            ((selectedContributors + 3n) * degree * 2209n +
                2048n +
                8n * metadataBits),
        recoveryPreparation =
            (1n << 20n) *
            (metadataBits + 1n) ** 2n *
            (recoveryScan +
                sum(Object.values(recoveryRows).map((row) => row.footprint)) +
                1n);
    const recoveryBody =
        recoveryPreparation +
        maximum([
            recoveryRows.offer.work,
            recoveryRows.ballot.work + recoveryRows.auxiliary.work,
        ]);
    const firstPrescribedReleases =
            origins.firstPrescribedReleases *
            honestRegistrations *
            (recoveryPreparation + recoveryRows.release.work),
        alternativeRecovery = ceiling(
            recoveryBody,
            38400n * ((4n * degree) / 136n),
        );

    const publicTree = operands.publicTree,
        openingRehashes = 2n * pricedQueries,
        treeQueries = [
            [domain + openingRehashes, publicTree.leafBits],
            [domain - 1n, publicTree.nodeBits],
        ];
    const treeTraffic = sum(
            treeQueries.map(
                ([count, input]) =>
                    count * (input + 512n + 2n * metadataBits + 513n),
            ),
        ),
        treePermutations = sum(
            treeQueries.map(
                ([count, input]) =>
                    2n *
                    count *
                    (ceiling(input + 6n, 1088n) + ceiling(1024n, 1088n) + 2n),
            ),
        );
    const treeStorage =
        128n * maximumColumns * (degree + domain) +
        publicTree.nodeBitsTotal +
        publicTree.frameBits +
        384n * (4n * domain + 16n);
    const publicTreeUnit =
        fieldConstructionWork +
        maximumColumns *
            (table(banks.evaluation) +
                (transform(domain) + 2n * degree) * fieldOperationWork +
                (transformEvents(domain) + 128n * domain + 1024n) *
                    (gap(banks.evaluation) * step(banks.evaluation) +
                        access(384n))) +
        (maximumColumns + 1n) * table(banks.roots) +
        256n *
            (maximumColumns + 1n) *
            (fieldOperationWork +
                64n * (gap(banks.roots) * step(banks.roots) + access(384n))) +
        (1024n * maximumColumns * degree + 128n * maximumColumns * domain) *
            (outerStep + access()) +
        span(16n * treeStorage, 65536n) +
        (64n * metadataBits + 16n) * (treeStorage + table(publicTree)) +
        128n *
            (domain + openingRehashes) *
            (maximumColumns + 1024n + 128n) *
            (gap(publicTree) * step(publicTree) + access()) +
        64n *
            maximumColumns *
            degree *
            (fieldOperationWork + 128n * (outerStep + access())) +
        span(16n * 384n * maximumColumns * (degree + 1n), 65536n) +
        38400n * treePermutations +
        queryCoefficient * treeTraffic;
    const publicColumnTrees = 3n * honestRegistrations * publicTreeUnit;

    // Carried public jobs and arbitrary original query history remain maximumOriginalWork work.
    // Full preimage journals and both clean calls are charged by the slope.
    const journalAccess = access(4n * metadataBits),
        bitCost = 256n * (metadataBits + 1n) + 8n,
        rate = 1344n,
        history = 9n,
        minimumOriginalWork = 1n << 29n;
    const journalConstant =
        (1n << 24n) * (metadataBits + 1n) ** 4n +
        64n * journalAccess +
        64n * metadataBits * bitCost;
    const journalDirect =
        256n * (metadataBits + 1n) * journalAccess +
        (4n * (rate + 1n) + 64n * metadataBits) * bitCost +
        queryCoefficient;
    const journalPermutation =
        (256n * (metadataBits + 1n) + 32n * rate * history) * journalAccess +
        (4n * (rate + 2n * rate * history) + 64n * metadataBits) * bitCost +
        queryCoefficient * (2n * rate * history + 2n * metadataBits + 1n);
    const carriedHash = ceiling(
        journalConstant * 38400n +
            journalDirect * minimumOriginalWork * 38400n +
            journalPermutation * minimumOriginalWork,
        minimumOriginalWork * 38400n,
    );
    const maskCells =
            (2n * pricedQueries + 1n) *
                (maximumColumns + 3n * maximumLookups + 7n) +
            9n * 131072n,
        maskCalls = maximumColumns + maximumLookups + 4n,
        samplerGates = 1n << 14n;
    const masks = ceiling(
        2n * (3n * metadataBits + 8n) * samplerGates +
            2n * (1n << 12n) +
            3n *
                (maskCells *
                    (64n * metadataBits * (samplerGates + 1n) + samplerGates) +
                    (maskCells + maskCalls) * 512n * metadataBits ** 2n),
        minimumOriginalWork,
    );
    const fixed = {
        caller: callerFixed,
        commonInitialization,
        authentication,
        statements,
        statementRouting,
        descriptors,
        descriptorRouting,
        earlySourceRecovery,
        recoveryArithmeticConstruction,
        firstPrescribedReleases,
        publicColumnTrees,
    };
    const slope = {
        caller: callerSlope,
        carriedHash,
        alternativeRecovery,
        masks,
    };
    const fixedExternalQueries =
        2n *
            (origins.proofScopes * honestRegistrations * descriptorQueries +
                statementOrigins * statementCalls +
                honestRegistrations * (authTree.calls + 12n * authSign.calls)) +
        6n * honestRegistrations * (2n * domain - 1n + openingRehashes);
    const maximumOriginalWork = (1n << 128n) - 1n,
        E = 2052n * maximumOriginalWork + 1539n * factoryObjects,
        P = 32n * maximumOriginalWork + 24n * factoryObjects,
        U = 8n * E;
    const originalMemory =
        (1n + (4n * metadataBits + 1n) * U) * 4n * metadataBits +
        (U + 1n) * 32n * metadataBits +
        4n * metadataBits ** 2n +
        P * payload +
        4n * metadataBits * 257n * maximumOriginalWork +
        4096n * metadataBits +
        (recipeWords + 2n * registerWords + banks.caller.registers) *
            metadataBits *
            E +
        65536n * 64n * metadataBits +
        (meterTable + meterWords * metadataBits) * (maximumOriginalWork + 1n);
    return {
        fixed,
        slope,
        fixedWork: sum(Object.values(fixed)),
        workSlope: sum(Object.values(slope)),
        fixedExternalQueries,
        originalMemory,
        queryCoefficient,
        statementRows,
        recoveryRows,
        descriptorParts: {
            polynomialCore,
            affineWork,
            serialization,
            shell,
            oracle: 38400n * descriptorPermutations,
            coins: 2n * (1024n * leaves + 1024n * rounds + prefix),
        },
    };
};
