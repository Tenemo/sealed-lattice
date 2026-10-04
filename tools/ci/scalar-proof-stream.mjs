/** @typedef {{bytes:number,sha512:string}} Proof */
/** @typedef {{name:string,proof:number,context:number,expected?:number,headerCut?:number,truncate?:number,append?:boolean,change?:boolean,sourceControl?:'missing-all'|'missing-second'|'first-slot-one'|'repeated-slot'|'reordered'|'duplicate'|'truncated'|'changed'}} Probe */
/** @typedef {{memory:WebAssembly.Memory,inputCapacity():number,inputPointer():number,headerLength():number,begin(context:number,length:number):number,push(length:number):number,finish():number}} StreamApi */
/** @param {boolean} condition @param {string} message */
export const requireProofCondition = (condition, message) => {
    if (!condition) throw new Error(message);
};

// The owning Wasm verifier returns every cryptographic refusal. Transport and
// ABI errors throw and cannot be counted as successful hostile-proof checks.
/** @param {{api:StreamApi,proof:Proof,probe:Probe,readExact:(length:number,position:number)=>Promise<Uint8Array>}} input */
export const streamScalarProof = async ({ api, proof, probe, readExact }) => {
    let longestCallMilliseconds = 0;
    /** @param {()=>number} invoke */
    const call = (invoke) => {
        const started = performance.now();
        try {
            return invoke();
        } finally {
            longestCallMilliseconds = Math.max(
                longestCallMilliseconds,
                performance.now() - started,
            );
        }
    };
    const capacity = api.inputCapacity();
    const headerLength = api.headerLength();
    requireProofCondition(
        Number.isSafeInteger(capacity) &&
            capacity > 0 &&
            capacity <= 1_048_576 &&
            Number.isSafeInteger(headerLength) &&
            headerLength > 0 &&
            headerLength <= capacity,
        'The verifier input layout exceeds its bound.',
    );
    let maximumLinearMemoryBytes = api.memory.buffer.byteLength;
    /** @param {Uint8Array} bytes */
    const transfer = (bytes) => {
        const pointer = api.inputPointer();
        requireProofCondition(
            Number.isSafeInteger(pointer) &&
                pointer >= 0 &&
                bytes.length <= capacity &&
                pointer + bytes.length <= api.memory.buffer.byteLength,
            'The verifier input lies outside its memory.',
        );
        new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes);
    };
    /** @param {number} length @param {number} position */
    const read = async (length, position) => {
        requireProofCondition(
            length > 0 && length <= capacity,
            'A proof read exceeds the input bound.',
        );
        const bytes = await readExact(length, position);
        requireProofCondition(
            bytes instanceof Uint8Array && bytes.length === length,
            'A bounded proof read returned the wrong length.',
        );
        return bytes;
    };
    const sample = () => {
        maximumLinearMemoryBytes = Math.max(
            maximumLinearMemoryBytes,
            api.memory.buffer.byteLength,
        );
    };
    const started = performance.now();
    let suppliedBytes = 0;
    const readHeader = headerLength - (probe.headerCut ?? 0);
    transfer(await read(readHeader, 0));
    let code = call(() => api.begin(probe.context, readHeader));
    suppliedBytes += readHeader;
    sample();
    const end = proof.bytes - (probe.truncate ?? 0);
    for (let offset = headerLength; code === 0 && offset < end;) {
        const length = Math.min(capacity, end - offset);
        const bytes = await read(length, offset);
        if (probe.change && offset + length === end) bytes[length - 1] ^= 1;
        transfer(bytes);
        code = call(() => api.push(length));
        suppliedBytes += length;
        offset += length;
        sample();
    }
    if (code === 0 && probe.append) {
        transfer(new Uint8Array([0]));
        code = call(() => api.push(1));
        suppliedBytes++;
        sample();
    }
    if (code === 0) code = call(() => api.finish());
    sample();
    return {
        name: probe.name,
        code,
        suppliedBytes,
        maximumLinearMemoryBytes,
        longestCallMilliseconds,
        milliseconds: performance.now() - started,
        proofSha512: proof.sha512,
    };
};
