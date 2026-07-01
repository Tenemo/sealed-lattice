export { protocolHashPattern } from '../common-fields.js';
export { setupTransportChunkSizeBytes } from '../vss-coefficient-commitments/constants-and-types.js';

export const setupTransportStorageQuotaBytes = 2_147_483_648;
export const setupTransportLargestSingleBufferBytes = 1_572_864;
export const setupTransportCopyCountLimit = 2;
export const setupTransportStreamOrder = 'ascending-chunk-index';
export const setupTransportResumePolicy = 'chunk-index-checkpointed-by-hash';
export const setupTransportLazyLoadingPolicy =
    'root-addressed-large-object-loading';
export const setupTransportedObjectLoadingPolicy =
    'stream-verified-before-object-use';
