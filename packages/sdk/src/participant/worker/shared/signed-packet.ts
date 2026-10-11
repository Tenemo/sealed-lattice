import { concatenate, readUnsigned32, unsigned32 } from './bytes.js';

// A body and its signature as the module frames them: the body's length as a
// 32-bit word, the body, then the signature.
export type SignedPacket = Readonly<{
    body: Uint8Array;
    signature: Uint8Array;
}>;

export const encodeSignedPacket = (packet: SignedPacket) =>
    concatenate(unsigned32(packet.body.length), packet.body, packet.signature);

// Splits a framed packet whose signature has the given length, or returns
// nothing for any other framing.
export const decodeSignedPacket = (
    bytes: Uint8Array,
    signatureBytes: number,
): SignedPacket | undefined =>
    bytes.length >= 4 &&
    bytes.length === 4 + readUnsigned32(bytes, 0) + signatureBytes
        ? {
              body: bytes.slice(4, bytes.length - signatureBytes),
              signature: bytes.slice(bytes.length - signatureBytes),
          }
        : undefined;
