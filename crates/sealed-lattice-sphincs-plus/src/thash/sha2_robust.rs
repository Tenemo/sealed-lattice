use crate::{context::SpxCtx, params::*, sha2::*, utils::*};

/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
pub fn thash<const N: usize>(out: &mut [u8], input: Option<&[u8]>, ctx: &SpxCtx, addr: &[u32]) {
    if N > 1 {
        thash_512::<N>(out, input, ctx, addr);
        return;
    }
    const MAX_INPUT_BYTE_LENGTH: usize = SPX_WOTS_BYTES;
    let input_byte_length = N * SPX_N;
    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + MAX_INPUT_BYTE_LENGTH];
    let mut bitmask = [0u8; MAX_INPUT_BYTE_LENGTH];
    let mut sha2_state = [0u8; 40];
    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    buf[SPX_N..SPX_N + SPX_SHA256_ADDR_BYTES]
        .copy_from_slice(&address_to_bytes(addr)[..SPX_SHA256_ADDR_BYTES]);
    mgf1_256(&mut bitmask[..input_byte_length], input_byte_length, &buf);

    // Retrieve precomputed state containing pub_seed
    sha2_state.copy_from_slice(&ctx.state_seeded[..40]);

    for i in 0..input_byte_length {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = input.unwrap_or(out)[i] ^ bitmask[i];
    }

    sha256_inc_finalize(
        &mut outbuf,
        &mut sha2_state,
        &buf[SPX_N..],
        SPX_SHA256_ADDR_BYTES + input_byte_length,
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

pub fn thash_512<const N: usize>(out: &mut [u8], input: Option<&[u8]>, ctx: &SpxCtx, addr: &[u32]) {
    const MAX_INPUT_BYTE_LENGTH: usize = SPX_WOTS_BYTES;
    let input_byte_length = N * SPX_N;
    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut bitmask = [0u8; MAX_INPUT_BYTE_LENGTH];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + MAX_INPUT_BYTE_LENGTH];
    let mut sha2_state = [0u8; 72];

    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    buf[SPX_N..SPX_N + SPX_SHA256_ADDR_BYTES]
        .copy_from_slice(&address_to_bytes(addr)[..SPX_SHA256_ADDR_BYTES]);
    mgf1_512(&mut bitmask[..input_byte_length], input_byte_length, &buf);

    // Retrieve precomputed state containing pub_seed
    sha2_state[..72].copy_from_slice(&ctx.state_seeded_512);

    // TODO: copy from slice
    for i in 0..input_byte_length {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = input.unwrap_or(out)[i] ^ bitmask[i];
    }

    sha512_inc_finalize(
        &mut outbuf,
        &mut sha2_state,
        &buf[SPX_N..],
        SPX_SHA256_ADDR_BYTES + input_byte_length,
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}
