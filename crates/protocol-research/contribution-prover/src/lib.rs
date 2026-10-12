#![deny(unsafe_op_in_unsafe_fn)]
#[path = "contribution-session.rs"]
pub mod contribution_session;

use protocol_foundations::roster::RetainedContributionContext;
use supported_profile::{Profile, relation::setup_relation};
use word_proof::bridge::Error;
use word_proof::bridge::first_checkpoint;

/// Opens only the public checkpoint header under the original owner's
/// retained context. The importer still authenticates every sealed record
/// and recipient key before restoring the unfinished proof.
pub fn import_checkpoint(
    context: &RetainedContributionContext,
    position: usize,
    bytes: &[u8],
) -> Result<first_checkpoint::Import, Error> {
    let prefix = bytes.get(..128).ok_or(Error::Operation)?;
    let import = first_checkpoint::Import::begin(&bytes[128..])?;
    let expected = context
        .checkpoint_role(prefix, position, import.profile())
        .map_err(|_| Error::Operation)?;
    if import.role() != expected || import.input_hashes().len() != context.profile().participants()
    {
        return Err(Error::Operation);
    }
    Ok(import)
}

/// The longest checkpoint header of a profile's contribution and each of its
/// sealed checkpoint records' lengths, in record order.
pub fn checkpoint_layout(profile: Profile) -> (usize, Vec<usize>) {
    (
        first_checkpoint::maximum_header_bytes(profile),
        first_checkpoint::record_lengths(&setup_relation(profile)),
    )
}
