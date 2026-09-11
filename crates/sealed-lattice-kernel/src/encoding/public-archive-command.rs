use super::{BinaryReader, BinaryWriter, CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    FoundationSchemaError, Hash512,
    public_archive::{
        ArchivePolicy, ArchiveRecord, ArchiveReference, MAXIMUM_ARCHIVE_DEPENDENCIES,
        MAXIMUM_ARCHIVE_PAYLOAD_BYTES, MAXIMUM_ARCHIVE_REPLICAS,
    },
};

fn error(error: FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.message)
}

fn hash(reader: &mut BinaryReader<'_>) -> CanonicalResult<Hash512> {
    Ok(Hash512::from_bytes(
        reader.read_exact(64)?.try_into().map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "archive identity length",
            )
        })?,
    ))
}

fn reference(reader: &mut BinaryReader<'_>) -> CanonicalResult<ArchiveReference> {
    Ok(ArchiveReference {
        identity: hash(reader)?,
        byte_length: reader.read_u64()?,
    })
}

fn count(reader: &mut BinaryReader<'_>, maximum: usize) -> CanonicalResult<usize> {
    let count = usize::from(reader.read_u16()?);
    if count > maximum {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "archive count exceeds its bound",
        ));
    }
    Ok(count)
}

fn policy(reader: &mut BinaryReader<'_>) -> CanonicalResult<ArchivePolicy> {
    let fault_bound = reader.read_u16()?;
    let count = count(reader, MAXIMUM_ARCHIVE_REPLICAS)?;
    let mut verification_keys = Vec::with_capacity(count);
    for _ in 0..count {
        verification_keys.push(
            reader
                .read_exact(fips204::ml_dsa_65::PK_LEN)?
                .try_into()
                .map_err(|_| {
                    CanonicalError::new(CanonicalErrorCode::MalformedLength, "archive key length")
                })?,
        );
    }
    Ok(ArchivePolicy {
        fault_bound,
        verification_keys,
    })
}

pub(super) fn run(command: u8, reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let mut response = BinaryWriter::new();
    match command {
        9 => {
            let context = hash(reader)?;
            let purpose = reader.read_string()?;
            if purpose.len() > 128 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "archive purpose exceeds its bound",
                ));
            }
            let count = count(reader, MAXIMUM_ARCHIVE_DEPENDENCIES)?;
            let mut dependencies = Vec::with_capacity(count);
            for _ in 0..count {
                dependencies.push(reference(reader)?);
            }
            let payload = reader.read_bytes()?;
            if payload.len() > MAXIMUM_ARCHIVE_PAYLOAD_BYTES {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "archive payload exceeds its bound",
                ));
            }
            let bytes = ArchiveRecord {
                context,
                purpose: purpose.to_owned(),
                dependencies,
                payload: payload.to_vec(),
            }
            .encode()
            .map_err(error)?;
            response.write_fixed(ArchiveRecord::identity(&bytes).map_err(error)?.as_bytes())?;
            response.write_bytes(&bytes)?;
        }
        10 => {
            let context = hash(reader)?;
            let reference = reference(reader)?;
            let bytes = reader.read_bytes()?;
            reference.validate().map_err(error)?;
            if bytes.len() as u64 != reference.byte_length
                || ArchiveRecord::identity(bytes).map_err(error)? != reference.identity
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "archive bytes do not match their reference",
                ));
            }
            let record = ArchiveRecord::decode(bytes, context).map_err(error)?;
            response.write_string(&record.purpose)?;
            response.write_fixed(&(record.dependencies.len() as u16).to_le_bytes())?;
            for dependency in record.dependencies {
                response.write_fixed(dependency.identity.as_bytes())?;
                response.write_fixed(&dependency.byte_length.to_le_bytes())?;
            }
            response.write_bytes(&record.payload)?;
        }
        11 | 12 => {
            let policy = policy(reader)?;
            let context = hash(reader)?;
            let root = reference(reader)?;
            if command == 11 {
                response.write_fixed(
                    policy
                        .receipt_message(context, &root)
                        .map_err(error)?
                        .as_bytes(),
                )?;
            } else {
                let count = count(reader, MAXIMUM_ARCHIVE_REPLICAS)?;
                let mut acknowledgements = Vec::with_capacity(count);
                for _ in 0..count {
                    let position = reader.read_u16()?;
                    let signature = reader.read_bytes()?;
                    if signature.len() == fips204::ml_dsa_65::SIG_LEN {
                        acknowledgements.push((position, signature.to_vec()));
                    }
                }
                let signers = policy
                    .verify_acknowledgements(context, &root, &acknowledgements)
                    .map_err(error)?;
                response.write_fixed(&(signers.len() as u16).to_le_bytes())?;
                for signer in signers {
                    response.write_fixed(&signer.to_le_bytes())?;
                }
            }
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidEnum,
                "unknown archive command",
            ));
        }
    }
    Ok(response.into_bytes())
}
