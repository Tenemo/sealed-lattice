use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_confirmation},
    poll::{VerifiedPoll, verify_poll},
    roster_authentication::verify_roster_proposal,
    roster_input::RosterInputVerifier,
};
use setup_aggregate::{
    CHUNK_BYTES, ModulusKind,
    verified::{SetupAggregator, VerifiedSetupAggregate},
};
use std::{
    fs,
    io::{self, Read},
    path::Path,
    sync::Arc,
};

pub fn bounded(file: impl AsRef<Path>, limit: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(file)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(io::Error::other("Oversized fixture control."));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("Growing fixture control."));
    }
    Ok(bytes)
}
pub fn required<T, E: std::fmt::Debug>(value: Result<T, E>) -> io::Result<T> {
    value.map_err(|error| io::Error::other(format!("Public verification refused: {error:?}")))
}
fn packet(bytes: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let prefix = bytes
        .get(..4)
        .ok_or_else(|| io::Error::other("Short signature packet."))?;
    let length = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return Err(io::Error::other("Signature packet shape."));
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
fn feed(
    file: impl AsRef<Path>,
    buffer: &mut [u8],
    mut receive: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut file = fs::File::open(file)?;
    loop {
        let length = file.read(buffer)?;
        if length == 0 {
            return Ok(());
        }
        receive(&buffer[..length])?;
    }
}
pub fn setup(arguments: &[String]) -> io::Result<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
    let context = bounded(&arguments[0], 128)?;
    if context.len() != 128 {
        return Err(io::Error::other("Context length."));
    }
    let definition = bounded(&arguments[1], 1 << 20)?;
    let signature = bounded(&arguments[2], 3309)?;
    let poll = Arc::new(required(verify_poll(
        context[..64].try_into().unwrap(),
        context[64..].try_into().unwrap(),
        &definition,
        &signature,
    ))?);
    let mut control = context;
    control.extend(10u16.to_le_bytes());
    control.extend((definition.len() as u32).to_le_bytes());
    control.extend(definition);
    control.extend(signature);
    let mut roster = required(RosterInputVerifier::new(&control))?;
    let mut buffer = vec![0; CHUNK_BYTES];
    for (position, directory) in arguments[6..16].iter().enumerate() {
        let directory = Path::new(directory);
        let header = bounded(directory.join("registration-header.bin"), 4096)?;
        let signature = bounded(directory.join("signature.bin"), 3309)?;
        let mut control = Vec::from((position as u16).to_le_bytes());
        control.extend((header.len() as u32).to_le_bytes());
        control.extend(header);
        control.extend(signature);
        required(roster.begin_record(&control))?;
        feed(directory.join("polynomial-01.bin"), &mut buffer, |bytes| {
            required(roster.push_key(bytes))
        })?;
        required(roster.finish_key())?;
        feed(directory.join("proof.bin"), &mut buffer, |bytes| {
            required(roster.push_proof(bytes))
        })?;
        required(roster.finish_record())?;
    }
    let proposal = Arc::new(required(verify_roster_proposal(
        required(roster.finish())?,
        &bounded(&arguments[3], 3309)?,
    ))?);
    let batch = bounded(&arguments[4], 1 << 20)?;
    if batch.get(..4) != Some(10u32.to_le_bytes().as_slice()) {
        return Err(io::Error::other("Inventory count."));
    }
    let mut offset = 4;
    let mut confirmations = Vec::new();
    for _ in 0..10 {
        let prefix = batch
            .get(offset..offset + 4)
            .ok_or_else(|| io::Error::other("Inventory truncated."))?;
        let length = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
        if length > 1024 {
            return Err(io::Error::other("Inventory packet bound."));
        }
        let bytes = batch
            .get(offset..offset + 4 + length + 3309)
            .ok_or_else(|| io::Error::other("Inventory truncated."))?;
        let (body, signature) = packet(bytes)?;
        confirmations.push(required(verify_confirmation(&proposal, body, signature))?);
        offset += bytes.len();
    }
    if offset != batch.len() {
        return Err(io::Error::other("Inventory trailing bytes."));
    }
    let inventory = Arc::new(required(CommitmentInventory::new(proposal, confirmations))?);
    let mut aggregate = required(SetupAggregator::new(inventory))?;
    let indices: Vec<_> = (0..75)
        .filter(|index| ModulusKind::for_contribution_polynomial(*index).is_some())
        .collect();
    for position in 0..10 {
        let opening = bounded(
            Path::new(&arguments[16 + position]).join("opening.bin"),
            4 + 1024 + 3309,
        )?;
        let header = bounded(
            Path::new(&arguments[16 + position]).join("body-header.bin"),
            12,
        )?;
        let (body, signature) = packet(&opening)?;
        let mut lookahead = [0; 4004];
        fs::File::open(&arguments[36 + position])?.read_exact(&mut lookahead)?;
        required(aggregate.begin(body, signature, &header, &lookahead))?;
        for index in &indices {
            let kind = ModulusKind::for_contribution_polynomial(*index).unwrap();
            let length = kind.degree() * kind.coefficient_bytes();
            let chunk = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let name = format!("polynomial-{index:02}.bin");
            let mut input = fs::File::open(Path::new(&arguments[26 + position]).join(&name))?;
            if input.metadata()?.len() != length as u64 {
                return Err(io::Error::other("Body polynomial length."));
            }
            let mut previous = if position == 0 {
                None
            } else {
                Some(fs::File::open(
                    Path::new(&arguments[5])
                        .join(format!("after-participant-{}", position - 1))
                        .join(&name),
                )?)
            };
            if let Some(file) = previous.as_ref()
                && file.metadata()?.len() != length as u64
            {
                return Err(io::Error::other("Cached polynomial length."));
            }
            let mut prior = vec![0; chunk];
            let mut offset = 0;
            while offset < length {
                let used = chunk.min(length - offset);
                input.read_exact(&mut buffer[..used])?;
                if let Some(previous) = previous.as_mut() {
                    previous.read_exact(&mut prior[..used])?;
                }
                required(aggregate.polynomial(
                    *index,
                    offset,
                    &buffer[..used],
                    &mut prior[..used],
                ))?;
                offset += used;
            }
        }
        let mut offset = 0;
        feed(&arguments[36 + position], &mut buffer, |bytes| {
            required(aggregate.proof(offset, bytes))?;
            offset += bytes.len();
            Ok(())
        })?;
        required(aggregate.finish_contribution())?;
        println!("Verified original setup position {position}");
    }
    Ok((poll, Arc::new(required(aggregate.finish())?)))
}
