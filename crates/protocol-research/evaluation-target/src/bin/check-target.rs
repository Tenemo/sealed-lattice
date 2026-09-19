use ballot_proof::{
    body::SignedBallotVerifier,
    publication::PublicationContext,
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use evaluation_target::target::{ClassifiedClosedInventory, Error, PublicInputs, WorkingStore};
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_confirmation},
    roster_authentication::verify_roster_proposal,
    roster_input::RosterInputVerifier,
};
use rns_arithmetic_probe::ranking::{Ciphertext, DEGREE};
use setup_aggregate::{CHUNK_BYTES, ModulusKind, verified::SetupAggregator};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

#[path = "../public-completion-check.rs"]
mod completion;

#[derive(Default)]
struct Work {
    read_bytes: u64,
    written_bytes: u64,
    retained_bytes: u64,
    peak_retained_bytes: u64,
}
impl Work {
    fn read(&mut self, file: &mut File, bytes: &mut [u8]) -> io::Result<()> {
        file.read_exact(bytes)?;
        self.read_bytes += bytes.len() as u64;
        Ok(())
    }
    fn save(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.written(bytes.len());
        Ok(())
    }
    fn written(&mut self, count: usize) {
        self.written_bytes += count as u64;
        self.retained_bytes += count as u64;
        self.peak_retained_bytes = self.peak_retained_bytes.max(self.retained_bytes);
    }
    fn remove(&mut self, path: &Path) -> io::Result<()> {
        let length = fs::metadata(path)?.len();
        fs::remove_file(path)?;
        self.retained_bytes -= length;
        Ok(())
    }
}
fn refusal(value: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("Public verification refused: {value:?}"))
}
fn bounded(path: impl AsRef<Path>, limit: usize, work: &mut Work) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(refusal)?;
    if length > limit {
        return Err(refusal("oversized control"));
    }
    let mut bytes = vec![0; length];
    work.read(&mut file, &mut bytes)?;
    end(&mut file)?;
    Ok(bytes)
}
fn end(file: &mut File) -> io::Result<()> {
    if file.read(&mut [0])? != 0 {
        return Err(refusal("trailing bytes"));
    }
    Ok(())
}
fn packet(bytes: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| refusal("packet"))?
            .try_into()
            .map_err(refusal)?,
    ) as usize;
    if length > 2048 || bytes.len() != 4 + length + 3309 {
        return Err(refusal("packet length"));
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
fn polynomial_name(index: usize) -> String {
    format!("polynomial-{index:02}.bin")
}

struct Operands<'a> {
    aggregate: PathBuf,
    ballots: &'a [String],
    work: &'a mut Work,
}
struct CountedReader<'a> {
    file: File,
    work: &'a mut Work,
}
impl Read for CountedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(bytes)?;
        self.work.read_bytes += count as u64;
        Ok(count)
    }
}
impl PublicInputs for Operands<'_> {
    fn aggregate(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error> {
        Ok(Box::new(CountedReader {
            file: File::open(self.aggregate.join(polynomial_name(index)))
                .map_err(|_| Error::PublicInput)?,
            work: self.work,
        }))
    }
    fn ballot(&mut self, author: usize) -> Result<Box<dyn Read + '_>, Error> {
        Ok(Box::new(CountedReader {
            file: File::open(self.ballots.get(author).ok_or(Error::PublicInput)?)
                .map_err(|_| Error::PublicInput)?,
            work: self.work,
        }))
    }
}
struct Spool {
    directory: PathBuf,
    indices: BTreeSet<usize>,
    work: Work,
}
impl WorkingStore for Spool {
    fn put(&mut self, index: usize, value: &Ciphertext) -> Result<(), Error> {
        if !self.indices.insert(index) {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::with_capacity(2 * DEGREE * 112);
        for polynomial in value {
            for coefficient in polynomial {
                for word in coefficient {
                    bytes.extend(word.to_le_bytes());
                }
            }
        }
        self.work
            .save(&self.directory.join(format!("{index}.bin")), &bytes)
            .map_err(|_| Error::Storage)
    }
    fn get(&mut self, index: usize) -> Result<Ciphertext, Error> {
        let bytes = bounded(
            self.directory.join(format!("{index}.bin")),
            2 * DEGREE * 112,
            &mut self.work,
        )
        .map_err(|_| Error::Storage)?;
        if bytes.len() != 2 * DEGREE * 112 {
            return Err(Error::Storage);
        }
        Ok(std::array::from_fn(|part| {
            bytes[part * DEGREE * 112..(part + 1) * DEGREE * 112]
                .chunks_exact(112)
                .map(|coefficient| {
                    std::array::from_fn(|word| {
                        u64::from_le_bytes(coefficient[word * 8..word * 8 + 8].try_into().unwrap())
                    })
                })
                .collect()
        }))
    }
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        if self.indices.remove(&index) {
            self.work
                .remove(&self.directory.join(format!("{index}.bin")))
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err(refusal(
            "supply public path manifest, new result directory and optional public completion directory",
        ));
    }
    let started = Instant::now();
    let mut work = Work::default();
    let manifest = bounded(&arguments[0], 65536, &mut work)?;
    let paths: Vec<_> = std::str::from_utf8(&manifest)
        .map_err(refusal)?
        .lines()
        .map(str::to_owned)
        .collect();
    if paths.len() != 60 || paths.iter().any(String::is_empty) {
        return Err(refusal("path manifest"));
    }
    let output = Path::new(&arguments[1]);
    fs::create_dir(output)?;
    let scratch = Path::new(&paths[5]);
    fs::create_dir(scratch)?;
    let mut control = bounded(&paths[0], 128, &mut work)?;
    if control.len() != 128 {
        return Err(refusal("context length"));
    }
    let definition = bounded(&paths[1], 1 << 20, &mut work)?;
    control.extend(10u16.to_le_bytes());
    control.extend((definition.len() as u32).to_le_bytes());
    control.extend(definition);
    control.extend(bounded(&paths[2], 3309, &mut work)?);
    let mut roster = RosterInputVerifier::new(&control).map_err(refusal)?;
    let mut buffer = vec![0; CHUNK_BYTES];
    for (position, directory) in paths[6..16].iter().enumerate() {
        let directory = Path::new(directory);
        let header = bounded(directory.join("registration-header.bin"), 4096, &mut work)?;
        let mut control = Vec::from((position as u16).to_le_bytes());
        control.extend((header.len() as u32).to_le_bytes());
        control.extend(header);
        control.extend(bounded(directory.join("signature.bin"), 3309, &mut work)?);
        roster.begin_record(&control).map_err(refusal)?;
        for (ordinal, name) in ["polynomial-01.bin", "proof.bin"].into_iter().enumerate() {
            let mut file = File::open(directory.join(name))?;
            loop {
                let count = file.read(&mut buffer)?;
                work.read_bytes += count as u64;
                if count == 0 {
                    break;
                }
                if ordinal == 0 {
                    roster.push_key(&buffer[..count])
                } else {
                    roster.push_proof(&buffer[..count])
                }
                .map_err(refusal)?;
            }
            if ordinal == 0 {
                roster.finish_key()
            } else {
                roster.finish_record()
            }
            .map_err(refusal)?;
        }
    }
    let proposal = roster.finish().map_err(refusal)?;
    let poll = Arc::new(roster.into_poll());
    let proposal = Arc::new(
        verify_roster_proposal(proposal, &bounded(&paths[3], 3309, &mut work)?).map_err(refusal)?,
    );
    let batch = bounded(&paths[4], 1 << 20, &mut work)?;
    if batch.get(..4) != Some(10u32.to_le_bytes().as_slice()) {
        return Err(refusal("confirmation count"));
    }
    let mut offset = 4;
    let mut confirmations = Vec::new();
    for _ in 0..10 {
        let length = u32::from_le_bytes(
            batch
                .get(offset..offset + 4)
                .ok_or_else(|| refusal("confirmation frame"))?
                .try_into()
                .map_err(refusal)?,
        ) as usize;
        let bytes = batch
            .get(offset..offset + 4 + length + 3309)
            .ok_or_else(|| refusal("confirmation frame"))?;
        let (body, signature) = packet(bytes)?;
        confirmations.push(verify_confirmation(&proposal, body, signature).map_err(refusal)?);
        offset += bytes.len();
    }
    if offset != batch.len() {
        return Err(refusal("confirmation suffix"));
    }
    let inventory = Arc::new(CommitmentInventory::new(proposal, confirmations).map_err(refusal)?);
    let mut aggregator = SetupAggregator::new(inventory).map_err(refusal)?;
    let indices: Vec<_> = (0..75)
        .filter(|index| ModulusKind::for_contribution_polynomial(*index).is_some())
        .collect();
    for position in 0..10 {
        let stage = scratch.join(format!("aggregate-{position}"));
        fs::create_dir(&stage)?;
        let opening = bounded(
            Path::new(&paths[16 + position]).join("opening.bin"),
            4 + 2048 + 3309,
            &mut work,
        )?;
        let header = bounded(
            Path::new(&paths[16 + position]).join("body-header.bin"),
            12,
            &mut work,
        )?;
        let mut proof = File::open(&paths[36 + position])?;
        let mut proof_header = [0; 4004];
        work.read(&mut proof, &mut proof_header)?;
        let (body, signature) = packet(&opening)?;
        aggregator
            .begin(body, signature, &header, &proof_header)
            .map_err(refusal)?;
        for index in &indices {
            let kind = ModulusKind::for_contribution_polynomial(*index).unwrap();
            let length = kind.degree() * kind.coefficient_bytes();
            let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let name = polynomial_name(*index);
            let mut incoming = File::open(Path::new(&paths[26 + position]).join(&name))?;
            let mut prior = if position == 0 {
                None
            } else {
                Some(File::open(
                    scratch
                        .join(format!("aggregate-{}", position - 1))
                        .join(&name),
                )?)
            };
            let mut destination = BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(stage.join(&name))?,
            );
            let mut previous = vec![0; capacity];
            let mut offset = 0;
            while offset < length {
                let count = capacity.min(length - offset);
                work.read(&mut incoming, &mut buffer[..count])?;
                if let Some(prior) = prior.as_mut() {
                    work.read(prior, &mut previous[..count])?;
                }
                aggregator
                    .polynomial(*index, offset, &buffer[..count], &mut previous[..count])
                    .map_err(refusal)?;
                destination.write_all(&previous[..count])?;
                work.written(count);
                offset += count;
            }
            end(&mut incoming)?;
            if let Some(prior) = prior.as_mut() {
                end(prior)?;
            }
            destination.flush()?;
            destination.get_ref().sync_all()?;
        }
        let mut proof = File::open(&paths[36 + position])?;
        let mut offset = 0;
        loop {
            let count = proof.read(&mut buffer)?;
            work.read_bytes += count as u64;
            if count == 0 {
                break;
            }
            aggregator
                .proof(offset, &buffer[..count])
                .map_err(refusal)?;
            offset += count;
        }
        aggregator.finish_contribution().map_err(refusal)?;
        if position > 0 {
            for index in &indices {
                work.remove(
                    &scratch
                        .join(format!("aggregate-{}", position - 1))
                        .join(polynomial_name(*index)),
                )?;
            }
        }
        println!("Verified setup contribution {position}");
    }
    let setup = Arc::new(aggregator.finish().map_err(refusal)?);
    let setup_milliseconds = started.elapsed().as_secs_f64() * 1000.0;
    let publication = PublicationContext::new(poll.clone(), setup.clone()).map_err(refusal)?;
    let close = bounded(&paths[46], 4 + 2048 + 3309, &mut work)?;
    let (body, signature) = packet(&close)?;
    let close = publication
        .authenticate_close(body, signature)
        .map_err(refusal)?;
    let selection = bounded(&paths[48], 62, &mut work)?;
    if selection.len() != 62 {
        return Err(refusal("carrier selection length"));
    }
    let carrier_count = u16::from_le_bytes(selection[..2].try_into().unwrap()) as usize;
    if !(1..=30).contains(&carrier_count) {
        return Err(refusal("carrier count"));
    }
    let mut carriers = Vec::new();
    for index in 0..carrier_count {
        let bytes = bounded(
            Path::new(&paths[47]).join(format!("carrier-{index}.bin")),
            4 + 2048 + 3309,
            &mut work,
        )?;
        let (body, signature) = packet(&bytes)?;
        carriers.push(
            publication
                .authenticate_witness(body, signature)
                .map_err(refusal)?,
        );
    }
    let aggregate = scratch.join("aggregate-9");
    let mut classifications = Vec::new();
    let mut slots = Vec::new();
    for author in 0..10 {
        let bytes = bounded(
            Path::new(&paths[49]).join(format!("source-{author}.bin")),
            1 + 4 + 2048 + 3309,
            &mut work,
        )?;
        let source = match bytes.first() {
            Some(0) => {
                let (body, signature) = packet(&bytes[1..])?;
                classifications.push(None);
                publication
                    .authenticate_empty(&close, body, signature)
                    .map_err(refusal)?
            }
            Some(1) if bytes.len() == 1 + 206 + 3309 => {
                let authentication = authenticate_envelope(&setup, &bytes[1..207], &bytes[207..])
                    .map_err(refusal)?;
                let mut authenticated =
                    BallotBodyAuthentication::new(authentication.clone()).map_err(refusal)?;
                let mut body = File::open(&paths[50 + author])?;
                let mut header = [0; 148];
                work.read(&mut body, &mut header)?;
                authenticated.push(&header).map_err(refusal)?;
                let mut classifier =
                    SignedBallotVerifier::new(poll.clone(), setup.clone(), authentication, &header)
                        .map_err(refusal)?;
                if classifier.requires_keys() {
                    for index in [1, 74] {
                        classifier.begin_key(index).map_err(refusal)?;
                        let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
                        let capacity =
                            CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
                        let mut key = File::open(aggregate.join(polynomial_name(index)))?;
                        loop {
                            let count = key.read(&mut buffer[..capacity])?;
                            work.read_bytes += count as u64;
                            if count == 0 {
                                break;
                            }
                            classifier.push_key(&buffer[..count]).map_err(refusal)?;
                        }
                        classifier.finish_key().map_err(refusal)?;
                    }
                }
                loop {
                    let count = body.read(&mut buffer)?;
                    work.read_bytes += count as u64;
                    if count == 0 {
                        break;
                    }
                    authenticated.push(&buffer[..count]).map_err(refusal)?;
                    classifier.push(&buffer[..count]).map_err(refusal)?;
                }
                classifications.push(Some(classifier.finish().map_err(refusal)?));
                publication
                    .ballot_source(authenticated.finish().map_err(refusal)?)
                    .map_err(refusal)?
            }
            _ => return Err(refusal("source kind")),
        };
        let selected = (0..3)
            .map(|ordinal| {
                let start = 2 + 2 * (author * 3 + ordinal);
                let index =
                    u16::from_le_bytes(selection[start..start + 2].try_into().unwrap()) as usize;
                carriers
                    .get(index)
                    .cloned()
                    .ok_or_else(|| refusal("carrier index"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        slots.push(publication.verify_slot(source, selected).map_err(refusal)?);
    }
    let closed = publication
        .verify_closed_slots(close, slots)
        .map_err(refusal)?;
    let incomplete = publication
        .verify_closed_slots(closed.close().clone(), closed.slots().to_vec())
        .map_err(refusal)?;
    if !matches!(
        ClassifiedClosedInventory::new(poll.clone(), setup.clone(), incomplete, vec![]),
        Err(Error::Incomplete)
    ) {
        return Err(refusal("missing classifications authorized evaluation"));
    }
    work.save(&output.join("closed.bin"), closed.body())?;
    let classified =
        ClassifiedClosedInventory::new(poll, setup, closed, classifications).map_err(refusal)?;
    let accepted: Vec<_> = classified.accepted_authors().collect();
    let classified_milliseconds = started.elapsed().as_secs_f64() * 1000.0;
    let spool_directory = scratch.join("evaluation");
    fs::create_dir(&spool_directory)?;
    let mut spool = Spool {
        directory: spool_directory,
        indices: BTreeSet::new(),
        work: Work::default(),
    };
    let mut operands = Operands {
        aggregate: aggregate.clone(),
        ballots: &paths[50..60],
        work: &mut work,
    };
    let target = classified
        .evaluate(&mut operands, &mut spool)
        .map_err(refusal)?;
    work.save(&output.join("target.bin"), target.body())?;
    let ciphertext_identity = if let Some(ciphertext) = target.ciphertext() {
        work.save(&output.join("ciphertext.bin"), ciphertext)?;
        Sha512::digest(ciphertext)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    } else {
        String::new()
    };
    if !spool.indices.is_empty() {
        return Err(refusal("unretired evaluation storage"));
    }
    let identity = target
        .identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if let Some(directory) = arguments.get(2) {
        let terminal = completion::verify(
            Arc::new(target),
            Path::new(directory),
            &aggregate,
            &mut work,
        )?;
        work.save(&output.join("terminal.json"), terminal.as_bytes())?;
    }
    let report = format!(
        "{{\"accepted\":{accepted:?},\"targetIdentity\":\"{identity}\",\"ciphertextSha512\":\"{ciphertext_identity}\",\"setupMilliseconds\":{setup_milliseconds},\"throughClassificationMilliseconds\":{classified_milliseconds},\"totalMilliseconds\":{},\"readBytes\":{},\"writtenBytes\":{},\"peakSetupStorageBytes\":{},\"peakEvaluationStorageBytes\":{},\"retainedBytes\":{}}}\n",
        started.elapsed().as_secs_f64() * 1000.0,
        work.read_bytes + spool.work.read_bytes,
        work.written_bytes + spool.work.written_bytes,
        work.peak_retained_bytes,
        spool.work.peak_retained_bytes,
        work.retained_bytes + spool.work.retained_bytes
    );
    fs::write(output.join("result.json"), &report)?;
    print!("{report}");
    Ok(())
}
