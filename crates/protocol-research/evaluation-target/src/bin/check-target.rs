use ballot_proof::{
    body::SignedBallotVerifier,
    close::{CloseContext, ClosedSlot},
    statement::setup_inputs,
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use evaluation_target::target::{ClassifiedClosedInventory, Error, PublicInputs, WorkingStore};
use registration_credentials::{
    ballot_authentication::ENVELOPE_BYTES,
    ballot_body,
    close_signing::{
        CloseProposalMessage, ClosePurpose, CloseResponseMessage, maximum_close_message_bytes,
    },
    contribution_authentication::{CommitmentInventory, verify_confirmation},
    roster_authentication::verify_roster_proposal,
    roster_input::RosterInputVerifier,
};
use rns_arithmetic_probe::ranking::{
    Ciphertext, KEY_RECORD_BYTES, stored_bytes, stored_value_bytes,
};
use setup_aggregate::{CHUNK_BYTES, contribution_family, verified::SetupAggregator};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use supported_profile::{Profile, relation::PROOF_HEADER_BYTES};

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
/// A length-prefixed signed message body followed by its signature.
fn packet(bytes: &[u8], maximum: usize) -> io::Result<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| refusal("packet"))?
            .try_into()
            .map_err(refusal)?,
    ) as usize;
    if length > maximum || bytes.len() != 4 + length + 3309 {
        return Err(refusal("packet length"));
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
fn close_packet(
    directory: &Path,
    name: &str,
    purpose: ClosePurpose,
    participants: usize,
    work: &mut Work,
) -> io::Result<Vec<u8>> {
    let maximum = maximum_close_message_bytes(purpose, participants);
    bounded(directory.join(name), 4 + maximum + 3309, work)
}
/// A public body path inside the ceremony directory.
fn contained(ceremony: &Path, relative: &str) -> io::Result<PathBuf> {
    let path = Path::new(relative);
    if relative.is_empty()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(refusal("body path"));
    }
    Ok(ceremony.join(path))
}
fn polynomial_name(index: usize) -> String {
    format!("polynomial-{index:02}.bin")
}
/// Bytes of a contribution polynomial and of the largest whole-coefficient
/// chunk.
fn polynomial_bytes(profile: Profile, index: usize) -> io::Result<(usize, usize)> {
    let family = contribution_family(profile, index).ok_or_else(|| refusal("key index"))?;
    let width = 1 + profile.family_magnitude_bytes(family);
    Ok((
        profile.family_degree(family) * width,
        CHUNK_BYTES / width * width,
    ))
}

struct Operands<'a> {
    aggregate: PathBuf,
    ballots: &'a [Option<PathBuf>],
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
            file: File::open(
                self.ballots
                    .get(author)
                    .and_then(Option::as_ref)
                    .ok_or(Error::PublicInput)?,
            )
            .map_err(|_| Error::PublicInput)?,
            work: self.work,
        }))
    }
}
struct Spool {
    directory: PathBuf,
    indices: BTreeSet<usize>,
    records: BTreeSet<(usize, usize)>,
    value_bytes: usize,
    work: Work,
}
impl WorkingStore for Spool {
    fn put(&mut self, index: usize, value: &Ciphertext) -> Result<(), Error> {
        if !self.indices.insert(index) {
            return Err(Error::Storage);
        }
        self.work
            .save(
                &self.directory.join(format!("{index}.bin")),
                &stored_bytes(value),
            )
            .map_err(|_| Error::Storage)
    }
    fn get(&mut self, index: usize) -> Result<Vec<u8>, Error> {
        let bytes = bounded(
            self.directory.join(format!("{index}.bin")),
            self.value_bytes,
            &mut self.work,
        )
        .map_err(|_| Error::Storage)?;
        if bytes.len() != self.value_bytes {
            return Err(Error::Storage);
        }
        Ok(bytes)
    }
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        if self.indices.remove(&index) {
            self.work
                .remove(&self.directory.join(format!("{index}.bin")))
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
    fn put_record(&mut self, ordinal: usize, prime: usize, record: &[u8]) -> Result<(), Error> {
        if !self.records.insert((ordinal, prime)) {
            return Err(Error::Storage);
        }
        self.work
            .save(
                &self.directory.join(format!("key-{ordinal}-{prime}.bin")),
                record,
            )
            .map_err(|_| Error::Storage)
    }
    fn get_record(&mut self, ordinal: usize, prime: usize) -> Result<Vec<u8>, Error> {
        if !self.records.contains(&(ordinal, prime)) {
            return Err(Error::Storage);
        }
        bounded(
            self.directory.join(format!("key-{ordinal}-{prime}.bin")),
            KEY_RECORD_BYTES,
            &mut self.work,
        )
        .map_err(|_| Error::Storage)
    }
    fn clear_records(&mut self) -> Result<(), Error> {
        for (ordinal, prime) in std::mem::take(&mut self.records) {
            self.work
                .remove(&self.directory.join(format!("key-{ordinal}-{prime}.bin")))
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(3..=5).contains(&arguments.len())
        || arguments
            .get(4)
            .is_some_and(|value| value != "certificate" && value != "release")
    {
        return Err(refusal(
            "supply the ceremony directory, a new scratch directory, a new result directory, an optional public completion directory and an optional certificate or release selector",
        ));
    }
    let started = Instant::now();
    let mut work = Work::default();
    let ceremony = Path::new(&arguments[0]);
    let scratch = Path::new(&arguments[1]);
    let output = Path::new(&arguments[2]);
    fs::create_dir(output)?;
    fs::create_dir(scratch)?;
    let count = (0..=*Profile::participant_range().end())
        .take_while(|position| ceremony.join(format!("participant-{position}")).is_dir())
        .count();
    if !Profile::participant_range().contains(&count) {
        return Err(refusal("participant count"));
    }
    let mut control = bounded(ceremony.join("context.bin"), 128, &mut work)?;
    if control.len() != 128 {
        return Err(refusal("context length"));
    }
    let definition = bounded(ceremony.join("poll-definition.bin"), 1 << 20, &mut work)?;
    control.extend((count as u16).to_le_bytes());
    control.extend((definition.len() as u32).to_le_bytes());
    control.extend(definition);
    control.extend(bounded(
        ceremony.join("poll-signature.bin"),
        3309,
        &mut work,
    )?);
    let mut roster = RosterInputVerifier::new(&control).map_err(refusal)?;
    let mut buffer = vec![0; CHUNK_BYTES];
    for position in 0..count {
        let directory = ceremony.join(format!("participant-{position}"));
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
                    roster.push_key(position, &buffer[..count])
                } else {
                    roster.push_proof(position, &buffer[..count])
                }
                .map_err(refusal)?;
            }
            if ordinal == 0 {
                roster.finish_key(position)
            } else {
                roster.finish_record(position)
            }
            .map_err(refusal)?;
        }
    }
    let proposal = roster.finish().map_err(refusal)?;
    let poll = Arc::new(roster.into_poll());
    let proposal = Arc::new(
        verify_roster_proposal(
            proposal,
            &bounded(ceremony.join("proposal-signature.bin"), 3309, &mut work)?,
        )
        .map_err(refusal)?,
    );
    // Every roster participant published a confirmation; only the setup
    // contributors published a contribution.
    let profile = proposal.proposal().profile();
    let directories: Vec<_> = (0..profile.participants())
        .map(|position| ceremony.join(format!("contribution-{position}")))
        .collect();
    let contributions = &directories[..profile.setup_contributors()];
    let mut confirmations = Vec::new();
    for directory in &directories {
        let body = bounded(directory.join("confirmation.bin"), 2048, &mut work)?;
        let signature = bounded(
            directory.join("confirmation-signature.bin"),
            3309,
            &mut work,
        )?;
        confirmations.push(verify_confirmation(&proposal, &body, &signature).map_err(refusal)?);
    }
    let inventory = Arc::new(CommitmentInventory::new(proposal, confirmations).map_err(refusal)?);
    let mut aggregator = SetupAggregator::new(inventory).map_err(refusal)?;
    let indices = profile.contribution_body_polynomials();
    for (position, directory) in contributions.iter().enumerate() {
        let stage = scratch.join(format!("aggregate-{position}"));
        fs::create_dir(&stage)?;
        let opening = bounded(directory.join("opening.bin"), 2048, &mut work)?;
        let signature = bounded(directory.join("opening-signature.bin"), 3309, &mut work)?;
        let header = bounded(directory.join("body-header.bin"), 12, &mut work)?;
        let mut proof = File::open(directory.join("proof.bin"))?;
        let mut proof_header = [0; PROOF_HEADER_BYTES];
        work.read(&mut proof, &mut proof_header)?;
        aggregator
            .begin(&opening, &signature, &header, &proof_header)
            .map_err(refusal)?;
        for index in &indices {
            let (length, capacity) = polynomial_bytes(profile, *index)?;
            let name = polynomial_name(*index);
            let mut incoming = File::open(directory.join(&name))?;
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
        let mut proof = File::open(directory.join("proof.bin"))?;
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
    let close = CloseContext::new(poll.clone(), setup.clone()).map_err(refusal)?;
    let records = ceremony.join("close");
    let intent_packet = close_packet(
        &records,
        "intent.bin",
        ClosePurpose::Intent,
        count,
        &mut work,
    )?;
    let (body, signature) = packet(
        &intent_packet,
        maximum_close_message_bytes(ClosePurpose::Intent, count),
    )?;
    let intent = close
        .authenticate_intent(body, signature)
        .map_err(refusal)?;
    let proposal_packet = close_packet(
        &records,
        "proposal.bin",
        ClosePurpose::Proposal,
        count,
        &mut work,
    )?;
    let (proposal_body, proposal_signature) = packet(
        &proposal_packet,
        maximum_close_message_bytes(ClosePurpose::Proposal, count),
    )?;
    // The proposal names its responses; only those and their listed bodies
    // are needed. Nothing is accepted before the proposal verifier runs.
    let named =
        CloseProposalMessage::parse(proposal_body, count, close.organizer()).map_err(refusal)?;
    let mut response_packets = Vec::new();
    let mut needed = BTreeSet::new();
    for (responder, identity) in named.responses() {
        // The organizer's copy under the named identity, when the records
        // hold it, or else the responder's own.
        let closure = format!(
            "closure/response-{}.bin",
            identity
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let name = if records.join(&closure).is_file() {
            closure
        } else {
            format!("response-{responder}.bin")
        };
        let bytes = close_packet(&records, &name, ClosePurpose::Response, count, &mut work)?;
        let (body, _) = packet(
            &bytes,
            maximum_close_message_bytes(ClosePurpose::Response, count),
        )?;
        let response = CloseResponseMessage::parse(body, count).map_err(refusal)?;
        needed.extend(response.listed().iter().map(|(_, identity)| *identity));
        response_packets.push(bytes);
    }
    // The submission index names each stored submission and its public body.
    // Every listed envelope is authenticated; no listed body is read yet.
    let index = bounded(records.join("submissions.txt"), 1 << 16, &mut work)?;
    let mut envelopes = Vec::new();
    let mut bodies = BTreeMap::new();
    for (ordinal, line) in std::str::from_utf8(&index)
        .map_err(refusal)?
        .lines()
        .enumerate()
    {
        let (name, relative) = line
            .split_once(' ')
            .ok_or_else(|| refusal("submission index line"))?;
        if name != format!("submission-{ordinal}.bin") {
            return Err(refusal("submission index order"));
        }
        let bytes = bounded(records.join(name), ENVELOPE_BYTES + 3309, &mut work)?;
        if bytes.len() != ENVELOPE_BYTES + 3309 {
            return Err(refusal("stored submission length"));
        }
        let authentication =
            authenticate_envelope(&setup, &bytes[..ENVELOPE_BYTES], &bytes[ENVELOPE_BYTES..])
                .map_err(refusal)?;
        let identity = authentication.envelope().identity();
        if !needed.contains(&identity) || bodies.contains_key(&identity) {
            continue;
        }
        bodies.insert(identity, contained(ceremony, relative)?);
        envelopes.push(authentication);
    }
    let mut responses = Vec::new();
    for bytes in &response_packets {
        let (body, signature) = packet(
            bytes,
            maximum_close_message_bytes(ClosePurpose::Response, count),
        )?;
        responses.push(
            close
                .authenticate_response(&intent, body, signature, &envelopes)
                .map_err(refusal)?,
        );
    }
    // Only a usable slot needs its body. Each streams once through the owning
    // body authentication and classification.
    let required = close
        .required_bodies(&intent, &named, &responses)
        .map_err(refusal)?;
    let aggregate = scratch.join(format!("aggregate-{}", contributions.len() - 1));
    let mut authenticated_bodies = Vec::new();
    let mut classifications: Vec<_> = (0..count).map(|_| None).collect();
    let mut ballots = vec![None; count];
    for (author, identity) in required {
        let path = bodies
            .get(&identity)
            .ok_or_else(|| refusal("usable body outside the stored submissions"))?
            .clone();
        let authentication = envelopes
            .iter()
            .find(|value| value.envelope().identity() == identity)
            .ok_or_else(|| refusal("usable envelope outside the stored submissions"))?
            .clone();
        let mut authenticated =
            BallotBodyAuthentication::new(authentication.clone()).map_err(refusal)?;
        let mut body = File::open(&path)?;
        let mut header = [0; ballot_body::HEADER_BYTES];
        work.read(&mut body, &mut header)?;
        authenticated.push(&header).map_err(refusal)?;
        let mut classifier =
            SignedBallotVerifier::new(poll.clone(), setup.clone(), authentication, &header, None)
                .map_err(refusal)?;
        if classifier.requires_keys() {
            for (_, _, index) in setup_inputs(profile) {
                classifier.begin_key(index).map_err(refusal)?;
                // Whole-coefficient chunks, as the key reader takes them.
                let (length, capacity) = polynomial_bytes(profile, index)?;
                let mut key = File::open(aggregate.join(polynomial_name(index)))?;
                let mut offset = 0;
                while offset < length {
                    let count = capacity.min(length - offset);
                    work.read(&mut key, &mut buffer[..count])?;
                    classifier.push_key(&buffer[..count]).map_err(refusal)?;
                    offset += count;
                }
                end(&mut key)?;
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
        authenticated_bodies.push(authenticated.finish().map_err(refusal)?);
        classifications[author] = Some(classifier.finish().map_err(refusal)?);
        ballots[author] = Some(path);
    }
    let barrier = close
        .verify_proposal(
            intent.clone(),
            proposal_body,
            proposal_signature,
            &responses,
            &authenticated_bodies,
        )
        .map_err(refusal)?;
    // A second capability over the same records cannot evaluate without
    // every usable slot's classification.
    let unclassified = close
        .verify_proposal(
            intent,
            proposal_body,
            proposal_signature,
            &responses,
            &authenticated_bodies,
        )
        .map_err(refusal)?;
    if !matches!(
        ClassifiedClosedInventory::new(unclassified, vec![]),
        Err(Error::Incomplete)
    ) {
        return Err(refusal("missing classifications authorized evaluation"));
    }
    let conflicting: Vec<_> = barrier
        .slots()
        .iter()
        .enumerate()
        .filter_map(|(author, slot)| matches!(slot, ClosedSlot::Conflicting(_)).then_some(author))
        .collect();
    work.save(&output.join("proposal.bin"), barrier.proposal().body())?;
    let classified = ClassifiedClosedInventory::new(barrier, classifications).map_err(refusal)?;
    let accepted: Vec<_> = classified.accepted_authors().collect();
    let classified_milliseconds = started.elapsed().as_secs_f64() * 1000.0;
    let spool_directory = scratch.join("evaluation");
    fs::create_dir(&spool_directory)?;
    let mut spool = Spool {
        directory: spool_directory,
        indices: BTreeSet::new(),
        records: BTreeSet::new(),
        value_bytes: stored_value_bytes(profile),
        work: Work::default(),
    };
    let mut operands = Operands {
        aggregate: aggregate.clone(),
        ballots: &ballots,
        work: &mut work,
    };
    let target = classified
        .evaluate(&mut operands, &mut spool)
        .map_err(refusal)?;
    work.save(&output.join("target.bin"), target.body())?;
    let ciphertext_bytes = if let Some(ciphertext) = target.ciphertext() {
        work.save(&output.join("ciphertext.bin"), ciphertext)?;
        ciphertext.len()
    } else {
        0
    };
    if !spool.indices.is_empty() || !spool.records.is_empty() {
        return Err(refusal("unretired evaluation storage"));
    }
    let identity = target
        .identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if let Some(directory) = arguments.get(3) {
        let stage = match arguments.get(4).map(String::as_str) {
            Some("certificate") => completion::Stage::Certificate,
            Some("release") => completion::Stage::Release,
            _ => completion::Stage::Terminal,
        };
        let terminal = completion::verify(
            Arc::new(target),
            Path::new(directory),
            &aggregate,
            &mut work,
            stage,
        )?;
        let name = match stage {
            completion::Stage::Certificate => "certificate.json",
            completion::Stage::Release => "release.json",
            completion::Stage::Terminal => "terminal.json",
        };
        work.save(&output.join(name), terminal.as_bytes())?;
    }
    let poll_identity: String = poll
        .identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let report = format!(
        "{{\"participantCount\":{count},\"pollIdentity\":\"{poll_identity}\",\"accepted\":{accepted:?},\"conflicting\":{conflicting:?},\"targetIdentity\":\"{identity}\",\"ciphertextBytes\":{ciphertext_bytes},\"setupMilliseconds\":{setup_milliseconds},\"throughClassificationMilliseconds\":{classified_milliseconds},\"totalMilliseconds\":{},\"readBytes\":{},\"writtenBytes\":{},\"peakSetupStorageBytes\":{},\"peakEvaluationStorageBytes\":{},\"retainedBytes\":{}}}\n",
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
