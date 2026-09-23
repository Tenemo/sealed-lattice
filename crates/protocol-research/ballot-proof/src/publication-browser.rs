use crate::{
    publication::{
        AuthenticatedClose, AuthenticatedSource, AuthenticatedWitnessBatch, PublicationContext,
        VerifiedClosedSlots, VerifiedSlotEvidence,
    },
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use std::cell::RefCell;

struct Session {
    input: Vec<u8>,
    context: Option<PublicationContext>,
    close: Option<AuthenticatedClose>,
    pending_body: Option<BallotBodyAuthentication>,
    sources: Vec<AuthenticatedSource>,
    batches: Vec<AuthenticatedWitnessBatch>,
    slots: Vec<VerifiedSlotEvidence>,
    closed: Option<VerifiedClosedSlots>,
}
impl Session {
    fn new() -> Self {
        Self {
            input: vec![0; 1 << 20],
            context: None,
            close: None,
            pending_body: None,
            sources: Vec::new(),
            batches: Vec::new(),
            slots: Vec::new(),
            closed: None,
        }
    }
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        if operation == 1 {
            if length != 0 {
                return Err(());
            }
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            let context = PublicationContext::new(poll, setup).map_err(|_| ())?;
            self.context = Some(context);
            self.close = None;
            self.pending_body = None;
            self.sources.clear();
            self.batches.clear();
            self.slots.clear();
            self.closed = None;
            return Ok(());
        }
        if self.closed.is_some() {
            return Err(());
        }
        let context = self.context.as_ref().ok_or(())?;
        let bytes = self.input.get(..length).ok_or(())?;
        match operation {
            2 => {
                if self.close.is_some() {
                    return Err(());
                }
                let (body, signature) = packet(bytes)?;
                self.close = Some(
                    context
                        .authenticate_close(body, signature)
                        .map_err(|_| ())?,
                );
            }
            3 => {
                if self.pending_body.is_some()
                    || self.sources.len() >= context.participant_count()
                    || bytes.len() != 206 + 3309
                {
                    return Err(());
                }
                let (_, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
                let authentication =
                    authenticate_envelope(&setup, &bytes[..206], &bytes[206..]).map_err(|_| ())?;
                if authentication.envelope().position() != self.sources.len() {
                    return Err(());
                }
                self.pending_body =
                    Some(BallotBodyAuthentication::new(authentication).map_err(|_| ())?);
            }
            4 => {
                if let Err(error) = self.pending_body.as_mut().ok_or(())?.push(bytes) {
                    self.pending_body = None;
                    let _ = error;
                    return Err(());
                }
            }
            5 => {
                if !bytes.is_empty() {
                    return Err(());
                }
                let body = self
                    .pending_body
                    .take()
                    .ok_or(())?
                    .finish()
                    .map_err(|_| ())?;
                let source = context.ballot_source(body).map_err(|_| ())?;
                if source.author() != self.sources.len() {
                    return Err(());
                }
                self.sources.push(source);
            }
            6 => {
                if self.pending_body.is_some() || self.sources.len() >= context.participant_count()
                {
                    return Err(());
                }
                let (body, signature) = packet(bytes)?;
                let source = context
                    .authenticate_empty(self.close.as_ref().ok_or(())?, body, signature)
                    .map_err(|_| ())?;
                if source.author() != self.sources.len() {
                    return Err(());
                }
                self.sources.push(source);
            }
            7 => {
                let (body, signature) = packet(bytes)?;
                let batch = context
                    .authenticate_witness(body, signature)
                    .map_err(|_| ())?;
                context
                    .collect_witness_batch(&mut self.batches, batch)
                    .map_err(|_| ())?;
            }
            8 => {
                let others = (context.participant_count() - 1) / 3;
                if bytes.len() != 2 + 2 * others || self.slots.len() >= self.sources.len() {
                    return Err(());
                }
                let author =
                    usize::from(u16::from_le_bytes(bytes[..2].try_into().map_err(|_| ())?));
                if author != self.slots.len() {
                    return Err(());
                }
                let batches = bytes[2..]
                    .chunks_exact(2)
                    .map(|bytes| {
                        let index =
                            usize::from(u16::from_le_bytes(bytes.try_into().map_err(|_| ())?));
                        self.batches.get(index).cloned().ok_or(())
                    })
                    .collect::<Result<Vec<_>, ()>>()?;
                let slot = context
                    .verify_slot(self.sources[author].clone(), batches)
                    .map_err(|_| ())?;
                self.slots.push(slot);
            }
            9 => {
                if !bytes.is_empty() {
                    return Err(());
                }
                self.closed = Some(
                    context
                        .verify_closed_slots(self.close.clone().ok_or(())?, self.slots.clone())
                        .map_err(|_| ())?,
                );
            }
            10 => {
                if !bytes.is_empty() {
                    return Err(());
                }
                self.pending_body = None;
            }
            _ => return Err(()),
        }
        Ok(())
    }
}
fn packet(bytes: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    let length = u32::from_le_bytes(bytes.get(..4).ok_or(())?.try_into().map_err(|_| ())?) as usize;
    if length > 2048 || bytes.len() != 4 + length + 3309 {
        return Err(());
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session::new()); }
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|session| u32::from(session.borrow_mut().command(operation, length).is_err()))
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_source_count() -> usize {
    SESSION.with(|session| session.borrow().sources.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_batch_count() -> usize {
    SESSION.with(|session| session.borrow().batches.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_closed_pointer() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .closed
            .as_ref()
            .map_or(0, |closed| closed.body().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_closed_length() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .closed
            .as_ref()
            .map_or(0, |closed| closed.body().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn slot_publication_identity_pointer() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .closed
            .as_ref()
            .map_or(0, |closed| closed.identity().as_ptr() as usize)
    })
}

pub(super) fn take_closed() -> Option<VerifiedClosedSlots> {
    SESSION.with(|session| session.borrow_mut().closed.take())
}
