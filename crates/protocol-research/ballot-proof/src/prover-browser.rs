use crate::{columns, oracles::Witness, proof::BallotProof, statement::PublicStatement};
use std::{
    cell::RefCell,
    io::{self, Write},
};

struct PublicWriter {
    kind: u32,
    offset: usize,
    bytes: Vec<u8>,
}
impl PublicWriter {
    fn new(kind: u32) -> Self {
        Self {
            kind,
            offset: 0,
            bytes: Vec::with_capacity(1 << 20),
        }
    }
    fn send(&mut self) -> io::Result<()> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        #[link(wasm_import_module = "ballot_proof")]
        unsafe extern "C" {
            fn public_chunk(kind: u32, offset: usize, pointer: *const u8, length: usize) -> u32;
        }
        // SAFETY: the sink receives this live bounded slice of public statement or proof bytes.
        if unsafe {
            public_chunk(
                self.kind,
                self.offset,
                self.bytes.as_ptr(),
                self.bytes.len(),
            )
        } != 0
        {
            return Err(io::Error::other("Public proof sink refused."));
        }
        self.offset += self.bytes.len();
        self.bytes.clear();
        Ok(())
    }
}
impl Write for PublicWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min((1 << 20) - self.bytes.len());
            self.bytes.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.bytes.len() == 1 << 20 {
                self.send()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.send()
    }
}
struct Session {
    consumed: bool,
    context: [u8; 194],
    completed: bool,
}
thread_local! { static SESSION: RefCell<Session> = const { RefCell::new(Session { consumed: false, context: [0; 194], completed: false }) }; }
#[unsafe(no_mangle)]
pub extern "C" fn ballot_prover_create() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        if session.consumed {
            return 1;
        }
        let Some(encryption) = ballot_encryption::encryption_browser::take_witness() else {
            return 1;
        };
        session.consumed = true;
        let result = (|| {
            let role = crate::context::private_proof_role(&encryption.context).map_err(|_| ())?;
            let public = PublicStatement::from_encryption(&encryption).map_err(|_| ())?;
            let mut columns = columns::from_encryption(&encryption).map_err(|_| ())?;
            let witness = Witness::from_columns(public.digest(), std::mem::take(&mut *columns))
                .map_err(|_| ())?;
            let mut context = [0; 194];
            context[..64].copy_from_slice(&encryption.context.poll().identity());
            context[64..128].copy_from_slice(encryption.context.inventory());
            context[128..192].copy_from_slice(&public.digest());
            context[192..].copy_from_slice(&(encryption.context.position() as u16).to_le_bytes());
            drop(encryption);
            let proof = BallotProof::create(&role, &public, witness, false);
            for (kind, bytes) in std::iter::once(&public.header)
                .chain(&public.polynomials)
                .enumerate()
            {
                let mut writer = PublicWriter::new(kind as u32);
                writer.write_all(bytes).map_err(|_| ())?;
                writer.flush().map_err(|_| ())?;
            }
            let mut writer = PublicWriter::new(9);
            proof.write(&mut writer);
            writer.flush().map_err(|_| ())?;
            Ok(context)
        })();
        match result {
            Ok(context) => {
                session.context = context;
                session.completed = true;
                0
            }
            Err(()) => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_prover_context_pointer() -> usize {
    SESSION.with(|session| {
        let session = session.borrow();
        if session.completed {
            session.context.as_ptr() as usize
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_prover_clear() {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.context.fill(0);
        session.completed = false;
    });
}
