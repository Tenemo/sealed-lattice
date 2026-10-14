use super::{
    Arithmetic, DIGITS, FORGET, IDENTITY_BYTES, KEYED, KEYED_GROUPS, PrimeSet, RECORDS,
    RecordContext, RecordRequest, prime_sets, window, words,
};
use parallel_work::{Part, Shared, Ticket, session, share, submit};
use std::collections::VecDeque;
use zeroize::Zeroizing;

/// A keyed product in progress: the sums of a polynomial's gadget digits
/// times each gadget coordinate's key of two groups, one job for each prime
/// and group in the order of [`keyed_job`], each over the records of its
/// group's keys modulo its prime, which the caller delivers. Each prime's
/// digits are kept from just before its first group's job to its last
/// group's.
pub(in super::super) struct KeyedProduct {
    session: u64,
    context: RecordContext,
    // The polynomial until the last prime's digits have started.
    polynomial: Option<Shared>,
    started: Vec<Ticket>,
    requested: usize,
    delivered: Vec<u8>,
    // The pending request's records when the host shared them itself.
    shared: Option<Shared>,
    running: VecDeque<(usize, Ticket)>,
    sums: [Vec<Vec<u64>>; KEYED_GROUPS],
    // The primes whose digits have started and whose last group's job has
    // not.
    kept: Vec<usize>,
}

impl Drop for KeyedProduct {
    // A product that ends before its last group's job of a prime, as after
    // a refusal, drops that prime's digits where they are kept, after its
    // jobs there.
    fn drop(&mut self) {
        for prime in self.kept.drain(..) {
            let mut input = self.session.to_le_bytes().to_vec();
            input.extend((prime as u32).to_le_bytes());
            submit(&FORGET, Some(prime), &[Part::Bytes(&input)], 0);
        }
    }
}

/// A keyed product's next need: the records of a request, the end of a
/// job the host awaits, by the host's number, or both groups' sums modulo
/// each prime, which the caller lifts.
pub(in super::super) enum Keyed {
    Records(RecordRequest),
    Waiting(u32),
    Done([Vec<Vec<u64>>; KEYED_GROUPS]),
}

impl KeyedProduct {
    /// The ordinal of its first group's first key.
    pub(in super::super) fn first_ordinal(&self) -> usize {
        self.context.ordinal
    }
    /// The index of its pending request.
    pub(in super::super) fn requested(&self) -> usize {
        self.requested
    }
}

/// The prime and group of a keyed product's job of the index among the
/// jobs of the primes' two groups. The jobs come in batches of as many
/// primes as there are helpers, each batch's first group before its second,
/// so that each helper, which holds one prime of a batch, has a job while
/// the batch runs; without helpers each prime's groups come in turn.
pub(in super::super) fn keyed_job(index: usize, primes: usize, helpers: usize) -> (usize, usize) {
    let batch = helpers.max(1);
    let first = index / (KEYED_GROUPS * batch) * batch;
    let held = batch.min(primes - first);
    let within = index - KEYED_GROUPS * first;
    (first + within % held, within / held)
}
impl Arithmetic {
    /// The key's record modulo each external-product prime, in prime order,
    /// and each record's identity.
    pub(in super::super) fn key_records(
        &self,
        key: &[u64],
        context: RecordContext,
    ) -> (Vec<[u8; 64]>, Vec<Vec<u8>>) {
        let shared = self.shared_polynomial(key);
        let sets = prime_sets(self.external_primes, self.degree, parallel_work::helpers());
        let record_bytes = 8 * self.degree;
        let tickets: Vec<Ticket> = sets
            .iter()
            .map(|set| {
                let mut input = self.set_header(*set);
                context.write(&mut input);
                submit(
                    &RECORDS,
                    Some(set.first),
                    &[Part::Bytes(&input), Part::Streamed(&shared)],
                    set.len() * (IDENTITY_BYTES + record_bytes),
                )
            })
            .collect();
        drop(shared);
        let mut identities = vec![[0; 64]; self.external_primes];
        let mut records = vec![Vec::new(); self.external_primes];
        for (set, ticket) in sets.into_iter().zip(tickets) {
            let output = ticket.wait();
            for (prime, bytes) in set
                .primes()
                .zip(output.chunks_exact(IDENTITY_BYTES + record_bytes))
            {
                identities[prime] = bytes[..IDENTITY_BYTES].try_into().unwrap();
                records[prime] = bytes[IDENTITY_BYTES..].to_vec();
            }
        }
        (identities, records)
    }

    /// Starts the keyed product of the value with the two groups of keys
    /// from the context's ordinal.
    pub(in super::super) fn keyed_product(
        &self,
        value: &[u64],
        context: RecordContext,
    ) -> KeyedProduct {
        KeyedProduct {
            session: session(),
            context,
            polynomial: Some(self.shared_polynomial(value)),
            started: Vec::new(),
            requested: 0,
            delivered: Vec::new(),
            shared: None,
            running: VecDeque::new(),
            sums: std::array::from_fn(|_| vec![Vec::new(); self.external_primes]),
            kept: Vec::new(),
        }
    }

    /// The records a keyed product's next job needs.
    fn keyed_request(&self, product: &KeyedProduct) -> RecordRequest {
        self.keyed_request_at(product.context.ordinal, product.requested)
    }

    /// The records that the job of the index needs in a keyed product whose
    /// first group's first key has the ordinal.
    fn keyed_request_at(&self, ordinal: usize, index: usize) -> RecordRequest {
        let (prime, group) = keyed_job(index, self.external_primes, parallel_work::helpers());
        RecordRequest {
            first: ordinal + group * self.gadget_length,
            count: self.gadget_length,
            prime,
        }
    }

    /// The requests of such a keyed product from the job of the index on.
    pub(in super::super) fn keyed_requests_from(
        &self,
        ordinal: usize,
        index: usize,
    ) -> impl Iterator<Item = RecordRequest> + '_ {
        (index..KEYED_GROUPS * self.external_primes)
            .map(move |index| self.keyed_request_at(ordinal, index))
    }

    /// Takes the next record of the keyed product's pending request; false
    /// when it is not that record.
    pub(in super::super) fn deliver_record(
        &self,
        product: &mut KeyedProduct,
        ordinal: usize,
        prime: usize,
        record: &[u8],
    ) -> bool {
        // Once every job has requested its records, no request is left.
        if product.requested == KEYED_GROUPS * self.external_primes || product.shared.is_some() {
            return false;
        }
        let record_bytes = 8 * self.degree;
        let request = self.keyed_request(product);
        let received = product.delivered.len() / record_bytes;
        if prime != request.prime
            || received == request.count
            || ordinal != request.first + received
            || record.len() != record_bytes
        {
            return false;
        }
        if product.delivered.is_empty() {
            product
                .delivered
                .reserve_exact(request.count * record_bytes);
        }
        product.delivered.extend_from_slice(record);
        true
    }

    /// Takes the pending request's records, which the host shared itself
    /// one after another; false when they are not that whole request's
    /// records or a record of it was delivered.
    pub(in super::super) fn deliver_shared_records(
        &self,
        product: &mut KeyedProduct,
        request: RecordRequest,
        records: Shared,
    ) -> bool {
        if product.requested == KEYED_GROUPS * self.external_primes
            || request != self.keyed_request(product)
            || !product.delivered.is_empty()
            || product.shared.is_some()
            || records.length() != request.count * 8 * self.degree
        {
            return false;
        }
        product.shared = Some(records);
        true
    }

    /// Starts the job of a complete delivery and takes the outputs beyond
    /// the window. Returns the next request, the oldest such job while it
    /// runs when the host can await it, or both groups' sums once every job
    /// has ended. Fails when a job's records are not those whose identities
    /// the caller holds, by ordinal and prime.
    pub(in super::super) fn advance_keyed(
        &self,
        product: &mut KeyedProduct,
        identities: &[Vec<[u8; 64]>],
    ) -> Result<Keyed, ()> {
        let total = KEYED_GROUPS * self.external_primes;
        let record_bytes = 8 * self.degree;
        if product.requested < total
            && (product.shared.is_some()
                || product.delivered.len() == self.gadget_length * record_bytes)
        {
            let request = self.keyed_request(product);
            let (_, group) = keyed_job(
                product.requested,
                self.external_primes,
                parallel_work::helpers(),
            );
            if group == 0
                && let Some(polynomial) = &product.polynomial
            {
                let set = PrimeSet {
                    first: request.prime,
                    stride: 1,
                    count: request.prime + 1,
                };
                let mut input = self.set_header(set);
                input.extend(product.session.to_le_bytes());
                product.started.push(submit(
                    &DIGITS,
                    Some(request.prime),
                    &[Part::Bytes(&input), Part::Streamed(polynomial)],
                    0,
                ));
                product.kept.push(request.prime);
            }
            if group + 1 == KEYED_GROUPS {
                product.kept.retain(|prime| *prime != request.prime);
            }
            let mut input = self.header(request.prime);
            input.extend(product.session.to_le_bytes());
            input.extend(u32::from(group + 1 == KEYED_GROUPS).to_le_bytes());
            RecordContext {
                ordinal: request.first,
                ..product.context
            }
            .write(&mut input);
            let records = product
                .shared
                .take()
                .unwrap_or_else(|| share(Zeroizing::new(std::mem::take(&mut product.delivered))));
            let ticket = submit(
                &KEYED,
                Some(request.prime),
                &[Part::Bytes(&input), Part::Streamed(&records)],
                IDENTITY_BYTES * self.gadget_length + record_bytes,
            );
            drop(records);
            product.running.push_back((product.requested, ticket));
            product.requested += 1;
            if product.requested == total {
                product.polynomial = None;
            }
        }
        let window = if product.requested == total {
            0
        } else {
            window()
        };
        while product.running.len() > window {
            if let Some(number) = product.running[0].1.pending() {
                return Ok(Keyed::Waiting(number));
            }
            let (index, ticket) = product.running.pop_front().unwrap();
            let output = ticket.wait();
            let (prime, group) = keyed_job(index, self.external_primes, parallel_work::helpers());
            let first = product.context.ordinal + group * self.gadget_length;
            let (held, sum) = output.split_at(IDENTITY_BYTES * self.gadget_length);
            for (digit, identity) in held.chunks_exact(IDENTITY_BYTES).enumerate() {
                if identities
                    .get(first + digit)
                    .and_then(|record| record.get(prime))
                    .map(<[u8; 64]>::as_slice)
                    != Some(identity)
                {
                    return Err(());
                }
            }
            product.sums[group][prime] = words(sum);
        }
        if product.requested < total {
            return Ok(Keyed::Records(self.keyed_request(product)));
        }
        for ticket in product.started.drain(..) {
            assert!(ticket.wait().is_empty());
        }
        Ok(Keyed::Done(std::mem::take(&mut product.sums)))
    }
}

#[cfg(test)]
#[path = "keyed-products-tests.rs"]
mod tests;
