use super::*;
use parallel_work::ProtocolHash;
use setup_witness::encrypted_source::VerifiedSource;
use statement_stream::{SetupStatementStream, StatementOutput};
use word_verifier::engine::Statement;

/// The owning verifier supplies the registered source and the proof supplies
/// committed-column claims. The enclosing digest binds both byte streams.
pub struct LinkedStatementStream {
    profile: Profile,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    core: SetupStatementStream,
    core_remaining: usize,
    source: PublicSource,
    source_records: Vec<u8>,
    source_position: usize,
    hash: ProtocolHash,
    public_root: [u8; 64],
    remaining: usize,
    failed: bool,
}
impl LinkedStatementStream {
    pub fn committed(
        profile: Profile,
        expected: [u8; 64],
        registered: VerifiedSource,
        alpha: Element,
        queries: &[u32],
        public_root: [u8; 64],
        evaluations: &[Element],
    ) -> Result<Self, Refusal> {
        let core = SetupStatementStream::embedded_committed(
            profile,
            alpha,
            queries,
            public_root,
            evaluations,
        )
        .map_err(|_| Refusal::Shape)?;
        let core_remaining = profile.setup_statement_length()
            - profile
                .committed_polynomials()
                .iter()
                .map(|index| profile.setup_polynomial_bytes(*index).unwrap())
                .sum::<usize>();
        let source = registered.into_public(profile)?;
        let source_records = source.records()?.concat();
        let remaining = core_remaining + source_records.len();
        Ok(Self {
            profile,
            expected,
            alpha,
            queries: queries.to_vec(),
            core,
            core_remaining,
            source,
            source_records,
            source_position: 0,
            hash: ProtocolHash::new(),
            public_root,
            remaining,
            failed: false,
        })
    }
    fn consume(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || bytes.len() > parallel_work::CHUNK_LIMIT || bytes.len() > self.remaining {
            return Err(Refusal::Shape);
        }
        self.remaining -= bytes.len();
        self.hash.update(bytes);
        if self.core_remaining > 0 {
            let length = bytes.len().min(self.core_remaining);
            self.core
                .push(&bytes[..length])
                .map_err(|_| Refusal::Encoding)?;
            self.core_remaining -= length;
            bytes = &bytes[length..];
        }
        let end = self
            .source_position
            .checked_add(bytes.len())
            .ok_or(Refusal::Shape)?;
        if self.source_records.get(self.source_position..end) != Some(bytes) {
            return Err(Refusal::Binding);
        }
        self.source_position = end;
        Ok(())
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let result = self.consume(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish(mut self) -> Result<StatementOutput, Refusal> {
        if self.failed
            || self.remaining != 0
            || self.core_remaining != 0
            || self.source_position != self.source_records.len()
        {
            return Err(Refusal::Shape);
        }
        self.hash.update(self.public_root);
        if self.hash.finalize() != self.expected {
            return Err(Refusal::Binding);
        }
        let core = self.core.finish().map_err(|_| Refusal::Binding)?;
        let added = source_operator(self.profile, &self.source, self.alpha, core.lookup_weight)?;
        let target = field::add(core.target, added.target);
        let lookup_weight = added.lookup_weight;
        let count = self.queries.len();
        let mut coefficients = added
            .at_queries(relation(self.profile).columns(), &self.queries)
            .map_err(|_| Refusal::Arithmetic)?;
        let old_words = self.profile.setup_shape().word_columns;
        if core.coefficients.len() != setup_relation(self.profile).columns() * count {
            return Err(Refusal::Shape);
        }
        for column in 0..setup_relation(self.profile).columns() {
            let mapped = remap(column, old_words);
            for query in 0..count {
                coefficients[mapped * count + query] = field::add(
                    coefficients[mapped * count + query],
                    core.coefficients[column * count + query],
                );
            }
        }
        Ok(StatementOutput {
            target,
            lookup_weight,
            coefficients,
        })
    }
}
impl Statement for LinkedStatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        LinkedStatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        LinkedStatementStream::finish(self).ok()
    }
}
