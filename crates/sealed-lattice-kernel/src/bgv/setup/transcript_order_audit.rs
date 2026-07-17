use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::bgv::setup) struct TranscriptOrderAuditEvent {
    pub transcript_family: String,
    pub transcript_path: String,
    pub event_index: u64,
    pub operation: String,
    pub label: String,
    pub byte_length: Option<usize>,
    pub squeeze_counter: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::bgv::setup) struct TranscriptOrderAuditSegment {
    pub event_count: u64,
    pub operation: String,
    pub label: String,
    pub byte_length: Option<usize>,
    pub squeeze_counter_start: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::bgv::setup) struct TranscriptOrderAuditTrace {
    pub transcript_family: String,
    pub transcript_path: String,
    pub segments: Vec<TranscriptOrderAuditSegment>,
    #[serde(skip)]
    next_event_index: u64,
}

type SharedAuditEvents = Arc<Mutex<Vec<TranscriptOrderAuditEvent>>>;

thread_local! {
    static ACTIVE_AUDIT_EVENTS: RefCell<Option<SharedAuditEvents>> = const { RefCell::new(None) };
}

#[derive(Clone)]
pub(in crate::bgv::setup) struct TranscriptOrderAuditRecorder {
    events: SharedAuditEvents,
    transcript_family: String,
    transcript_path: String,
    next_event_index: u64,
}

impl TranscriptOrderAuditRecorder {
    pub(in crate::bgv::setup) fn fork(&self, label: &str, index: u64) -> Self {
        Self {
            events: Arc::clone(&self.events),
            transcript_family: self.transcript_family.clone(),
            transcript_path: format!("{}/{label}[{index}]", self.transcript_path),
            next_event_index: 0,
        }
    }

    pub(in crate::bgv::setup) fn record_absorb(&mut self, label: &str, byte_length: usize) {
        self.record("absorb", label, Some(byte_length), None);
    }

    pub(in crate::bgv::setup) fn record_initialize(
        &mut self,
        protocol_label: &str,
        byte_length: usize,
    ) {
        self.record("initialize", protocol_label, Some(byte_length), None);
    }

    pub(in crate::bgv::setup) fn record_squeeze(&mut self, label: &str, counter: u64) {
        self.record("squeeze", label, None, Some(counter));
    }

    fn record(
        &mut self,
        operation: &str,
        label: &str,
        byte_length: Option<usize>,
        squeeze_counter: Option<u64>,
    ) {
        self.events
            .lock()
            .expect("transcript-order audit event lock must not be poisoned")
            .push(TranscriptOrderAuditEvent {
                transcript_family: self.transcript_family.clone(),
                transcript_path: self.transcript_path.clone(),
                event_index: self.next_event_index,
                operation: operation.to_string(),
                label: label.to_string(),
                byte_length,
                squeeze_counter,
            });
        self.next_event_index += 1;
    }
}

pub(in crate::bgv::setup) fn active_transcript_order_audit_recorder(
    transcript_family: &str,
    protocol_label: &str,
) -> Option<TranscriptOrderAuditRecorder> {
    ACTIVE_AUDIT_EVENTS.with(|active_events| {
        active_events
            .borrow()
            .as_ref()
            .map(|events| TranscriptOrderAuditRecorder {
                events: Arc::clone(events),
                transcript_family: transcript_family.to_string(),
                transcript_path: protocol_label.to_string(),
                next_event_index: 0,
            })
    })
}

pub(in crate::bgv::setup) fn capture_transcript_order_audit<T>(
    operation: impl FnOnce() -> T,
) -> (T, Vec<TranscriptOrderAuditEvent>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    ACTIVE_AUDIT_EVENTS.with(|active_events| {
        let previous = active_events.replace(Some(Arc::clone(&events)));
        assert!(
            previous.is_none(),
            "transcript-order audit capture must not be nested"
        );
    });

    struct ActiveAuditReset;
    impl Drop for ActiveAuditReset {
        fn drop(&mut self) {
            ACTIVE_AUDIT_EVENTS.with(|active_events| {
                active_events.replace(None);
            });
        }
    }
    let reset = ActiveAuditReset;
    let output = operation();
    drop(reset);

    let mut captured_events = events
        .lock()
        .expect("transcript-order audit event lock must not be poisoned")
        .clone();
    captured_events.sort_by(|left, right| {
        left.transcript_family
            .cmp(&right.transcript_family)
            .then_with(|| left.transcript_path.cmp(&right.transcript_path))
            .then_with(|| left.event_index.cmp(&right.event_index))
    });
    (output, captured_events)
}

pub(in crate::bgv::setup) fn run_length_encode_transcript_order_audit(
    events: &[TranscriptOrderAuditEvent],
) -> Vec<TranscriptOrderAuditTrace> {
    let mut traces: Vec<TranscriptOrderAuditTrace> = Vec::new();
    for event in events {
        let starts_new_trace = traces.last().is_none_or(|trace| {
            trace.transcript_family != event.transcript_family
                || trace.transcript_path != event.transcript_path
        });
        if starts_new_trace {
            traces.push(TranscriptOrderAuditTrace {
                transcript_family: event.transcript_family.clone(),
                transcript_path: event.transcript_path.clone(),
                segments: Vec::new(),
                next_event_index: 0,
            });
        }
        let trace = traces
            .last_mut()
            .expect("a transcript-order trace must exist after insertion");
        assert_eq!(
            event.event_index, trace.next_event_index,
            "transcript-order events must be contiguous within each transcript path"
        );
        let can_extend_last_segment = trace.segments.last().is_some_and(|segment| {
            let squeeze_counter_is_next =
                match (segment.squeeze_counter_start, event.squeeze_counter) {
                    (None, None) => true,
                    (Some(start), Some(counter)) => counter == start + segment.event_count,
                    _ => false,
                };
            segment.operation == event.operation
                && segment.label == event.label
                && segment.byte_length == event.byte_length
                && squeeze_counter_is_next
        });
        if can_extend_last_segment {
            trace
                .segments
                .last_mut()
                .expect("a checked transcript-order segment must exist")
                .event_count += 1;
        } else {
            trace.segments.push(TranscriptOrderAuditSegment {
                event_count: 1,
                operation: event.operation.clone(),
                label: event.label.clone(),
                byte_length: event.byte_length,
                squeeze_counter_start: event.squeeze_counter,
            });
        }
        trace.next_event_index += 1;
    }
    traces
}
