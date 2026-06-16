#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

#[cfg(not(target_arch = "wasm32"))]
pub(super) struct DirectBallotTimingStart(Instant);

#[cfg(target_arch = "wasm32")]
pub(super) struct DirectBallotTimingStart;

pub(super) struct DirectBallotTimingTotal {
    milliseconds: Option<u128>,
}

impl DirectBallotTimingStart {
    pub(super) fn now() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self(Instant::now())
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self
        }
    }

    pub(super) fn elapsed_milliseconds(&self) -> Option<u128> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Some(self.0.elapsed().as_millis())
        }
        #[cfg(target_arch = "wasm32")]
        {
            None
        }
    }
}

impl DirectBallotTimingTotal {
    pub(super) fn new() -> Self {
        Self {
            milliseconds: Some(0),
        }
    }

    pub(super) fn add(&mut self, elapsed_milliseconds: Option<u128>) {
        self.milliseconds = match (self.milliseconds, elapsed_milliseconds) {
            (Some(total), Some(elapsed)) => Some(total + elapsed),
            _ => None,
        };
    }

    pub(super) fn report_value(&self) -> String {
        direct_ballot_timing_report_value(self.milliseconds)
    }
}

pub(super) fn direct_ballot_timing_report_value(elapsed_milliseconds: Option<u128>) -> String {
    elapsed_milliseconds
        .map(|milliseconds| milliseconds.to_string())
        .unwrap_or_else(|| "not measured on wasm32-unknown-unknown".to_string())
}
