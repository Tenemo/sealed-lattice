//! The evaluation target: its evaluation from the classified ballots and the
//! close barrier, and the participant's retained copy.
use super::{SESSION, Session};
use ballot_proof::body::BallotBodyClassification;
use evaluation_target::{
    close::VerifiedCloseBarrier,
    target::VerifiedEvaluationTarget,
    target_session::{EVALUATION_INPUT_BYTES, EvaluationInputs, TargetSession},
};
use protocol_foundations::poll::VerifiedPoll;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{cell::RefCell, sync::Arc};
/// Emits the target this instance evaluated, keyed to the restored
/// credential, so that a later visit restores it instead of evaluating
/// again.
#[unsafe(no_mangle)]
pub extern "C" fn retain_evaluation() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let (Some(enrollment), Some(target)) = (state.enrollment.as_ref(), verified_target())
        else {
            return 1;
        };
        let Ok(retained) = target.retain(&enrollment.credential) else {
            return 1;
        };
        state.contribution_output = retained;
        0
    })
}

fn restore_evaluation_step(state: &mut Session, operation: u32, length: usize) -> Option<()> {
    match operation {
        0 => {
            let (_, setup) = super::setup_verification::verified_setup()?;
            let maximum = 8
                + protocol_foundations::target_signing::MAXIMUM_TARGET_BODY_BYTES
                + 2 * supported_profile::relation::SYSTEMATIC
                    * supported_profile::relation::release_coefficient_bytes(setup.profile())
                + protocol_foundations::RETAINED_TAG_BYTES;
            (state.evaluation.is_none() && length <= maximum).then_some(())?;
            state.evaluation = Some((length, Vec::with_capacity(length)));
        }
        1 => {
            let bytes = state.input.get(..length)?;
            let (expected, copy) = state.evaluation.as_mut()?;
            (length <= *expected - copy.len()).then_some(())?;
            copy.extend(bytes);
        }
        2 => {
            let (expected, copy) = state.evaluation.take()?;
            (length == 0 && copy.len() == expected).then_some(())?;
            let (poll, setup) = super::setup_verification::verified_setup()?;
            let target = evaluation_target::target::VerifiedEvaluationTarget::restore(
                &state.enrollment.as_ref()?.credential,
                poll,
                setup,
                &copy,
            )
            .ok()?;
            TARGET
                .with(|session| session.borrow_mut().restore_target(target))
                .then_some(())?;
        }
        _ => return None,
    }
    Some(())
}
/// Restores the target this participant evaluated from its retained copy,
/// which the host streams in: operation zero begins a copy of the given
/// length, one appends that many input bytes and two restores the complete
/// copy for this instance's verified poll and setup.
#[unsafe(no_mangle)]
pub extern "C" fn restore_evaluation(operation: u32, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let restored = restore_evaluation_step(&mut state, operation, length);
        if restored.is_none() {
            state.evaluation = None;
        }
        u32::from(restored.is_none())
    })
}

thread_local! {static TARGET: RefCell<TargetSession> = RefCell::new(TargetSession::new());}

// The instance's other verifiers, which the evaluation target reads.
struct InstanceInputs;
impl EvaluationInputs for InstanceInputs {
    fn setup(&mut self) -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
        super::setup_verification::verified_setup()
    }
    fn take_classification(&mut self) -> Option<BallotBodyClassification> {
        super::ballot::take_classification()
    }
    fn release_ballot_inputs(&mut self) {
        super::ballot::release_ballot_inputs();
    }
    fn take_barrier(&mut self) -> Option<VerifiedCloseBarrier> {
        super::close::take_barrier()
    }
}

pub(super) fn verified_target() -> Option<Arc<VerifiedEvaluationTarget>> {
    TARGET.with(|target| target.borrow().target())
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_input_pointer() -> usize {
    TARGET.with(|target| target.borrow_mut().input().as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_input_capacity() -> usize {
    EVALUATION_INPUT_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_output_pointer() -> usize {
    TARGET.with(|target| target.borrow().output().as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_output_length() -> usize {
    TARGET.with(|target| target.borrow().output().len())
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_command(operation: u32, argument: usize, length: usize) -> u32 {
    TARGET.with(|target| {
        u32::from(
            target
                .borrow_mut()
                .command(&mut InstanceInputs, operation, argument, length)
                .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_body_pointer() -> usize {
    verified_target().map_or(0, |target| target.body().as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_body_length() -> usize {
    verified_target().map_or(0, |target| target.body().len())
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_finished() -> u32 {
    TARGET.with(|target| u32::from(target.borrow().finished()))
}
