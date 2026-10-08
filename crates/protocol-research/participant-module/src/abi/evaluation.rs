//! The retained evaluated target.
use super::{SESSION, Session};
/// Emits the target this instance evaluated, keyed to the restored
/// credential, so that a later visit restores it instead of evaluating
/// again.
#[unsafe(no_mangle)]
pub extern "C" fn retain_evaluation() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let (Some(enrollment), Some(target)) = (
            state.enrollment.as_ref(),
            evaluation_target::verified_browser_target(),
        ) else {
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
            let (_, setup) = setup_aggregate::setup_browser::context()?;
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
            let (poll, setup) = setup_aggregate::setup_browser::context()?;
            let target = evaluation_target::target::VerifiedEvaluationTarget::restore(
                &state.enrollment.as_ref()?.credential,
                poll,
                setup,
                &copy,
            )
            .ok()?;
            evaluation_target::restore_browser_target(target).then_some(())?;
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
