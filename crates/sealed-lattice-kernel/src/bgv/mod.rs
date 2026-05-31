pub(crate) mod commands;
pub(crate) mod profile;

mod base_conversion;
mod encoding;
pub(crate) mod evaluator;
mod modular_arithmetic;
mod ntt;
mod rns;
mod serialization;
mod setup;
mod setup_helpers;
mod validation;

#[cfg(test)]
pub const MODULE_MARKER: &str = "bgv";
