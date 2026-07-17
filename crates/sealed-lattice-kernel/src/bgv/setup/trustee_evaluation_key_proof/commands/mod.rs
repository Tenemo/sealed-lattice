pub(in crate::bgv::setup) struct VssPublicCommandCommitmentExpectation<'a> {
    pub(in crate::bgv::setup) field_name: String,
    pub(in crate::bgv::setup) root: &'a str,
}

mod vss_commitment_parsing;

pub(in crate::bgv::setup) use vss_commitment_parsing::vss_share_linkage_commitment_from_value;
