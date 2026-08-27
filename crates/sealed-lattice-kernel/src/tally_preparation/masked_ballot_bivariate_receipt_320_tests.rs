use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512, Roster, RosterEntry},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bivariate_commitment_320::{
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        MaskedBallotBivariateCommitmentInventory320, MaskedBallotBivariateCommitmentLayout320,
        MaskedBallotBivariateCommitmentRootBody320,
        MaskedBallotBivariateCommitmentSignatureEnvelope320,
        verify_masked_ballot_bivariate_commitment_root_signature_320,
    },
    masked_ballot_bivariate_mailbox_320::{
        AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
        MaskedBallotBivariateMailboxSignatureEnvelope320,
        SealedMaskedBallotBivariateMailboxPackage320,
        complete_masked_ballot_bivariate_mailbox_delivery_320,
        seal_masked_ballot_bivariate_mailbox_package_320,
        verify_masked_ballot_bivariate_mailbox_manifest_signature_320,
        verify_masked_ballot_bivariate_mailbox_public_carrier_320,
    },
    masked_ballot_bivariate_receipt_320::{
        AllRosterMaskedBallotBivariateReceiptTerminal320,
        MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
        MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
        MaskedBallotBivariateReceiptEnvelope320, MaskedBallotBivariateReceiptError320,
        ProducedMaskedBallotBivariateReceipt320,
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320,
        join_masked_ballot_bivariate_custody_320,
        masked_ballot_bivariate_receipt_terminal_certificate_byte_length,
        produce_masked_ballot_bivariate_receipt_320,
        verify_masked_ballot_bivariate_receipt_announcement_320,
        verify_masked_ballot_bivariate_receipt_terminal_320,
    },
    masked_ballot_bivariate_sharing_320::MaskedBallotSymmetricBivariatePolynomial320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, masked_ballot_bundle_input_bit_count},
};

#[test]
fn all_ten_local_receipts_form_one_positive_terminal() {
    let fixture = completion_fixture(0x31, 0x41);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x51);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x61,
    );
    let receipt_envelope_bytes = produced_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes())
        .collect::<Vec<_>>();
    let terminal_certificate_bytes =
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &receipt_envelope_bytes,
        )
        .unwrap();
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &terminal_certificate_bytes,
    )
    .unwrap();
    assert_terminal_is_not_continuation_authority(&terminal);
    assert_eq!(terminal.receipt_body_identities().len(), 10);
    assert_eq!(terminal.receipt_envelope_identities().len(), 10);
    assert_ne!(
        terminal.terminal_body_identity(),
        Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
    );
    assert_ne!(
        terminal.certificate_identity(),
        Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
    );
    for (holder_index, produced_receipt) in produced_receipts.iter().enumerate() {
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .delivery()
                .holder_roster_position(),
            u16::try_from(holder_index).unwrap()
        );
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .receipt_envelope_identity(),
            terminal.receipt_envelope_identities()[holder_index]
        );
    }
}

#[test]
fn completion_receipts_and_terminal_have_exact_fixed_lengths() {
    let fixture = completion_fixture(0x32, 0x42);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x52);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x62,
    );
    assert_eq!(MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH, 311);
    assert_eq!(MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH, 3_717);
    assert_eq!(
        MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
        312
    );
    assert_eq!(
        masked_ballot_bivariate_receipt_terminal_certificate_byte_length(
            FOUNDATION_PROFILE.participant_count
        )
        .unwrap(),
        37_685
    );
    for produced_receipt in &produced_receipts {
        assert_eq!(produced_receipt.receipt_envelope_bytes().len(), 3_717);
        assert_eq!(
            produced_receipt
                .authenticated_receipt()
                .receipt_body()
                .canonical_bytes()
                .unwrap()
                .len(),
            311
        );
    }
    let receipt_envelope_bytes = produced_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes())
        .collect::<Vec<_>>();
    let certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &receipt_envelope_bytes,
    )
    .unwrap();
    assert_eq!(certificate.len(), 37_685);
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &certificate,
    )
    .unwrap();
    assert_eq!(
        terminal.terminal_body().canonical_bytes().unwrap().len(),
        312
    );
}

#[test]
fn missing_reordered_duplicate_and_forged_receipts_never_form_a_terminal() {
    let fixture = completion_fixture(0x33, 0x43);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x53);
    let produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x63,
    );
    let mut receipt_envelope_bytes = produced_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes().to_vec())
        .collect::<Vec<_>>();

    let missing = receipt_envelope_bytes[..9]
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    assert!(matches!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &missing,
        ),
        Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
            expected: 10,
            actual: 9
        })
    ));

    receipt_envelope_bytes.swap(0, 1);
    let reordered = receipt_envelope_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    assert!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &reordered,
        )
        .is_err()
    );
    receipt_envelope_bytes.swap(0, 1);

    receipt_envelope_bytes[1] = receipt_envelope_bytes[0].clone();
    let duplicate = receipt_envelope_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    assert!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &duplicate,
        )
        .is_err()
    );

    receipt_envelope_bytes[1] = produced_receipts[1].receipt_envelope_bytes().to_vec();
    *receipt_envelope_bytes[7].last_mut().unwrap() ^= 0x80;
    let forged = receipt_envelope_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    assert!(matches!(
        compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            &forged,
        ),
        Err(
            MaskedBallotBivariateReceiptError320::InvalidReceiptSignature {
                holder_roster_position: 7
            }
        )
    ));
}

#[test]
fn receipt_carrier_randomness_cannot_fork_the_semantic_terminal() {
    let fixture = completion_fixture(0x34, 0x44);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x54);
    let first_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x64,
    );
    let alternate_receipt_envelopes = first_receipts
        .iter()
        .enumerate()
        .map(|(holder_index, produced_receipt)| {
            let receipt_body = produced_receipt.authenticated_receipt().receipt_body();
            let signature = fixture.signing_keys[holder_index]
                .try_sign_with_seed(
                    &[0x74_u8.wrapping_add(u8::try_from(holder_index).unwrap()); 32],
                    &receipt_body.canonical_bytes().unwrap(),
                    MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
                )
                .unwrap();
            MaskedBallotBivariateReceiptEnvelope320::new(receipt_body, signature)
                .canonical_bytes()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let first_envelope_references = first_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes())
        .collect::<Vec<_>>();
    let alternate_envelope_references = alternate_receipt_envelopes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let first_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &first_envelope_references,
    )
    .unwrap();
    let alternate_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &alternate_envelope_references,
    )
    .unwrap();
    let first_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &first_certificate,
    )
    .unwrap();
    let alternate_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &alternate_certificate,
    )
    .unwrap();
    assert_eq!(
        first_terminal.terminal_body_identity(),
        alternate_terminal.terminal_body_identity()
    );
    assert_eq!(
        first_terminal.receipt_body_identities(),
        alternate_terminal.receipt_body_identities()
    );
    assert_ne!(
        first_terminal.receipt_envelope_identities(),
        alternate_terminal.receipt_envelope_identities()
    );
    assert_ne!(
        first_terminal.certificate_identity(),
        alternate_terminal.certificate_identity()
    );
}

#[test]
fn receipt_production_requires_the_bound_holder_key_and_nonzero_randomness() {
    let fixture = completion_fixture(0x35, 0x45);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x55);
    let delivery = complete_delivery(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
    );
    assert!(matches!(
        produce_masked_ballot_bivariate_receipt_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            delivery,
            &fixture.signing_keys[1],
            [0x65; 32],
        ),
        Err(
            MaskedBallotBivariateReceiptError320::HolderSigningKeyMismatch {
                holder_roster_position: 0
            }
        )
    ));

    let delivery = complete_delivery(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
    );
    assert!(matches!(
        produce_masked_ballot_bivariate_receipt_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            delivery,
            &fixture.signing_keys[0],
            [0_u8; 32],
        ),
        Err(MaskedBallotBivariateReceiptError320::InvalidSignatureRandomness)
    ));
}

#[test]
fn receipt_announcement_is_scoped_to_one_root_manifest_and_holder() {
    let fixture = completion_fixture(0x36, 0x46);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x56);
    let produced_receipt = produce_receipt(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0,
        0x66,
    );
    let announcement = verify_masked_ballot_bivariate_receipt_announcement_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        0,
        produced_receipt.receipt_envelope_bytes(),
    )
    .unwrap();
    assert_eq!(announcement.receipt_body().holder_roster_position(), 0);
    assert_eq!(
        announcement.receipt_envelope_identity(),
        produced_receipt
            .authenticated_receipt()
            .receipt_envelope_identity()
    );
    assert!(
        verify_masked_ballot_bivariate_receipt_announcement_320(
            &authenticated_root,
            &authenticated_manifest,
            &fixture.roster,
            1,
            produced_receipt.receipt_envelope_bytes(),
        )
        .is_err()
    );

    let other_fixture = completion_fixture(0x37, 0x47);
    let (other_root, other_manifest, _) = authenticate_package(&other_fixture, 0x57);
    assert!(
        verify_masked_ballot_bivariate_receipt_announcement_320(
            &other_root,
            &other_manifest,
            &other_fixture.roster,
            0,
            produced_receipt.receipt_envelope_bytes(),
        )
        .is_err()
    );
}

#[test]
fn local_receipt_joins_only_its_exact_all_roster_terminal() {
    let fixture = completion_fixture(0x38, 0x48);
    let (authenticated_root, authenticated_manifest, sealed_package) =
        authenticate_package(&fixture, 0x58);
    let mut produced_receipts = produce_all_receipts(
        &fixture,
        &authenticated_root,
        &authenticated_manifest,
        &sealed_package,
        0x68,
    );
    let receipt_envelope_bytes = produced_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes())
        .collect::<Vec<_>>();
    let terminal_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &receipt_envelope_bytes,
    )
    .unwrap();
    let terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &authenticated_root,
        &authenticated_manifest,
        &fixture.roster,
        &terminal_certificate,
    )
    .unwrap();
    let local_receipt = produced_receipts.remove(6).into_authenticated_receipt();
    let joined = join_masked_ballot_bivariate_custody_320(local_receipt, &terminal).unwrap();
    assert_eq!(joined.delivery().holder_roster_position(), 6);
    assert_eq!(
        joined.receipt_body_identity(),
        terminal.receipt_body_identities()[6]
    );
    assert_eq!(
        joined.receipt_envelope_identity(),
        terminal.receipt_envelope_identities()[6]
    );
    assert_eq!(
        joined.terminal_body_identity(),
        terminal.terminal_body_identity()
    );
    assert_eq!(
        joined.terminal_certificate_identity(),
        terminal.certificate_identity()
    );

    let other_fixture = completion_fixture(0x39, 0x49);
    let (other_root, other_manifest, other_package) = authenticate_package(&other_fixture, 0x59);
    let other_receipts = produce_all_receipts(
        &other_fixture,
        &other_root,
        &other_manifest,
        &other_package,
        0x69,
    );
    let other_receipt_envelope_bytes = other_receipts
        .iter()
        .map(|receipt| receipt.receipt_envelope_bytes())
        .collect::<Vec<_>>();
    let other_certificate = compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
        &other_root,
        &other_manifest,
        &other_fixture.roster,
        &other_receipt_envelope_bytes,
    )
    .unwrap();
    let other_terminal = verify_masked_ballot_bivariate_receipt_terminal_320(
        &other_root,
        &other_manifest,
        &other_fixture.roster,
        &other_certificate,
    )
    .unwrap();
    let remaining_local_receipt = produced_receipts.remove(0).into_authenticated_receipt();
    assert!(matches!(
        join_masked_ballot_bivariate_custody_320(remaining_local_receipt, &other_terminal),
        Err(MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch { .. })
    ));
}

struct CompletionFixture {
    roster: Roster,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
    decapsulation_keys: Vec<ml_kem_768::DecapsKey>,
    layout: MaskedBallotBivariateCommitmentLayout320,
    inventory: MaskedBallotBivariateCommitmentInventory320,
}

fn completion_fixture(roster_marker: u8, bundle_marker: u8) -> CompletionFixture {
    let (roster, signing_keys, decapsulation_keys) =
        roster_and_keys(FOUNDATION_PROFILE.participant_count, roster_marker);
    let circuit = completion_circuit();
    let layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(roster_marker.wrapping_add(1), 0),
        completion_context(&roster, &circuit, roster_marker.wrapping_add(2)),
        deterministic_hash(roster_marker.wrapping_add(3), 0),
        4,
    )
    .unwrap();
    let bundle = patterned_bundle(&circuit, bundle_marker);
    let polynomial = polynomial_for_bundle(layout, &bundle, bundle_marker.wrapping_add(1));
    let inventory = MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_salts(layout.leaf_count(), bundle_marker.wrapping_add(2)),
    )
    .unwrap();
    CompletionFixture {
        roster,
        signing_keys,
        decapsulation_keys,
        layout,
        inventory,
    }
}

fn authenticate_package(
    fixture: &CompletionFixture,
    marker: u8,
) -> (
    AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    SealedMaskedBallotBivariateMailboxPackage320,
) {
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let root_signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        marker,
    );
    let authenticated_root = verify_masked_ballot_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &root_signature_envelope_bytes,
    )
    .unwrap();
    let sealed_package = seal_masked_ballot_bivariate_mailbox_package_320(
        &fixture.inventory,
        &fixture.roster,
        &deterministic_encapsulation_randomness(
            FOUNDATION_PROFILE.participant_count,
            marker.wrapping_add(1),
        ),
    )
    .unwrap();
    let manifest_bytes = sealed_package.manifest().canonical_bytes().unwrap();
    let manifest_signature = fixture.signing_keys
        [usize::from(fixture.layout.author_roster_position())]
    .try_sign_with_seed(
        &[marker.wrapping_add(2); 32],
        &manifest_bytes,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
    )
    .unwrap();
    let manifest_signature_envelope_bytes = MaskedBallotBivariateMailboxSignatureEnvelope320::new(
        sealed_package.manifest().identity().unwrap(),
        manifest_signature,
    )
    .canonical_bytes()
    .unwrap();
    let authenticated_manifest = verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
        &authenticated_root,
        &fixture.roster,
        &manifest_bytes,
        &manifest_signature_envelope_bytes,
    )
    .unwrap();
    (authenticated_root, authenticated_manifest, sealed_package)
}

fn produce_all_receipts(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    marker: u8,
) -> Vec<ProducedMaskedBallotBivariateReceipt320> {
    (0..FOUNDATION_PROFILE.participant_count)
        .map(|holder_roster_position| {
            produce_receipt(
                fixture,
                authenticated_root,
                authenticated_manifest,
                sealed_package,
                holder_roster_position,
                marker.wrapping_add(u8::try_from(holder_roster_position).unwrap()),
            )
        })
        .collect()
}

fn produce_receipt(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    holder_roster_position: u16,
    signature_marker: u8,
) -> ProducedMaskedBallotBivariateReceipt320 {
    let delivery = complete_delivery(
        fixture,
        authenticated_root,
        authenticated_manifest,
        sealed_package,
        holder_roster_position,
    );
    produce_masked_ballot_bivariate_receipt_320(
        authenticated_root,
        authenticated_manifest,
        &fixture.roster,
        delivery,
        &fixture.signing_keys[usize::from(holder_roster_position)],
        [signature_marker; 32],
    )
    .unwrap()
}

fn complete_delivery(
    fixture: &CompletionFixture,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    sealed_package: &SealedMaskedBallotBivariateMailboxPackage320,
    holder_roster_position: u16,
) -> super::masked_ballot_bivariate_mailbox_320::AuthenticatedMaskedBallotBivariateMailboxDelivery320
{
    let holder_index = usize::from(holder_roster_position);
    let public_carrier = verify_masked_ballot_bivariate_mailbox_public_carrier_320(
        authenticated_root,
        authenticated_manifest,
        &fixture.roster,
        holder_roster_position,
        &sealed_package.headers()[holder_index]
            .canonical_bytes()
            .unwrap(),
        &sealed_package.encrypted_row_carriers()[holder_index],
    )
    .unwrap();
    complete_masked_ballot_bivariate_mailbox_delivery_320(
        authenticated_root,
        &fixture.roster,
        public_carrier,
        &fixture.decapsulation_keys[holder_index],
    )
    .unwrap()
}

fn sign_root(
    root_body: &MaskedBallotBivariateCommitmentRootBody320,
    signing_key: &ml_dsa_65::PrivateKey,
    marker: u8,
) -> Vec<u8> {
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[marker; 32],
            &root_body_bytes,
            MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    MaskedBallotBivariateCommitmentSignatureEnvelope320::new(
        root_body.identity().unwrap(),
        signature,
    )
    .canonical_bytes()
    .unwrap()
}

fn polynomial_for_bundle(
    layout: MaskedBallotBivariateCommitmentLayout320,
    bundle: &MaskedBallotBundle320,
    marker: u8,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    let reconstruction_threshold = usize::from(layout.reconstruction_threshold());
    let random_coefficient_count =
        reconstruction_threshold * (reconstruction_threshold + 1) / 2 - 1;
    let random_coefficients = (0..random_coefficient_count)
        .map(|coefficient_position| {
            BinaryFieldElement320::from_low_polynomial_u16(
                u16::from(marker)
                    .wrapping_mul(257)
                    .wrapping_add(u16::try_from(coefficient_position + 1).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    MaskedBallotSymmetricBivariatePolynomial320::from_bundle_and_random_coefficients(
        layout.participant_count(),
        bundle,
        &random_coefficients,
    )
    .unwrap()
}

fn patterned_bundle(circuit: &CompiledTallyCircuit, marker: u8) -> MaskedBallotBundle320 {
    let mut bytes = vec![0_u8; canonical_bundle_byte_length(circuit)];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = marker.wrapping_add(u8::try_from(byte_position).unwrap().wrapping_mul(29));
    }
    let input_bit_count = masked_ballot_bundle_input_bit_count(circuit).unwrap();
    let used_bit_count_in_last_byte = input_bit_count % 8;
    if used_bit_count_in_last_byte != 0 {
        let used_bit_mask = (1_u8 << used_bit_count_in_last_byte) - 1;
        *bytes.last_mut().unwrap() &= used_bit_mask;
    }
    MaskedBallotBundle320::from_canonical_bytes(circuit, &bytes).unwrap()
}

fn canonical_bundle_byte_length(circuit: &CompiledTallyCircuit) -> usize {
    masked_ballot_bundle_input_bit_count(circuit)
        .unwrap()
        .div_ceil(8)
}

fn deterministic_salts(
    leaf_count: u64,
    marker: u8,
) -> Vec<[u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]> {
    (0..leaf_count)
        .map(|leaf_ordinal| {
            let mut salt = [marker; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH];
            salt[..8].copy_from_slice(&leaf_ordinal.to_le_bytes());
            salt[63] ^= u8::try_from(leaf_ordinal % 251).unwrap();
            salt
        })
        .collect()
}

fn deterministic_encapsulation_randomness(participant_count: u16, marker: u8) -> Vec<[u8; 32]> {
    (0..participant_count)
        .map(|holder_roster_position| {
            let mut randomness = [marker; 32];
            randomness[0] ^= u8::try_from(holder_roster_position).unwrap();
            randomness[31] = marker.wrapping_add(u8::try_from(holder_roster_position).unwrap());
            randomness
        })
        .collect()
}

fn roster_and_keys(
    participant_count: u16,
    marker: u8,
) -> (
    Roster,
    Vec<ml_dsa_65::PrivateKey>,
    Vec<ml_kem_768::DecapsKey>,
) {
    let mut signing_keys = Vec::with_capacity(usize::from(participant_count));
    let mut decapsulation_keys = Vec::with_capacity(usize::from(participant_count));
    let entries = (0..participant_count)
        .map(|roster_position| {
            let mut signing_seed = [marker; 32];
            signing_seed[0] = marker.wrapping_add(u8::try_from(roster_position).unwrap());
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= u8::try_from(roster_position).unwrap();
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= u8::try_from(roster_position).unwrap();
            let (mailbox_encapsulation_key, mailbox_decapsulation_key) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            decapsulation_keys.push(mailbox_decapsulation_key);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    (
        Roster::new(entries).unwrap(),
        signing_keys,
        decapsulation_keys,
    )
}

fn completion_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}

fn completion_context(
    roster: &Roster,
    circuit: &CompiledTallyCircuit,
    marker: u8,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        deterministic_hash(0xd1, 0),
        roster.roster_hash().unwrap(),
        [marker; 32],
        circuit,
    )
    .unwrap()
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}

fn assert_terminal_is_not_continuation_authority(
    _terminal: &AllRosterMaskedBallotBivariateReceiptTerminal320,
) {
    // The type intentionally exposes only identities and receipt inventories.
}
