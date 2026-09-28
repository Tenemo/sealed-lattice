use super::*;
use parallel_work::{Job, Part, Ticket, submit};
use supported_profile::{
    AUXILIARY_SECRET_SUPPORT, FHE_SECRET_SUPPORT, Family, SHARE_EPHEMERAL_SUPPORT,
    auxiliary_modulus, fixed_common_sample_bits, share_modulus,
};
#[derive(Debug)]
pub enum Error {
    Phase,
    PublicKey,
}
pub struct Contribution {
    profile: Profile,
    modulus: BigInt,
    share_modulus: BigInt,
    auxiliary_modulus: BigInt,
    witness: Witness,
    secret: Sparse,
    auxiliary: Sparse,
    ephemerals: Vec<Sparse>,
    auxiliary_secret: Sparse,
    sharing: Zeroizing<Vec<Vec<i128>>>,
    common_share: Option<Vec<BigInt>>,
    next_gadget: usize,
    next_recipient: usize,
    finished: bool,
}
/// The common share polynomial. Registration keys use it before the roster,
/// and so the profile, is known.
pub fn common_share_polynomial() -> Vec<BigInt> {
    public_polynomial(
        "common-share",
        DEGREE,
        &integer(share_modulus()),
        fixed_common_sample_bits(),
    )
}
// The label, ring degree, modulus and sample bits of a common polynomial.
fn common_source(profile: Profile, index: usize) -> Result<(String, usize, Vec<u8>, usize), Error> {
    if let Some((gadget, component)) = profile.fhe_polynomial_position(index) {
        let name = match component {
            0 => "a",
            3 => "u",
            5 => "k",
            _ => return Err(Error::Phase),
        };
        Ok((
            format!("common-fhe-{name}-{gadget}"),
            DEGREE,
            profile.family_modulus(Family::Fhe),
            profile.fhe_common_sample_bits(),
        ))
    } else if index == profile.share_common_polynomial() {
        Ok((
            "common-share".to_owned(),
            DEGREE,
            share_modulus().to_vec(),
            fixed_common_sample_bits(),
        ))
    } else if index == profile.auxiliary_common_polynomial() {
        Ok((
            "common-auxiliary".to_owned(),
            AUXILIARY_DEGREE,
            auxiliary_modulus().to_vec(),
            fixed_common_sample_bits(),
        ))
    } else {
        Err(Error::Phase)
    }
}
/// A common polynomial. An FHE one reduces its samples modulo the
/// ciphertext modulus, a Proth prime, without dividing.
pub fn common_polynomial(profile: Profile, index: usize) -> Result<Vec<BigInt>, Error> {
    let (label, degree, modulus, sample_bits) = common_source(profile, index)?;
    Ok(if profile.fhe_polynomial_position(index).is_some() {
        proth_public_polynomial(&label, degree, profile.ciphertext_modulus(), sample_bits)
    } else {
        public_polynomial(&label, degree, &integer(&modulus), sample_bits)
    })
}
/// The canonical records of a common polynomial: each coefficient's sign
/// byte and its magnitude in the family's magnitude bytes.
pub fn common_records(profile: Profile, index: usize) -> Result<Vec<u8>, Error> {
    let (label, degree, modulus, sample_bits) = common_source(profile, index)?;
    Ok(if profile.fhe_polynomial_position(index).is_some() {
        proth_public_records(&label, degree, profile.ciphertext_modulus(), sample_bits)
    } else {
        public_records(&label, degree, &modulus, sample_bits)
    })
}
/// A common polynomial's canonical records, which helper instances of the
/// participant module compute. Its input is the profile's participant and
/// option counts and the polynomial's index, which the owner checks.
pub static COMMON_RECORDS: Job = Job {
    kind: 0x0500,
    run: run_common_records,
};
fn run_common_records(input: &[u8]) -> Vec<u8> {
    let [participants, options, index] = std::array::from_fn(|position| {
        u32::from_le_bytes(input[4 * position..4 * (position + 1)].try_into().unwrap()) as usize
    });
    let profile = Profile::new(participants, options).expect("Checked profile");
    common_records(profile, index).expect("Checked common polynomial")
}
/// Starts the canonical records of a common polynomial of the profile.
pub fn common_records_job(profile: Profile, index: usize) -> Result<Ticket, Error> {
    let (_, degree, modulus, _) = common_source(profile, index)?;
    let input: Vec<u8> = [profile.participants(), profile.options(), index]
        .into_iter()
        .flat_map(|value| (value as u32).to_le_bytes())
        .collect();
    Ok(submit(
        &COMMON_RECORDS,
        None,
        &[Part::Bytes(&input)],
        degree * (1 + modulus.len()),
    ))
}
impl Contribution {
    pub fn new(profile: Profile) -> Self {
        let modulus = integer(&profile.family_modulus(Family::Fhe));
        let plan = Plan::new(DEGREE);
        let auxiliary_plan = Plan::new(AUXILIARY_DEGREE);
        let mut witness = Witness::new();
        let secret = witness.sparse("fhe-secret", DEGREE, FHE_SECRET_SUPPORT, &plan);
        let auxiliary = witness.sparse("fhe-auxiliary", DEGREE, FHE_SECRET_SUPPORT, &plan);
        let ephemerals = (0..profile.participants())
            .map(|index| {
                witness.sparse(
                    &format!("share-ephemeral-{index}"),
                    DEGREE,
                    SHARE_EPHEMERAL_SUPPORT,
                    &plan,
                )
            })
            .collect();
        let auxiliary_secret = witness.sparse(
            "auxiliary-secret",
            AUXILIARY_DEGREE,
            AUXILIARY_SECRET_SUPPORT,
            &auxiliary_plan,
        );
        let bits = profile.sharing_coefficient_bits();
        let sharing = Zeroizing::new(
            (0..profile.sharing_degree())
                .map(|index| {
                    let mut random = private_reader(&format!("sharing-{index}"));
                    (0..DEGREE)
                        .map(|_| {
                            let mut bytes = Zeroizing::new([0; 16]);
                            random.read(bytes.as_mut());
                            (u128::from_le_bytes(*bytes) & ((1u128 << bits) - 1)) as i128
                                - (1i128 << (bits - 1))
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );
        // Each coefficient c = low + 2^limb * high + 2^(limb - 1) with signed
        // limb-bit low and (bits - limb)-bit high parts.
        let limb = profile.share_limb_bits();
        for coefficient in sharing.iter() {
            let low = Zeroizing::new(
                coefficient
                    .iter()
                    .map(|value| value.rem_euclid(1 << limb) - (1 << (limb - 1)))
                    .collect::<Vec<_>>(),
            );
            let high = Zeroizing::new(
                coefficient
                    .iter()
                    .map(|value| value.div_euclid(1 << limb))
                    .collect::<Vec<_>>(),
            );
            witness.signed(limb, &low);
            witness.signed(bits - limb, &high);
        }
        Self {
            profile,
            modulus,
            share_modulus: integer(share_modulus()),
            auxiliary_modulus: integer(auxiliary_modulus()),
            witness,
            secret,
            auxiliary,
            ephemerals,
            auxiliary_secret,
            sharing,
            common_share: None,
            next_gadget: 0,
            next_recipient: 0,
            finished: false,
        }
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn gadget(
        &mut self,
        gadget: usize,
        output: &mut impl PolynomialOutput,
    ) -> Result<(), Error> {
        let profile = self.profile;
        if gadget != self.next_gadget
            || gadget >= profile.gadget_length()
            || self.common_share.is_some()
        {
            return Err(Error::Phase);
        }
        let modulus = &self.modulus;
        let secret = &self.secret;
        let auxiliary = &self.auxiliary;
        let witness = &mut self.witness;
        let limbs = profile.fhe_limbs();
        let width = profile.family_magnitude_bytes(Family::Fhe);
        let digit = BigInt::from(1) << (Profile::gadget_base_bits() * gadget);

        // Each key's products start before the previous key's reduction, so
        // the helpers compute them while this instance reduces.
        let first = common_polynomial(profile, profile.fhe_polynomial(gadget, 0))?;
        let encryption = KeyInput {
            label: &format!("encryption-{gadget}"),
            common: &first,
            left: secret,
            right: &auxiliary.values,
            multiplier: BigInt::from(0),
            automorphism: 1,
            modulus,
            limbs,
            width,
        };
        let encryption_products = encryption.products();
        let first_relinearization = KeyInput {
            label: &format!("first-relinearization-{gadget}"),
            common: &first,
            left: auxiliary,
            right: &secret.values,
            multiplier: digit.clone(),
            automorphism: 1,
            modulus,
            limbs,
            width,
        };
        let first_relinearization_products = first_relinearization.products();
        output.polynomial(&first, modulus, width);
        key(witness, output, encryption, encryption_products);
        let second = common_polynomial(profile, profile.fhe_polynomial(gadget, 3))?;
        let second_relinearization = KeyInput {
            label: &format!("second-relinearization-{gadget}"),
            common: &second,
            left: secret,
            right: &auxiliary.values,
            multiplier: -digit.clone(),
            automorphism: 1,
            modulus,
            limbs,
            width,
        };
        let second_relinearization_products = second_relinearization.products();
        key(
            witness,
            output,
            first_relinearization,
            first_relinearization_products,
        );
        drop(first);
        let third = common_polynomial(profile, profile.fhe_polynomial(gadget, 5))?;
        let automorphism = KeyInput {
            label: &format!("automorphism-{gadget}"),
            common: &third,
            left: secret,
            right: &secret.values,
            multiplier: digit,
            automorphism: 5,
            modulus,
            limbs,
            width,
        };
        let automorphism_products = automorphism.products();
        output.polynomial(&second, modulus, width);
        key(
            witness,
            output,
            second_relinearization,
            second_relinearization_products,
        );
        drop(second);
        output.polynomial(&third, modulus, width);
        key(witness, output, automorphism, automorphism_products);

        self.next_gadget += 1;
        Ok(())
    }
    pub fn begin_shares(&mut self, output: &mut impl PolynomialOutput) -> Result<(), Error> {
        if self.next_gadget != self.profile.gadget_length() || self.common_share.is_some() {
            return Err(Error::Phase);
        }
        let common = common_share_polynomial();
        output.polynomial(&common, &self.share_modulus, share_modulus().len());
        self.common_share = Some(common);
        Ok(())
    }
    pub fn share(
        &mut self,
        recipient: usize,
        public_key: &[BigInt],
        output: &mut impl PolynomialOutput,
    ) -> Result<Vec<Vec<BigInt>>, Error> {
        if self.common_share.is_none()
            || recipient != self.next_recipient
            || recipient >= self.profile.participants()
            || self.finished
        {
            return Err(Error::Phase);
        }
        let half = &self.share_modulus >> 1usize;
        if public_key.len() != DEGREE || public_key.iter().any(|value| value.abs() > half) {
            return Err(Error::PublicKey);
        }
        output.polynomial(public_key, &self.share_modulus, share_modulus().len());
        let ciphertexts = share_ciphertexts(
            &mut self.witness,
            output,
            ShareInput {
                profile: self.profile,
                recipient,
                common: self.common_share.as_ref().unwrap(),
                public_key,
                secret: &self.secret,
                sharing: &self.sharing,
                ephemeral: &self.ephemerals[recipient],
                modulus: &self.share_modulus,
            },
        );
        self.next_recipient += 1;
        Ok(ciphertexts)
    }
    pub fn finish(&mut self, output: &mut impl PolynomialOutput) -> Result<(), Error> {
        if self.next_recipient != self.profile.participants() || self.finished {
            return Err(Error::Phase);
        }
        let common = common_polynomial(self.profile, self.profile.auxiliary_common_polynomial())?;
        let width = auxiliary_modulus().len();
        output.polynomial(&common, &self.auxiliary_modulus, width);
        let input = KeyInput {
            label: "auxiliary-key",
            common: &common,
            left: &self.auxiliary_secret,
            right: &self.auxiliary_secret.values,
            multiplier: BigInt::from(0),
            automorphism: 1,
            modulus: &self.auxiliary_modulus,
            limbs: 1,
            width,
        };
        let products = input.products();
        key(&mut self.witness, output, input, products);
        self.finished = true;
        Ok(())
    }
    /// The witness columns: every word column, then every Boolean column, in
    /// the profile's setup layout.
    pub fn into_columns(mut self) -> Result<Vec<Vec<u16>>, Error> {
        let shape = self.profile.setup_shape();
        if !self.finished
            || self.witness.words.len() != shape.word_columns
            || self.witness.booleans.len() != shape.boolean_columns
        {
            return Err(Error::Phase);
        }
        let mut columns = std::mem::take(&mut self.witness.words);
        columns.append(&mut self.witness.booleans);
        Ok(columns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parallel_work::MAXIMUM_JOB_BYTES;

    // Every common polynomial's records fit one job output. The job, which
    // reconstructs the profile from its input, returns the direct records,
    // which decode to the common polynomial, and refuses other polynomials.
    #[test]
    fn common_records_jobs_match_the_direct_records() {
        let profiles: Vec<Profile> = Profile::all().collect();
        for profile in &profiles {
            for index in 0..profile.setup_polynomials() {
                if let Ok((_, degree, modulus, _)) = common_source(*profile, index) {
                    assert!(degree * (1 + modulus.len()) <= MAXIMUM_JOB_BYTES);
                }
            }
        }
        let widest = profiles
            .iter()
            .max_by_key(|profile| profile.family_magnitude_bytes(Family::Fhe))
            .unwrap();
        for profile in [profiles[0], *widest] {
            let last = profile.gadget_length() - 1;
            for index in [
                profile.fhe_polynomial(0, 0),
                profile.fhe_polynomial(last, 3),
                profile.fhe_polynomial(last, 5),
                profile.share_common_polynomial(),
                profile.auxiliary_common_polynomial(),
            ] {
                let records = common_records(profile, index).unwrap();
                assert_eq!(*common_records_job(profile, index).unwrap().wait(), records);
                let values = common_polynomial(profile, index).unwrap();
                let width = records.len() / values.len();
                for (record, value) in records.chunks_exact(width).zip(values) {
                    let sign = if record[0] == 1 {
                        Sign::Minus
                    } else {
                        Sign::Plus
                    };
                    assert_eq!(BigInt::from_bytes_le(sign, &record[1..]), value);
                }
            }
            for index in [
                profile.fhe_polynomial(0, 1),
                profile.recipient_key_polynomial(0),
                profile.auxiliary_key_polynomial(),
            ] {
                assert!(common_records_job(profile, index).is_err());
            }
        }
    }
}
