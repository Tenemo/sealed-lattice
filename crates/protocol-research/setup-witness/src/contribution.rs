use super::*;
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
    plan: Plan,
    auxiliary_plan: Plan,
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
pub fn common_polynomial(profile: Profile, index: usize) -> Result<Vec<BigInt>, Error> {
    if let Some((gadget, component)) = profile.fhe_polynomial_position(index) {
        let name = match component {
            0 => "a",
            3 => "u",
            5 => "k",
            _ => return Err(Error::Phase),
        };
        Ok(public_polynomial(
            &format!("common-fhe-{name}-{gadget}"),
            DEGREE,
            &integer(&profile.family_modulus(Family::Fhe)),
            profile.fhe_common_sample_bits(),
        ))
    } else if index == profile.share_common_polynomial() {
        Ok(common_share_polynomial())
    } else if index == profile.auxiliary_common_polynomial() {
        Ok(public_polynomial(
            "common-auxiliary",
            AUXILIARY_DEGREE,
            &integer(auxiliary_modulus()),
            fixed_common_sample_bits(),
        ))
    } else {
        Err(Error::Phase)
    }
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
            plan,
            auxiliary_plan,
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
        let plan = &self.plan;
        let secret = &self.secret;
        let auxiliary = &self.auxiliary;
        let witness = &mut self.witness;
        let limbs = profile.fhe_limbs();
        let width = profile.family_magnitude_bytes(Family::Fhe);
        let digit = BigInt::from(1) << (Profile::gadget_base_bits() * gadget);

        let common = common_polynomial(profile, profile.fhe_polynomial(gadget, 0))?;
        output.polynomial(&common, modulus, width);
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("encryption-{gadget}"),
                common: &common,
                left: secret,
                right: &auxiliary.values,
                multiplier: BigInt::from(0),
                automorphism: 1,
                modulus,
                limbs,
                width,
            },
        );
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("first-relinearization-{gadget}"),
                common: &common,
                left: auxiliary,
                right: &secret.values,
                multiplier: digit.clone(),
                automorphism: 1,
                modulus,
                limbs,
                width,
            },
        );
        let common = common_polynomial(profile, profile.fhe_polynomial(gadget, 3))?;
        output.polynomial(&common, modulus, width);
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("second-relinearization-{gadget}"),
                common: &common,
                left: secret,
                right: &auxiliary.values,
                multiplier: -digit.clone(),
                automorphism: 1,
                modulus,
                limbs,
                width,
            },
        );
        let common = common_polynomial(profile, profile.fhe_polynomial(gadget, 5))?;
        output.polynomial(&common, modulus, width);
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("automorphism-{gadget}"),
                common: &common,
                left: secret,
                right: &secret.values,
                multiplier: digit,
                automorphism: 5,
                modulus,
                limbs,
                width,
            },
        );

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
            &self.plan,
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
        key(
            &mut self.witness,
            output,
            &self.auxiliary_plan,
            KeyInput {
                label: "auxiliary-key",
                common: &common,
                left: &self.auxiliary_secret,
                right: &self.auxiliary_secret.values,
                multiplier: BigInt::from(0),
                automorphism: 1,
                modulus: &self.auxiliary_modulus,
                limbs: 1,
                width,
            },
        );
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
