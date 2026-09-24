use super::*;
#[derive(Debug)]
pub enum Error {
    Phase,
    PublicKey,
}
pub struct Contribution {
    pub(super) plan: Plan,
    auxiliary_plan: Plan,
    modulus: BigInt,
    pub(super) share_modulus: BigInt,
    auxiliary_modulus: BigInt,
    witness: Witness,
    pub(super) secret: Sparse,
    auxiliary: Sparse,
    ephemerals: Vec<Sparse>,
    auxiliary_secret: Sparse,
    pub(super) sharing: Zeroizing<Vec<Vec<i128>>>,
    common_share: Option<Vec<BigInt>>,
    next_gadget: usize,
    next_recipient: usize,
    finished: bool,
}
pub fn statement_header() -> Vec<u8> {
    let mut bytes = Vec::from(b"SCO1".as_slice());
    bytes.extend((DEGREE as u32).to_le_bytes());
    bytes.extend((AUXILIARY_DEGREE as u32).to_le_bytes());
    bytes.extend(&PARAMETERS[4..]);
    bytes
}
impl Default for Contribution {
    fn default() -> Self {
        Self::new()
    }
}
pub fn common_polynomial(index: usize) -> Result<Vec<BigInt>, Error> {
    let (label, degree, bytes) = if index < 42 {
        let name = match index % 7 {
            0 => "a",
            3 => "u",
            5 => "k",
            _ => return Err(Error::Phase),
        };
        (
            format!("common-fhe-{name}-{}", index / 7),
            DEGREE,
            &PARAMETERS[4..112],
        )
    } else if index == 42 {
        ("common-share".to_owned(), DEGREE, &PARAMETERS[112..132])
    } else if index == 73 {
        (
            "common-auxiliary".to_owned(),
            AUXILIARY_DEGREE,
            &PARAMETERS[132..137],
        )
    } else {
        return Err(Error::Phase);
    };
    Ok(public_polynomial(
        &label,
        degree,
        &BigInt::from_bytes_le(Sign::Plus, bytes),
    ))
}
impl Contribution {
    pub fn new() -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[4..112]);
        let share_modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[112..132]);
        let auxiliary_modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[132..137]);
        let plan = Plan::new(DEGREE);
        let auxiliary_plan = Plan::new(AUXILIARY_DEGREE);
        let mut witness = Witness::new();
        let secret = witness.sparse("fhe-secret", DEGREE, 1024, &plan);
        let auxiliary = witness.sparse("fhe-auxiliary", DEGREE, 1024, &plan);
        let ephemerals = (0..10)
            .map(|index| witness.sparse(&format!("share-ephemeral-{index}"), DEGREE, 256, &plan))
            .collect();
        let auxiliary_secret =
            witness.sparse("auxiliary-secret", AUXILIARY_DEGREE, 256, &auxiliary_plan);
        let sharing = Zeroizing::new(
            (0..3)
                .map(|index| {
                    let mut random = private_reader(&format!("sharing-{index}"));
                    (0..DEGREE)
                        .map(|_| {
                            let mut bytes = Zeroizing::new([0; 16]);
                            random.read(bytes.as_mut());
                            (u128::from_le_bytes(*bytes) & ((1u128 << 114) - 1)) as i128
                                - (1i128 << 113)
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );
        for coefficient in sharing.iter() {
            witness.signed(114, coefficient);
        }
        Self {
            plan,
            auxiliary_plan,
            modulus,
            share_modulus,
            auxiliary_modulus,
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
    pub fn gadget(
        &mut self,
        gadget: usize,
        output: &mut impl PolynomialOutput,
    ) -> Result<(), Error> {
        if gadget != self.next_gadget || gadget >= 6 || self.common_share.is_some() {
            return Err(Error::Phase);
        }
        let modulus = &self.modulus;
        let plan = &self.plan;
        let secret = &self.secret;
        let auxiliary = &self.auxiliary;
        let witness = &mut self.witness;

        let common = common_polynomial(7 * gadget)?;
        output.polynomial(&common, modulus, 108);
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
                limbs: 9,
                width: 108,
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
                multiplier: BigInt::from(1) << (144 * gadget),
                automorphism: 1,
                modulus,
                limbs: 9,
                width: 108,
            },
        );
        let common = common_polynomial(7 * gadget + 3)?;
        output.polynomial(&common, modulus, 108);
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("second-relinearization-{gadget}"),
                common: &common,
                left: secret,
                right: &auxiliary.values,
                multiplier: -(BigInt::from(1) << (144 * gadget)),
                automorphism: 1,
                modulus,
                limbs: 9,
                width: 108,
            },
        );
        let common = common_polynomial(7 * gadget + 5)?;
        output.polynomial(&common, modulus, 108);
        key(
            witness,
            output,
            plan,
            KeyInput {
                label: &format!("automorphism-{gadget}"),
                common: &common,
                left: secret,
                right: &secret.values,
                multiplier: BigInt::from(1) << (144 * gadget),
                automorphism: 5,
                modulus,
                limbs: 9,
                width: 108,
            },
        );

        self.next_gadget += 1;
        Ok(())
    }
    pub fn begin_shares(&mut self, output: &mut impl PolynomialOutput) -> Result<(), Error> {
        if self.next_gadget != 6 || self.common_share.is_some() {
            return Err(Error::Phase);
        }
        let common = common_polynomial(42)?;
        output.polynomial(&common, &self.share_modulus, 20);
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
            || recipient >= 10
            || self.finished
        {
            return Err(Error::Phase);
        }
        let half = &self.share_modulus >> 1usize;
        if public_key.len() != DEGREE || public_key.iter().any(|value| value.abs() > half) {
            return Err(Error::PublicKey);
        }
        output.polynomial(public_key, &self.share_modulus, 20);
        let ciphertexts = share_ciphertexts(
            &mut self.witness,
            output,
            &self.plan,
            ShareInput {
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
        if self.next_recipient != 10 || self.finished {
            return Err(Error::Phase);
        }
        let common = common_polynomial(73)?;
        output.polynomial(&common, &self.auxiliary_modulus, 5);
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
                width: 5,
            },
        );
        self.finished = true;
        Ok(())
    }
    pub fn into_witness(self) -> Result<Witness, Error> {
        if !self.finished {
            return Err(Error::Phase);
        }
        Ok(self.witness)
    }
}
