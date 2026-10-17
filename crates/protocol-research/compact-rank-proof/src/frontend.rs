use crate::{
    Error, Result,
    field::*,
    relation::Relation,
    require,
    statement::{DEGREE, Statement},
};

pub struct Challenges {
    pub lookup: Element,
    pub lookup_weight: Element,
    pub affine: Element,
    pub combination: Element,
    pub point: Element,
}

pub fn check(
    statement: &Statement,
    relation: &Relation,
    challenges: &Challenges,
    mask_sum: Element,
    evaluations: &[Element],
    batch: Element,
) -> Result<(Vec<Vec<Element>>, Element)> {
    let first_count = relation.columns.len() + relation.families.len();
    let (first, tail) = evaluations.split_at(first_count);
    let (reciprocals, tail) = tail.split_at(relation.reciprocals.len());
    let [sum_mask, point_quotient, affine_quotient, short_remainder]: [Element; 4] =
        tail.try_into().unwrap();
    let point = challenges.point;
    let vanishing = subtract(power(point, DEGREE), ONE);
    let lagrange = lagrange(point, DEGREE);
    let (public_weights, public_constant) =
        relation.public_weights(statement, challenges.lookup_weight, &lagrange);
    let mut residual = ZERO;
    let mut weight = ONE;
    let mut point_term = |term| {
        residual = add(residual, multiply(weight, term));
        weight = multiply(weight, challenges.combination);
    };
    for (column, descriptor) in relation.columns.iter().enumerate() {
        if descriptor.range.is_none() {
            point_term(subtract(
                multiply(first[column], first[column]),
                first[column],
            ));
        }
    }
    point_term(multiply(first[relation.positive], first[relation.negative]));
    for (index, &column) in relation.reciprocals.iter().enumerate() {
        point_term(subtract(
            multiply(
                reciprocals[index],
                subtract(challenges.lookup, first[column]),
            ),
            ONE,
        ));
    }
    require(
        residual == multiply(vanishing, point_quotient),
        Error::Relation,
    )?;
    let mut affine = add(
        public_constant,
        dot(&public_weights, &first[..relation.columns.len()]),
    );
    let mut family_weight = power(challenges.lookup_weight, relation.affine_rows);
    for (family, &size) in relation.families.iter().enumerate() {
        let table = lagrange
            .iter()
            .enumerate()
            .fold(ZERO, |sum, (position, &coefficient)| {
                let value = if position < size { position } else { 0 };
                add(
                    sum,
                    multiply(
                        coefficient,
                        inverse(subtract(challenges.lookup, [value as u128, 0, 0])),
                    ),
                )
            });
        let inverse_sum = relation
            .reciprocals
            .iter()
            .enumerate()
            .filter(|&(_, &column)| relation.columns[column].range == Some(size))
            .fold(ZERO, |sum, (index, _)| add(sum, reciprocals[index]));
        let table_term = multiply(first[relation.columns.len() + family], table);
        affine = add(
            affine,
            multiply(family_weight, subtract(inverse_sum, table_term)),
        );
        family_weight = multiply(family_weight, challenges.lookup_weight);
    }
    require(
        subtract(
            add(multiply(challenges.affine, affine), sum_mask),
            scale(mask_sum, base::power(DEGREE as u128, MODULUS - 2)),
        ) == add(
            multiply(vanishing, affine_quotient),
            multiply(point, short_remainder),
        ),
        Error::Relation,
    )?;

    let mask_weights = [
        vanishing,
        multiply(vanishing, point),
        multiply(vanishing, multiply(point, point)),
    ];
    let mut forms = relation.lengths.map(Vec::with_capacity);
    let mut target = ZERO;
    let mut claim_weight = ONE;
    let mut claim = |group: usize, coefficients: &[Element], value: Element| {
        forms[group].extend(
            coefficients
                .iter()
                .map(|&coefficient| multiply(claim_weight, coefficient)),
        );
        target = add(target, multiply(claim_weight, value));
        claim_weight = multiply(claim_weight, batch);
    };
    for (index, active) in relation
        .columns
        .iter()
        .map(|column| column.active)
        .chain(relation.families.iter().copied())
        .enumerate()
    {
        let mut coefficients = lagrange[..active].to_vec();
        coefficients.extend_from_slice(&mask_weights);
        claim(0, &coefficients, first[index]);
    }
    claim(0, &[ONE, point, power(point, DEGREE)], sum_mask);
    let inactive = inverse(challenges.lookup);
    for (index, &column) in relation.reciprocals.iter().enumerate() {
        let active = relation.columns[column].active;
        let constant = multiply(inactive, lagrange[active..].iter().copied().fold(ZERO, add));
        let mut coefficients = lagrange[..active].to_vec();
        coefficients.extend_from_slice(&mask_weights);
        claim(1, &coefficients, subtract(reciprocals[index], constant));
    }
    for (length, value) in [
        (DEGREE + 5, point_quotient),
        (DEGREE + 5, affine_quotient),
        (DEGREE - 1, short_remainder),
    ] {
        claim(2, &powers(point, length), value);
    }
    assert_eq!(forms.each_ref().map(|form| form.len()), relation.lengths);
    Ok((forms.into(), target))
}
