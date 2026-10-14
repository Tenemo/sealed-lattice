use super::*;
use parallel_work::ProtocolHash;

fn element(seed: usize) -> Element {
    let value = |offset: usize| {
        (seed as u128 * 0x9e37_79b9_7f4a_7c15 + offset as u128 * 0x632b_e59b_d9b4_e019) % MODULUS
    };
    [value(1), value(2), value(3)]
}

// Every kind of public column, at full and reduced degrees, gives each
// relation column the values at the queries that evaluating the column's
// every row gives; a column no term names is zero.
#[test]
fn terms_give_every_column_the_values_of_its_rows() {
    let reduced = SYSTEMATIC / 16;
    let terms = vec![
        (PublicColumn::Powers(SYSTEMATIC), vec![0, 1, 3]),
        (PublicColumn::Powers(reduced), vec![1, 4]),
        (PublicColumn::Ones(SYSTEMATIC), vec![2, 3]),
        (PublicColumn::Ones(reduced), vec![0, 4]),
        (
            PublicColumn::Values((0..SYSTEMATIC).map(|row| element(row + 7)).collect()),
            vec![3, 5],
        ),
        (
            PublicColumn::Values((0..reduced).map(|row| element(row + 3)).collect()),
            vec![1, 5],
        ),
    ];
    let operator = Operator {
        alpha: element(1),
        terms: terms
            .into_iter()
            .enumerate()
            .map(|(term, (public, columns))| Term {
                public,
                weights: columns
                    .into_iter()
                    .map(|column| (column, element(100 * term + column)))
                    .collect(),
            })
            .collect(),
        target: ZERO,
        lookup_weight: ZERO,
    };
    let queries = [
        0,
        1,
        2,
        3,
        17,
        1000,
        SYSTEMATIC as u32,
        EVALUATION_DOMAIN_SIZE as u32 - 1,
    ];
    let columns = operator.columns(7);
    assert!(columns[6].iter().all(|value| *value == ZERO));
    let expected = evaluate_public_columns(columns, &queries).unwrap();
    assert_eq!(operator.at_queries(7, &queries).unwrap(), expected);
}

// A column's sum is the sum of the values it places.
#[test]
fn public_column_sums_add_their_values() {
    let alpha = element(5);
    let mut current = ONE;
    let mut expected = ZERO;
    for _ in 0..SYSTEMATIC / 16 {
        expected = plus(expected, current);
        current = times(current, alpha);
    }
    assert_eq!(PublicColumn::Powers(SYSTEMATIC / 16).sum(alpha), expected);
    assert_eq!(PublicColumn::Ones(4096).sum(alpha), [4096, 0, 0]);
    assert_eq!(
        PublicColumn::Values(vec![element(1), element(2)]).sum(alpha),
        plus(element(1), element(2))
    );
}

/// A two-byte header that must start with one, then two polynomials of
/// four coefficients modulo 251. The first polynomial's fingerprint weights
/// the only column on every row and the second's is the target.
struct Sums(Vec<Element>, Element);
impl OperatorBuilder for Sums {
    type Error = Error;
    const HEADER_BYTES: usize = 2;
    const POLYNOMIALS: usize = 2;
    fn columns(_: Profile) -> usize {
        1
    }
    fn polynomial_bytes(_: Profile, _: usize) -> usize {
        4 * 2
    }
    fn polynomial_stream(_: Profile, _: usize, alpha: Element) -> Result<PolynomialStream, Error> {
        PolynomialStream::new(&[251], 4, 17, alpha)
    }
    fn begin(_: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        if header[0] != 1 {
            return Err(Error::Encoding);
        }
        Ok(Self(Vec::new(), alpha))
    }
    fn polynomial(&mut self, _: usize, stream: PolynomialStream) -> Result<(), Error> {
        self.0.push(stream.finish_value()?);
        Ok(())
    }
    fn finish(self) -> Result<Operator, Error> {
        Ok(Operator {
            alpha: self.1,
            terms: vec![Term {
                public: PublicColumn::Ones(SYSTEMATIC),
                weights: vec![(0, self.0[0])],
            }],
            target: self.0[1],
            lookup_weight: ZERO,
        })
    }
}

// The statement streams in parts of any size; its digest must be the one
// declared, and a byte short, extra or out of place, a bad challenge or
// query, and any part after a refusal is refused.
#[test]
fn header_then_polynomials_takes_exactly_the_declared_statement() {
    let profile = Profile::new(3, 2).unwrap();
    let alpha = [3, 5, 7];
    let queries = [1, 9, 40];
    let statement = [1, 0, 0, 1, 0, 2, 0, 3, 1, 125, 0, 4, 0, 0, 0, 1, 0, 1];
    let digest = |bytes: &[u8]| {
        let mut hash = ProtocolHash::new();
        hash.update(bytes);
        hash.finalize()
    };
    let open = |expected| HeaderThenPolynomials::<Sums>::new(profile, expected, alpha, &queries);
    let output = |bytes: &[u8], part: usize| {
        let mut stream = open(digest(bytes)).unwrap();
        for chunk in bytes.chunks(part) {
            stream.push(chunk)?;
        }
        stream.finish()
    };
    let fingerprint = |bytes: &[u8]| {
        let mut stream = PolynomialStream::new(&[251], 4, 17, alpha).unwrap();
        stream.push(bytes).unwrap();
        stream.finish_value().unwrap()
    };
    for part in [1, 3, statement.len()] {
        let output = output(&statement, part).unwrap();
        assert_eq!(output.statement_digest, digest(&statement));
        assert_eq!(output.coefficients, vec![fingerprint(&statement[2..10]); 3]);
        assert_eq!(output.target, fingerprint(&statement[10..]));
    }

    let mut header = statement;
    header[0] = 2;
    let mut negative_zero = statement;
    negative_zero[2] = 1;
    negative_zero[3] = 0;
    for refused in [
        &statement[..statement.len() - 1],
        &[&statement[..], &[0]].concat(),
        &[&statement[..], &statement[10..]].concat(),
        &header,
        &negative_zero,
    ] {
        assert!(output(refused, 4).is_err());
    }
    let mut wrong = open([0; 64]).unwrap();
    wrong.push(&statement).unwrap();
    assert!(wrong.finish().is_err());
    let refused: [&[u32]; 4] = [&[], &[9, 1], &[1, 1], &[EVALUATION_DOMAIN_SIZE as u32]];
    for queries in refused {
        assert!(HeaderThenPolynomials::<Sums>::new(profile, [0; 64], alpha, queries).is_err());
    }
    assert!(HeaderThenPolynomials::<Sums>::new(profile, [0; 64], [MODULUS, 0, 0], &[1]).is_err());
    let mut stopped = open(digest(&statement)).unwrap();
    assert!(stopped.push(&vec![0; CHUNK_LIMIT + 1]).is_err());
    assert!(stopped.push(&statement).is_err());
    assert!(stopped.finish().is_err());
}
