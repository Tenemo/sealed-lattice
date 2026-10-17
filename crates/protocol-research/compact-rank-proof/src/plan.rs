use crate::field::MODULUS;
use num_bigint::BigUint;

pub struct Plan {
    pub domains: Vec<usize>,
    pub messages: Vec<usize>,
    pub rows: Vec<usize>,
    pub folds: Vec<usize>,
    pub queries: usize,
    pub masks: usize,
    pub rounds: usize,
    pub bytes: usize,
}

fn query_count(stages: usize) -> usize {
    let mut left = (BigUint::from(stages) << 305) * 5u32;
    let mut right = BigUint::from(8u32);
    let mut count = 1;
    while left > right {
        left *= 5u32;
        right *= 8u32;
        count += 1;
    }
    count
}
fn opening_bytes(domain: usize, width: usize, queries: usize, roots: usize) -> usize {
    let count = queries.min(domain);
    let mut siblings = 0;
    let mut parents = domain / 2;
    while parents != 0 {
        siblings += count.min(parents);
        parents /= 2;
    }
    roots * (4 + count * 132 + siblings * 64) + count * width * 48
}
impl Plan {
    fn compile(groups: &[usize], exponents: &[usize], queries: usize) -> Self {
        let domains: Vec<_> = exponents
            .iter()
            .map(|exponent| 1usize << exponent)
            .collect();
        let messages: Vec<_> = domains
            .iter()
            .map(|domain| domain / 4 - queries - 1)
            .collect();
        let mask_length = queries + 1;
        let mask_domain = (4 * (mask_length + queries) + 1).next_power_of_two();
        let mut rows = Vec::new();
        let mut folds = Vec::new();
        let mut masks = 0;
        let mut bytes = 0;
        let mut fields = 0;
        let mut algebraic = 0u64;
        for stage in 0..domains.len() {
            let active = if stage == 0 {
                groups
                    .iter()
                    .map(|length| length.div_ceil(messages[0]))
                    .sum()
            } else {
                messages[stage - 1].div_ceil(messages[stage])
            };
            let bits = active.next_power_of_two().ilog2() as usize;
            assert!(bits >= 1);
            rows.push(active);
            folds.push(bits);
            masks += bits;
            bytes += opening_bytes(
                domains[stage],
                active,
                queries,
                if stage == 0 { groups.len() } else { 1 },
            );
            bytes += opening_bytes(mask_domain, bits, queries, 1);
            fields += bits * mask_length + 1;
            algebraic += 1;
            for step in 1..=bits {
                algebraic += ((1 << (bits - step)) * domains[stage] + mask_length) as u64;
            }
            if stage + 1 < domains.len() {
                bytes += opening_bytes(mask_domain, 1, queries, 1);
                fields += 1;
                masks += 1;
                algebraic += (messages[stage] + 2 * queries + 1) as u64;
            }
        }
        let terminal = domains.len() - 1;
        bytes += opening_bytes(domains[terminal], 1, queries, 1)
            + opening_bytes(mask_domain, masks, queries, 1);
        fields += messages[terminal] + queries + masks * (mask_length + queries) + 1 + masks;
        algebraic += (domains[terminal] + masks * mask_domain + 1) as u64;
        let rounds = folds.iter().sum::<usize>() + 3 * domains.len();
        bytes += fields * 48 + (groups.len() + 3 * domains.len()) * 80 + rounds * 128 + 80;
        let field_order = BigUint::from(MODULUS).pow(3);
        let query_denominator = BigUint::from(8u32).pow(queries as u32);
        let numerator = &query_denominator * algebraic
            + BigUint::from(domains.len()) * BigUint::from(5u32).pow(queries as u32) * &field_order;
        assert!((numerator << 304) <= field_order * query_denominator);
        Self {
            domains,
            messages,
            rows,
            folds,
            queries,
            masks,
            rounds,
            bytes,
        }
    }

    pub fn select(groups: &[usize]) -> Self {
        let queries = [query_count(1), query_count(2), query_count(3)];
        let mut selected: Option<Self> = None;
        let mut consider = |exponents: &[usize]| {
            let plan = Self::compile(groups, exponents, queries[exponents.len() - 1]);
            if selected
                .as_ref()
                .is_none_or(|prior| prior.bytes >= plan.bytes)
            {
                selected = Some(plan);
            }
        };
        for first in 13..=20 {
            consider(&[first]);
            for second in 11..=16 {
                if second >= first {
                    continue;
                }
                consider(&[first, second]);
                for third in 11..=13 {
                    if third < second {
                        consider(&[first, second, third]);
                    }
                }
            }
        }
        selected.unwrap()
    }
}
