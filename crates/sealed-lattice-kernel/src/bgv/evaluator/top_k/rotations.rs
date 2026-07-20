use crate::{
    bgv::parameters::POLYNOMIAL_DEGREE,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::FOUNDATION_PROFILE,
};

use super::{SCATTER_KEY_LEVEL, SELECTED_EVALUATOR_WORKING_LEVEL, TRACE_KEY_LEVEL};

pub(crate) const TRACE_GALOIS_ELEMENTS: [usize; 3] = [257, 1_025, 8_193];
pub(crate) const SCATTER_GALOIS_ELEMENTS: [usize; 3] = [219, 19, 15];

// Paths for the eight doubling steps of the degree-256 field trace. Their
// composed elements are p^(1,2,4,8,16,32,64,128) modulo 2N.
pub(crate) const TRACE_GALOIS_PATHS: [&[usize]; 8] = [
    &[257],
    &[257, 257],
    &[1_025],
    &[1_025, 1_025],
    &[1_025, 1_025, 1_025, 1_025],
    &[8_193],
    &[8_193, 8_193],
    &[8_193, 8_193, 8_193, 8_193],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ScatterRouteCoordinate {
    bank_ordinal: u16,
    lane_start: u16,
}

impl ScatterRouteCoordinate {
    pub(crate) const fn bank_ordinal(self) -> u16 {
        self.bank_ordinal
    }

    pub(crate) const fn lane_start(self) -> u16 {
        self.lane_start
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScatterRoute {
    coordinate: ScatterRouteCoordinate,
    inverse_route_galois_element: usize,
    galois_path: &'static [usize],
}

impl ScatterRoute {
    pub(crate) const fn coordinate(self) -> ScatterRouteCoordinate {
        self.coordinate
    }

    pub(crate) const fn galois_path(self) -> &'static [usize] {
        self.galois_path
    }
}

// One route per distinct lower/higher rank contribution coordinate. Multiple
// pair separations sharing a coordinate are merged before the route; the
// compiler owns exactly one mask per contributing ciphertext and coordinate.
pub(crate) const SCATTER_ROUTES: [ScatterRoute; 18] = [
    route(0, 7, 139, &[219, 19, 19, 19, 19]),
    route(0, 12, 241, &[219, 219, 219, 219]),
    route(0, 21, 179, &[19, 15, 15]),
    route(0, 29, 147, &[219, 219, 19, 19, 19]),
    route(0, 35, 155, &[219, 219, 19]),
    route(0, 38, 89, &[219, 219]),
    route(0, 43, 123, &[219, 15, 15]),
    route(0, 52, 17, &[19, 19, 19, 19]),
    route(0, 57, 35, &[219, 219, 219]),
    route(1, 6, 39, &[19, 19, 15]),
    route(1, 12, 15, &[15]),
    route(1, 15, 149, &[219, 15, 15, 15, 15, 15]),
    route(1, 31, 213, &[219, 15]),
    route(1, 33, 125, &[19, 15, 15, 15]),
    route(1, 41, 157, &[219, 219, 19, 19, 19, 15]),
    route(1, 49, 189, &[219, 19, 19, 15, 15, 15]),
    route(1, 52, 239, &[219, 19, 15, 15, 15]),
    route(1, 58, 151, &[19, 19, 19, 19, 19, 19, 15]),
];

const fn route(
    bank_ordinal: u16,
    lane_start: u16,
    inverse_route_galois_element: usize,
    galois_path: &'static [usize],
) -> ScatterRoute {
    ScatterRoute {
        coordinate: ScatterRouteCoordinate {
            bank_ordinal,
            lane_start,
        },
        inverse_route_galois_element,
        galois_path,
    }
}

pub(crate) fn compose_galois_path(path: &[usize]) -> CanonicalResult<usize> {
    let ring_order = POLYNOMIAL_DEGREE
        .checked_mul(2)
        .ok_or_else(rotation_error)?;
    path.iter().try_fold(1_usize, |composed, element| {
        if *element == 0 || element.is_multiple_of(2) || *element >= ring_order {
            return Err(rotation_error());
        }
        composed
            .checked_mul(*element)
            .map(|product| product % ring_order)
            .ok_or_else(rotation_error)
    })
}

pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if option_count != usize::from(FOUNDATION_PROFILE.option_count)
        || SELECTED_EVALUATOR_WORKING_LEVEL + 1 != crate::bgv::parameters::DATA_PRIMES.len()
        || TRACE_KEY_LEVEL >= SELECTED_EVALUATOR_WORKING_LEVEL
        || SCATTER_KEY_LEVEL >= TRACE_KEY_LEVEL
    {
        return Err(rotation_error());
    }
    validate_selected_rotation_topology()?;
    let mut ordered_catalog = TRACE_GALOIS_ELEMENTS
        .into_iter()
        .map(|element| (element, TRACE_KEY_LEVEL))
        .chain(
            SCATTER_GALOIS_ELEMENTS
                .into_iter()
                .map(|element| (element, SCATTER_KEY_LEVEL)),
        )
        .collect::<Vec<_>>();
    ordered_catalog
        .sort_unstable_by_key(|(galois_element, catalog_level)| (*catalog_level, *galois_element));
    Ok(ordered_catalog)
}

fn validate_selected_rotation_topology() -> CanonicalResult<()> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let expected_trace_elements = [257, 513, 1_025, 2_049, 4_097, 8_193, 16_385, 32_769];
    for (path, expected) in TRACE_GALOIS_PATHS.into_iter().zip(expected_trace_elements) {
        if compose_galois_path(path)? != expected {
            return Err(rotation_error());
        }
    }
    let mut hop_count = 0_usize;
    let mut previous_coordinate = None;
    for route in SCATTER_ROUTES {
        if previous_coordinate.is_some_and(|previous| previous >= route.coordinate)
            || compose_galois_path(route.galois_path)? % 256 != route.inverse_route_galois_element
            || route
                .galois_path
                .iter()
                .any(|element| !SCATTER_GALOIS_ELEMENTS.contains(element) || *element >= ring_order)
        {
            return Err(rotation_error());
        }
        previous_coordinate = Some(route.coordinate);
        hop_count = hop_count
            .checked_add(route.galois_path.len())
            .ok_or_else(rotation_error)?;
    }
    if hop_count != 72 {
        return Err(rotation_error());
    }
    Ok(())
}

fn rotation_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "selected extension-trace rotation topology is inconsistent",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_rotation_catalog_has_exact_levels_and_compositions() {
        assert_eq!(
            selected_evaluator_rotation_key_schedule(20).unwrap(),
            vec![
                (15, 14),
                (19, 14),
                (219, 14),
                (257, 18),
                (1_025, 18),
                (8_193, 18),
            ]
        );
        assert!(selected_evaluator_rotation_key_schedule(19).is_err());
        validate_selected_rotation_topology().unwrap();
        assert_eq!(
            TRACE_GALOIS_PATHS
                .iter()
                .map(|path| path.len())
                .sum::<usize>(),
            17
        );
        assert_eq!(
            SCATTER_ROUTES
                .iter()
                .map(|route| route.galois_path.len())
                .sum::<usize>(),
            72
        );
    }
}
