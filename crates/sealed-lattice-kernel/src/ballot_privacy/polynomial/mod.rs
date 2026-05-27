pub(crate) mod matrix;
pub(crate) mod ring;
pub(crate) mod sparse_matrix;
pub(crate) mod sparse_vector;
pub(crate) mod vector;

pub(crate) use matrix as polynomial_matrix;
pub(crate) use ring as polynomial_ring;
pub(crate) use sparse_matrix as sparse_polynomial_matrix;
pub(crate) use sparse_vector as sparse_polynomial_vector;
pub(crate) use vector as polynomial_vector;
