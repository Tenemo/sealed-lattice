use registration_enrollment::Enrollment;
use std::{
    collections::BTreeMap,
    ops::{Index, IndexMut},
};

/// Original positions never move when a participant loses its private state.
pub struct OriginalEnrollments(BTreeMap<usize, Enrollment>);

impl OriginalEnrollments {
    pub fn new(enrollments: Vec<Enrollment>) -> Self {
        Self(enrollments.into_iter().enumerate().collect())
    }
    pub fn depart(&mut self, position: usize) {
        drop(
            self.0
                .remove(&position)
                .expect("The departing original participant exists"),
        );
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn positions(&self) -> Vec<usize> {
        self.0.keys().copied().collect()
    }
    pub fn iter(&self) -> impl Iterator<Item = (usize, &Enrollment)> {
        self.0
            .iter()
            .map(|(position, enrollment)| (*position, enrollment))
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut Enrollment)> {
        self.0
            .iter_mut()
            .map(|(position, enrollment)| (*position, enrollment))
    }
}
impl Index<usize> for OriginalEnrollments {
    type Output = Enrollment;
    fn index(&self, position: usize) -> &Self::Output {
        self.0
            .get(&position)
            .expect("The original private authority is unavailable")
    }
}
impl IndexMut<usize> for OriginalEnrollments {
    fn index_mut(&mut self, position: usize) -> &mut Self::Output {
        self.0
            .get_mut(&position)
            .expect("The original private authority is unavailable")
    }
}
