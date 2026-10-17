use crate::{
    Error, Result,
    field::{Element, encode_fields},
    layout::Tree,
    reader::Reader,
    require,
    transcript::{hash, word},
};
use std::collections::{BTreeMap, BTreeSet};

pub fn opening(
    role: &[u8],
    tree: &Tree,
    root: &[u8; 64],
    requested: &[usize],
    reader: &mut Reader<'_>,
) -> Result<Vec<Vec<Element>>> {
    let positions: BTreeSet<_> = requested.iter().copied().collect();
    require(reader.word()? == positions.len(), Error::Encoding)?;
    let mut authenticated: BTreeMap<usize, [u8; 64]> = BTreeMap::new();
    let mut values = BTreeMap::new();
    for position in positions {
        require(reader.word()? == position, Error::Encoding)?;
        let fields = reader.fields(tree.width)?;
        let salt = reader.take(128)?;
        let mut digest = hash(
            b"bounded-proof/leaf",
            &[
                role,
                &word(tree.identifier),
                &word(position),
                salt,
                &encode_fields(&fields),
            ],
        );
        let mut node = tree.domain + position;
        let mut level = 1;
        let mut pending = Vec::new();
        while node > 1 && !authenticated.contains_key(&node) {
            pending.push((node, digest));
            let sibling = match authenticated.get(&(node ^ 1)) {
                Some(&value) => value,
                None => {
                    let value = reader.digest()?;
                    pending.push((node ^ 1, value));
                    value
                }
            };
            let (left, right) = if node & 1 == 0 {
                (digest, sibling)
            } else {
                (sibling, digest)
            };
            digest = hash(
                b"bounded-proof/node",
                &[role, &word(tree.identifier), &word(level), &left, &right],
            );
            node >>= 1;
            level += 1;
        }
        require(
            digest == *authenticated.get(&node).unwrap_or(root),
            Error::Authentication,
        )?;
        authenticated.extend(pending);
        values.insert(position, fields);
    }
    Ok((0..tree.width)
        .map(|row| {
            requested
                .iter()
                .map(|position| values[position][row])
                .collect()
        })
        .collect())
}
