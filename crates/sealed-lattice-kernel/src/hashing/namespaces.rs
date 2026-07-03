// Structural hash domains. Canonical objects are separated by the mandatory
// `objectType` discriminator inside their canonical JSON, not by a per-type
// domain string. The remaining structural domains (canonical-root type ids,
// chunk/transport roots, and raw row-coefficient vectors) are bespoke
// `hash512_hex` callers and are not listed here.
pub const CANONICAL_OBJECT_HASH_NAMESPACE: &str = "sealed-lattice-root/canonical-object-v1";
