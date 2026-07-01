// Structural hash domains. The protocol collapsed its formerly per-type string
// namespaces into a single canonical-object domain: typed objects, records, and
// roots are separated by the mandatory `objectType` discriminator already inside
// their canonical JSON, not by a per-type domain string. The remaining structural
// domains (the canonical-root type-id domain, chunk/transport roots, and the raw
// row-coefficient vector domains) are bespoke `hash512_hex` callers and are not
// listed here.
pub const CANONICAL_OBJECT_HASH_NAMESPACE: &str = "sealed-lattice-root/canonical-object-v1";
