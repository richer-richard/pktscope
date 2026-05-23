//! Passive enrichment of observed traffic: IP→name resolution (DNS answers +
//! TLS SNI) and, in a later milestone, offline GeoIP/ASN lookup.

pub mod names;

pub use names::{NameEntry, NameResolver, NameSource, SharedNameResolver};
