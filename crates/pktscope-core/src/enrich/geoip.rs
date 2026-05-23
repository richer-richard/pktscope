use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Country + ASN/org for a destination IP, resolved entirely from local
/// offline databases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. "US").
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

/// Maps an IP to geo/ASN info. Implemented by the real MaxMind/DB-IP reader and
/// by a no-op enricher for tests / when no database is present.
pub trait Enricher: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> GeoInfo;
}

/// Reads country and ASN `.mmdb` databases (MaxMind DB format, as produced by
/// DB-IP Lite or iptoasn). Missing databases degrade gracefully to empty results.
pub struct GeoIpEnricher {
    country: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpEnricher {
    /// Open the given databases. A path that is `None` or fails to open simply
    /// yields no data for that dimension (never an error).
    pub fn open(country_db: Option<&Path>, asn_db: Option<&Path>) -> Self {
        let country = country_db.and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        let asn = asn_db.and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self { country, asn }
    }

    /// An enricher with no databases (always returns empty `GeoInfo`).
    pub fn null() -> Self {
        Self {
            country: None,
            asn: None,
        }
    }

    pub fn has_data(&self) -> bool {
        self.country.is_some() || self.asn.is_some()
    }
}

/// Whether an address is globally routable (worth geo-locating). Private,
/// loopback, link-local, multicast, and unspecified addresses are skipped.
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xffc0) == 0xfe80 // link-local
                || (seg0 & 0xfe00) == 0xfc00) // unique local
        }
    }
}

impl Enricher for GeoIpEnricher {
    fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let mut info = GeoInfo::default();
        if !is_global(ip) {
            return info;
        }
        if let Some(reader) = &self.country {
            if let Ok(c) = reader.lookup::<maxminddb::geoip2::Country>(ip) {
                info.country = c.country.and_then(|c| c.iso_code).map(|s| s.to_string());
            }
        }
        if let Some(reader) = &self.asn {
            if let Ok(a) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                info.asn = a.autonomous_system_number;
                info.as_org = a.autonomous_system_organization.map(|s| s.to_string());
            }
        }
        info
    }
}

/// A no-op enricher used in tests and when GeoIP data is unavailable.
pub struct NullEnricher;

impl Enricher for NullEnricher {
    fn lookup(&self, _ip: IpAddr) -> GeoInfo {
        GeoInfo::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_null_enricher_is_empty() {
        let e = GeoIpEnricher::null();
        assert!(!e.has_data());
        assert_eq!(
            e.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            GeoInfo::default()
        );
    }

    #[test]
    fn test_private_ip_skipped() {
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_global(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_global(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn test_open_missing_db_is_null() {
        let e = GeoIpEnricher::open(Some(Path::new("/nonexistent/x.mmdb")), None);
        assert!(!e.has_data());
        assert_eq!(
            e.lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            GeoInfo::default()
        );
    }
}
