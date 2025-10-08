use super::*;
use crate::csp::{CspOptions, CspReportGroup};

mod header_pairs {
    use super::*;

    #[test]
    fn given_enforced_policy_when_header_pairs_then_returns_csp_header() {
        let policy = CspOptions::new()
            .with_directive("default-src", "'self'")
            .with_directive("base-uri", "'none'")
            .with_directive("frame-ancestors", "'none'")
            .validate()
            .expect("policy");

        let headers = header_pairs(&policy);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, HEADER_CONTENT_SECURITY_POLICY);
        assert_eq!(
            headers[0].1,
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn given_report_only_policy_when_header_pairs_then_includes_report_to_header() {
        let group = CspReportGroup::new("default", "https://reports.example.com");
        let policy = CspOptions::new()
            .with_directive("default-src", "'self'")
            .with_directive("base-uri", "'none'")
            .with_directive("frame-ancestors", "'none'")
            .enable_report_only()
            .with_report_group(group.clone())
            .validate()
            .expect("policy");

        let headers = header_pairs(&policy);

        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY);
        assert_eq!(headers[1].0, HEADER_REPORT_TO);
        assert_eq!(headers[1].1, group.to_header_value());
    }
}
