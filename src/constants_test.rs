use super::{cookie, executor_order, header_keys, header_values};

mod header_keys_cases {
    use super::header_keys;

    #[test]
    fn given_header_keys_when_checked_then_match_expected_values() {
        let expected_pairs = vec![
            (
                "Content-Security-Policy",
                header_keys::CONTENT_SECURITY_POLICY,
            ),
            ("X-Powered-By", header_keys::X_POWERED_BY),
            (
                "Strict-Transport-Security",
                header_keys::STRICT_TRANSPORT_SECURITY,
            ),
            (
                "X-Content-Type-Options",
                header_keys::X_CONTENT_TYPE_OPTIONS,
            ),
            ("X-Frame-Options", header_keys::X_FRAME_OPTIONS),
            ("Referrer-Policy", header_keys::REFERRER_POLICY),
            ("Permissions-Policy", header_keys::PERMISSIONS_POLICY),
            (
                "X-DNS-Prefetch-Control",
                header_keys::X_DNS_PREFETCH_CONTROL,
            ),
            ("Clear-Site-Data", header_keys::CLEAR_SITE_DATA),
            ("Set-Cookie", header_keys::SET_COOKIE),
            ("X-CSRF-Token", header_keys::CSRF_TOKEN),
            (
                "Cross-Origin-Embedder-Policy",
                header_keys::CROSS_ORIGIN_EMBEDDER_POLICY,
            ),
            (
                "Cross-Origin-Opener-Policy",
                header_keys::CROSS_ORIGIN_OPENER_POLICY,
            ),
            (
                "Cross-Origin-Resource-Policy",
                header_keys::CROSS_ORIGIN_RESOURCE_POLICY,
            ),
            ("Origin-Agent-Cluster", header_keys::ORIGIN_AGENT_CLUSTER),
        ];

        for (expected, actual) in expected_pairs {
            assert_eq!(actual, expected);
        }
    }
}

mod header_values_cases {
    use super::header_values;

    #[test]
    fn given_header_values_when_checked_then_match_expected_values() {
        let expected_pairs = vec![
            ("nosniff", header_values::NOSNIFF),
            ("Lax", header_values::SAMESITE_LAX),
            ("Strict", header_values::SAMESITE_STRICT),
            ("None", header_values::SAMESITE_NONE),
            ("require-corp", header_values::COEP_REQUIRE_CORP),
            ("credentialless", header_values::COEP_CREDENTIALLESS),
            ("same-origin", header_values::COOP_SAME_ORIGIN),
            (
                "same-origin-allow-popups",
                header_values::COOP_SAME_ORIGIN_ALLOW_POPUPS,
            ),
            ("unsafe-none", header_values::COOP_UNSAFE_NONE),
            ("same-origin", header_values::CORP_SAME_ORIGIN),
            ("same-site", header_values::CORP_SAME_SITE),
            ("cross-origin", header_values::CORP_CROSS_ORIGIN),
            ("DENY", header_values::X_FRAME_OPTIONS_DENY),
            ("SAMEORIGIN", header_values::X_FRAME_OPTIONS_SAMEORIGIN),
            ("no-referrer", header_values::REFERRER_POLICY_NO_REFERRER),
            (
                "no-referrer-when-downgrade",
                header_values::REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE,
            ),
            ("same-origin", header_values::REFERRER_POLICY_SAME_ORIGIN),
            ("origin", header_values::REFERRER_POLICY_ORIGIN),
            (
                "strict-origin",
                header_values::REFERRER_POLICY_STRICT_ORIGIN,
            ),
            (
                "origin-when-cross-origin",
                header_values::REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN,
            ),
            (
                "strict-origin-when-cross-origin",
                header_values::REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
            ),
            ("unsafe-url", header_values::REFERRER_POLICY_UNSAFE_URL),
            ("?1", header_values::ORIGIN_AGENT_CLUSTER_ENABLE),
            ("?0", header_values::ORIGIN_AGENT_CLUSTER_DISABLE),
            ("on", header_values::X_DNS_PREFETCH_CONTROL_ON),
            ("off", header_values::X_DNS_PREFETCH_CONTROL_OFF),
            ("\"cache\"", header_values::CLEAR_SITE_DATA_CACHE),
            ("\"cookies\"", header_values::CLEAR_SITE_DATA_COOKIES),
            ("\"storage\"", header_values::CLEAR_SITE_DATA_STORAGE),
            (
                "\"executionContexts\"",
                header_values::CLEAR_SITE_DATA_EXECUTION_CONTEXTS,
            ),
        ];

        for (expected, actual) in expected_pairs {
            assert_eq!(actual, expected);
        }
    }
}

mod cookie_cases {
    use super::cookie;

    #[test]
    fn given_cookie_prefix_when_checked_then_matches_expected_value() {
        assert_eq!(cookie::COOKIE_PREFIX_SECURE, "__Host-");
    }
}

mod executor_order_cases {
    use super::executor_order;

    #[test]
    fn given_executor_order_when_checked_then_matches_expected_sequence() {
        let expected_pairs = vec![
            (1u8, executor_order::CONTENT_SECURITY_POLICY),
            (2, executor_order::X_POWERED_BY),
            (3, executor_order::STRICT_TRANSPORT_SECURITY),
            (4, executor_order::X_CONTENT_TYPE_OPTIONS),
            (5, executor_order::CSRF_TOKEN),
            (6, executor_order::SAME_SITE),
            (7, executor_order::CROSS_ORIGIN_EMBEDDER_POLICY),
            (8, executor_order::CROSS_ORIGIN_OPENER_POLICY),
            (9, executor_order::CROSS_ORIGIN_RESOURCE_POLICY),
            (10, executor_order::X_FRAME_OPTIONS),
            (11, executor_order::REFERRER_POLICY),
            (12, executor_order::ORIGIN_AGENT_CLUSTER),
            (13, executor_order::PERMISSIONS_POLICY),
            (14, executor_order::X_DNS_PREFETCH_CONTROL),
            (15, executor_order::CLEAR_SITE_DATA),
        ];

        for (expected, actual) in expected_pairs {
            assert_eq!(actual, expected);
        }
    }
}
