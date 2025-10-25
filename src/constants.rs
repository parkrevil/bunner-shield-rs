pub mod header_keys {
    pub const CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
    pub const X_POWERED_BY: &str = "X-Powered-By";
    pub const STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";
    pub const X_CONTENT_TYPE_OPTIONS: &str = "X-Content-Type-Options";
    pub const X_FRAME_OPTIONS: &str = "X-Frame-Options";
    pub const REFERRER_POLICY: &str = "Referrer-Policy";
    pub const PERMISSIONS_POLICY: &str = "Permissions-Policy";
    pub const X_DNS_PREFETCH_CONTROL: &str = "X-DNS-Prefetch-Control";
    pub const CLEAR_SITE_DATA: &str = "Clear-Site-Data";
    pub const SET_COOKIE: &str = "Set-Cookie";
    pub const CSRF_TOKEN: &str = "X-CSRF-Token";
    pub const CROSS_ORIGIN_EMBEDDER_POLICY: &str = "Cross-Origin-Embedder-Policy";
    pub const CROSS_ORIGIN_OPENER_POLICY: &str = "Cross-Origin-Opener-Policy";
    pub const CROSS_ORIGIN_RESOURCE_POLICY: &str = "Cross-Origin-Resource-Policy";
    pub const ORIGIN_AGENT_CLUSTER: &str = "Origin-Agent-Cluster";
}

pub mod header_values {
    pub const NOSNIFF: &str = "nosniff";
    pub const SAMESITE_LAX: &str = "Lax";
    pub const SAMESITE_STRICT: &str = "Strict";
    pub const SAMESITE_NONE: &str = "None";
    pub const COEP_REQUIRE_CORP: &str = "require-corp";
    pub const COEP_CREDENTIALLESS: &str = "credentialless";
    pub const COOP_SAME_ORIGIN: &str = "same-origin";
    pub const COOP_SAME_ORIGIN_ALLOW_POPUPS: &str = "same-origin-allow-popups";
    pub const COOP_UNSAFE_NONE: &str = "unsafe-none";
    pub const CORP_SAME_ORIGIN: &str = "same-origin";
    pub const CORP_SAME_SITE: &str = "same-site";
    pub const CORP_CROSS_ORIGIN: &str = "cross-origin";
    pub const X_FRAME_OPTIONS_DENY: &str = "DENY";
    pub const X_FRAME_OPTIONS_SAMEORIGIN: &str = "SAMEORIGIN";
    pub const REFERRER_POLICY_NO_REFERRER: &str = "no-referrer";
    pub const REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE: &str = "no-referrer-when-downgrade";
    pub const REFERRER_POLICY_SAME_ORIGIN: &str = "same-origin";
    pub const REFERRER_POLICY_ORIGIN: &str = "origin";
    pub const REFERRER_POLICY_STRICT_ORIGIN: &str = "strict-origin";
    pub const REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN: &str = "origin-when-cross-origin";
    pub const REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN: &str =
        "strict-origin-when-cross-origin";
    pub const REFERRER_POLICY_UNSAFE_URL: &str = "unsafe-url";
    pub const ORIGIN_AGENT_CLUSTER_ENABLE: &str = "?1";
    pub const ORIGIN_AGENT_CLUSTER_DISABLE: &str = "?0";
    pub const X_DNS_PREFETCH_CONTROL_ON: &str = "on";
    pub const X_DNS_PREFETCH_CONTROL_OFF: &str = "off";
    pub const CLEAR_SITE_DATA_CACHE: &str = "\"cache\"";
    pub const CLEAR_SITE_DATA_COOKIES: &str = "\"cookies\"";
    pub const CLEAR_SITE_DATA_STORAGE: &str = "\"storage\"";
    pub const CLEAR_SITE_DATA_EXECUTION_CONTEXTS: &str = "\"executionContexts\"";
}

pub mod cookie {
    pub const COOKIE_PREFIX_SECURE: &str = "__Host-";
}

pub mod executor_order {
    pub const SAFE_HEADERS: u8 = 0;
    pub const CONTENT_SECURITY_POLICY: u8 = 1;
    pub const X_POWERED_BY: u8 = 2;
    pub const STRICT_TRANSPORT_SECURITY: u8 = 3;
    pub const X_CONTENT_TYPE_OPTIONS: u8 = 4;
    pub const CSRF_TOKEN: u8 = 5;
    pub const SAME_SITE: u8 = 6;
    pub const CROSS_ORIGIN_EMBEDDER_POLICY: u8 = 7;
    pub const CROSS_ORIGIN_OPENER_POLICY: u8 = 8;
    pub const CROSS_ORIGIN_RESOURCE_POLICY: u8 = 9;
    pub const X_FRAME_OPTIONS: u8 = 10;
    pub const REFERRER_POLICY: u8 = 11;
    pub const ORIGIN_AGENT_CLUSTER: u8 = 12;
    pub const PERMISSIONS_POLICY: u8 = 13;
    pub const X_DNS_PREFETCH_CONTROL: u8 = 14;
    pub const CLEAR_SITE_DATA: u8 = 15;
}
