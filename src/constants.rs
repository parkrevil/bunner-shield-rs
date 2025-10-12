pub mod header_keys {
    pub const CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
    pub const CONTENT_SECURITY_POLICY_REPORT_ONLY: &str = "Content-Security-Policy-Report-Only";
    pub const REPORT_TO: &str = "Report-To";
    pub const X_POWERED_BY: &str = "X-Powered-By";
    pub const STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";
    pub const X_CONTENT_TYPE_OPTIONS: &str = "X-Content-Type-Options";
    pub const SET_COOKIE: &str = "Set-Cookie";
    pub const CSRF_TOKEN: &str = "X-CSRF-Token";
    pub const CROSS_ORIGIN_EMBEDDER_POLICY: &str = "Cross-Origin-Embedder-Policy";
    pub const CROSS_ORIGIN_OPENER_POLICY: &str = "Cross-Origin-Opener-Policy";
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
}

pub mod cookie {
    pub const COOKIE_PREFIX_SECURE: &str = "__Host-";
}

pub mod executor_order {
    pub const CONTENT_SECURITY_POLICY: u8 = 1;
    pub const X_POWERED_BY: u8 = 2;
    pub const STRICT_TRANSPORT_SECURITY: u8 = 3;
    pub const X_CONTENT_TYPE_OPTIONS: u8 = 4;
    pub const CSRF_TOKEN: u8 = 5;
    pub const SAME_SITE: u8 = 6;
    pub const CROSS_ORIGIN_EMBEDDER_POLICY: u8 = 7;
    pub const CROSS_ORIGIN_OPENER_POLICY: u8 = 8;
}
