pub mod headers {
    pub const CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
    pub const CONTENT_SECURITY_POLICY_REPORT_ONLY: &str = "Content-Security-Policy-Report-Only";
    pub const REPORT_TO: &str = "Report-To";
    pub const X_POWERED_BY: &str = "X-Powered-By";
}

pub mod executor_order {
    pub const CONTENT_SECURITY_POLICY: u8 = 1;
    pub const X_POWERED_BY: u8 = 2;
}
