use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use bunner_shield_rs::{
    ClearSiteDataOptions, CoepOptions, CoepPolicy, CoopOptions, CoopPolicy, CorpOptions,
    CorpPolicy, CspDirective, CspHashAlgorithm, CspNonceManager, CspOptions, CspSource,
    CsrfOptions, HstsOptions, NormalizedHeaders, OriginAgentClusterOptions,
    PermissionsPolicyOptions, ReferrerPolicyOptions, ReferrerPolicyValue, SameSiteOptions,
    SameSitePolicy, SandboxToken, Shield, TrustedTypesPolicy, XFrameOptionsOptions,
    XFrameOptionsPolicy, XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy,
};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

fn bench_secure_all_features(c: &mut Criterion) {
    let mut group = c.benchmark_group("shield_secure_all_features");
    group
        .sample_size(40)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10));

    let shield = build_full_featured_shield();

    group.bench_function("secure-heavy-pipeline", |b| {
        b.iter_batched(
            heavy_request_headers,
            |headers| {
                let secured = shield.secure(headers).expect("secure");
                black_box(secured)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_normalized_headers_large_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalized_headers_large_inputs");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8));

    group.bench_function("construct_from_large_map", |b| {
        b.iter_batched(
            large_header_map,
            |input| {
                let normalized = NormalizedHeaders::new(input);
                black_box(normalized)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("append_large_set_cookie_blob", |b| {
        b.iter_batched(
            || NormalizedHeaders::new(HashMap::new()),
            |mut headers| {
                headers.insert("set-cookie", large_set_cookie_blob().clone());
                black_box(headers)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn build_full_featured_shield() -> Shield {
    let csp_options = build_comprehensive_csp_options();
    let csrf_secret = [0x5Au8; 32];

    Shield::new()
        .csp(csp_options)
        .expect("csp")
        .x_powered_by()
        .expect("x-powered-by")
        .hsts(
            HstsOptions::new()
                .include_subdomains()
                .preload()
                .max_age(62_208_000),
        )
        .expect("hsts")
        .x_content_type_options()
        .expect("x-content-type-options")
        .csrf(CsrfOptions::new(csrf_secret).cookie_name("__Host-heavy-csrf"))
        .expect("csrf")
        .same_site(
            SameSiteOptions::new()
                .same_site(SameSitePolicy::None)
                .secure(true)
                .http_only(true),
        )
        .expect("same-site")
        .coep(CoepOptions::new().policy(CoepPolicy::Credentialless))
        .expect("coep")
        .coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))
        .expect("coop")
        .corp(CorpOptions::new().policy(CorpPolicy::CrossOrigin))
        .expect("corp")
        .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
        .expect("x-frame-options")
        .referrer_policy(ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::StrictOrigin))
        .expect("referrer-policy")
        .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
        .expect("origin-agent-cluster")
        .permissions_policy(PermissionsPolicyOptions::new(
            "geolocation=(), microphone=(), camera=(), fullscreen=(self), payment=()",
        ))
        .expect("permissions-policy")
        .x_dns_prefetch_control(
            XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
        )
        .expect("x-dns-prefetch-control")
        .clear_site_data(
            ClearSiteDataOptions::new()
                .cache()
                .cookies()
                .storage()
                .execution_contexts(),
        )
        .expect("clear-site-data")
}

fn build_comprehensive_csp_options() -> CspOptions {
    let nonce_manager = CspNonceManager::with_size(48).expect("nonce manager");
    let script_nonce = nonce_manager.issue().into_inner();
    let style_nonce = nonce_manager.issue().into_inner();
    let attr_nonce = nonce_manager.issue().into_inner();

    let trusted_policy = TrustedTypesPolicy::new("heavyPolicy").expect("trusted policy");

    let sandbox_tokens = [
        SandboxToken::AllowDownloads,
        SandboxToken::AllowForms,
        SandboxToken::AllowModals,
        SandboxToken::AllowOrientationLock,
        SandboxToken::AllowPointerLock,
        SandboxToken::AllowPopups,
        SandboxToken::AllowPopupsToEscapeSandbox,
        SandboxToken::AllowPresentation,
        SandboxToken::AllowSameOrigin,
        SandboxToken::AllowScripts,
        SandboxToken::AllowStorageAccessByUserActivation,
        SandboxToken::AllowTopNavigation,
        SandboxToken::AllowTopNavigationByUserActivation,
        SandboxToken::AllowTopNavigationToCustomProtocols,
        SandboxToken::AllowDownloadsWithoutUserActivation,
    ];

    let sha256_hash = "A".repeat(44);
    let sha384_hash = "B".repeat(64);
    let sha512_hash = "C".repeat(88);

    let mut options = CspOptions::new()
        .default_src([
            CspSource::SelfKeyword,
            CspSource::scheme("https"),
            CspSource::host("https://cdn.example.com"),
        ])
        .img_src([
            CspSource::SelfKeyword,
            CspSource::scheme("data"),
            CspSource::host("https://images.example.com"),
        ])
        .connect_src([
            CspSource::SelfKeyword,
            CspSource::Wildcard,
            CspSource::host("https://api.internal.example.com"),
        ])
        .font_src([
            CspSource::SelfKeyword,
            CspSource::host("https://fonts.example.com"),
        ])
        .frame_src([
            CspSource::SelfKeyword,
            CspSource::host("https://frames.example.com"),
        ])
        .worker_src([
            CspSource::SelfKeyword,
            CspSource::host("https://workers.example.com"),
        ])
        .media_src([
            CspSource::SelfKeyword,
            CspSource::host("https://media.example.com"),
        ])
        .manifest_src([
            CspSource::SelfKeyword,
            CspSource::host("https://app.example.com"),
        ])
        .object_src([CspSource::None])
        .navigate_to([
            CspSource::SelfKeyword,
            CspSource::host("https://checkout.example.com"),
        ])
        .form_action([
            CspSource::SelfKeyword,
            CspSource::host("https://secure.example.com"),
        ])
        .frame_ancestors([CspSource::None])
        .base_uri([CspSource::host("https://app.example.com")])
        .report_to("primary-endpoint")
    .upgrade_insecure_requests()
        .upgrade_insecure_requests()
        .sandbox_with(sandbox_tokens)
        .script_src(|script| {
            script
                .sources([
                    CspSource::SelfKeyword,
                    CspSource::Hash {
                        algorithm: CspHashAlgorithm::Sha256,
                        value: sha256_hash.clone(),
                    },
                    CspSource::ReportSample,
                ])
                .elem([
                    CspSource::SelfKeyword,
                    CspSource::host("https://modules.example.com"),
                    CspSource::Hash {
                        algorithm: CspHashAlgorithm::Sha384,
                        value: sha384_hash.clone(),
                    },
                ])
                .attr([
                    CspSource::SelfKeyword,
                    CspSource::Hash {
                        algorithm: CspHashAlgorithm::Sha512,
                        value: sha512_hash.clone(),
                    },
                ])
                .nonce(script_nonce.clone())
                .hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
                .elem_nonce(script_nonce.clone())
                .elem_hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
                .attr_nonce(attr_nonce.clone())
                .attr_hash(CspHashAlgorithm::Sha256, sha256_hash.clone())
        })
        .style_src(|style| {
            style
                .sources([
                    CspSource::SelfKeyword,
                    CspSource::scheme("https"),
                    CspSource::host("https://fonts.example.com"),
                ])
                .elem([
                    CspSource::from(style_nonce.clone()),
                    CspSource::Hash {
                        algorithm: CspHashAlgorithm::Sha384,
                        value: sha384_hash.clone(),
                    },
                ])
                .attr([
                    CspSource::from(attr_nonce.clone()),
                    CspSource::Hash {
                        algorithm: CspHashAlgorithm::Sha256,
                        value: sha256_hash.clone(),
                    },
                ])
                .nonce(style_nonce.clone())
                .hash(CspHashAlgorithm::Sha256, sha256_hash.clone())
                .elem_nonce(style_nonce.clone())
                .elem_hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
                .attr_nonce(attr_nonce.clone())
                .attr_hash(CspHashAlgorithm::Sha384, sha384_hash.clone())
        })
        .trusted_types(|trusted| trusted.policy(trusted_policy).allow_duplicates())
        .require_trusted_types_for_scripts();

    options = options.add_source(
        CspDirective::WorkerSrc,
        CspSource::host("https://analytics.example.com"),
    );

    options
}

fn heavy_request_headers() -> HashMap<String, String> {
    static BASE_HEADERS: OnceLock<HashMap<String, String>> = OnceLock::new();

    BASE_HEADERS
        .get_or_init(|| {
            let mut headers = HashMap::with_capacity(560);
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("X-Powered-By".to_string(), "LegacyStack 3.2".to_string());
            headers.insert(
                "Strict-Transport-Security".to_string(),
                "max-age=0".to_string(),
            );
            headers.insert(
                "Content-Security-Policy".to_string(),
                "default-src *".to_string(),
            );
            headers.insert(
                "Cross-Origin-Embedder-Policy".to_string(),
                "unsafe-none".to_string(),
            );
            headers.insert(
                "Cross-Origin-Opener-Policy".to_string(),
                "unsafe-none".to_string(),
            );
            headers.insert(
                "Cross-Origin-Resource-Policy".to_string(),
                "cross-origin".to_string(),
            );
            headers.insert("Referrer-Policy".to_string(), "no-referrer".to_string());
            headers.insert("Origin-Agent-Cluster".to_string(), "?1".to_string());
            headers.insert(
                "Permissions-Policy".to_string(),
                "geolocation=*".to_string(),
            );
            headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
            headers.insert("X-DNS-Prefetch-Control".to_string(), "off".to_string());
            headers.insert("Clear-Site-Data".to_string(), "\"cache\"".to_string());
            headers.insert(
                "Set-Cookie".to_string(),
                "session=abc123; Path=/; SameSite=Lax".to_string(),
            );
            headers.insert("X-CSRF-Token".to_string(), "legacy-token".to_string());

            for index in 0..512 {
                headers.insert(format!("X-Custom-{index:03}"), format!("value-{index:08}"));
            }

            headers
        })
        .clone()
}

fn large_header_map() -> HashMap<String, String> {
    static LARGE_HEADERS: OnceLock<HashMap<String, String>> = OnceLock::new();

    LARGE_HEADERS
        .get_or_init(|| {
            let mut headers = HashMap::with_capacity(2_400);
            headers.insert("x-large-payload".to_string(), large_payload_value().clone());
            headers.insert("set-cookie".to_string(), large_set_cookie_blob().clone());

            for index in 0..2_048 {
                headers.insert(
                    format!("x-bulk-header-{index:04}"),
                    format!("value-{index:08}"),
                );
            }

            headers
        })
        .clone()
}

fn large_payload_value() -> &'static String {
    static LARGE_VALUE: OnceLock<String> = OnceLock::new();

    LARGE_VALUE.get_or_init(|| "X".repeat(250_000))
}

fn large_set_cookie_blob() -> &'static String {
    static COOKIE_BLOB: OnceLock<String> = OnceLock::new();

    COOKIE_BLOB.get_or_init(|| {
        let mut blob = String::with_capacity(2_048 * 96);
        for index in 0..2_048 {
            blob.push_str("Set-Cookie: large-token-");
            blob.push_str(&index.to_string());
            blob.push_str("=payload-");
            blob.push_str(&index.to_string());
            blob.push_str("; Path=/; Secure; HttpOnly\n");
        }
        blob
    })
}

criterion_group!(
    name = shield_benches;
    config = Criterion::default();
    targets = bench_secure_all_features, bench_normalized_headers_large_inputs
);
criterion_main!(shield_benches);
