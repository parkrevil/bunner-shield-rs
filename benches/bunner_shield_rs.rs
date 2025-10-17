use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use bunner_shield_rs::{
    ClearSiteDataOptions, CoepOptions, CoepPolicy, CoopOptions, CoopPolicy, CorpOptions,
    CorpPolicy, CspDirective, CspHashAlgorithm, CspNonceManager, CspOptions, CspSource,
    CsrfOptions, HstsOptions, OriginAgentClusterOptions, PermissionsPolicyOptions,
    ReferrerPolicyOptions, ReferrerPolicyValue, SameSiteOptions, SameSitePolicy, SandboxToken,
    Shield, TrustedTypesPolicy, TrustedTypesToken, XFrameOptionsOptions, XFrameOptionsPolicy,
    XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy,
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
        .style_src([
            CspSource::SelfKeyword,
            CspSource::scheme("https"),
            CspSource::host("https://fonts.example.com"),
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
        .block_all_mixed_content()
        .upgrade_insecure_requests()
        .sandbox_with(sandbox_tokens)
        .script_src([
            CspSource::SelfKeyword,
            CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha256,
                value: sha256_hash.clone(),
            },
            CspSource::ReportSample,
        ])
        .script_src_elem([
            CspSource::SelfKeyword,
            CspSource::host("https://modules.example.com"),
            CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha384,
                value: sha384_hash.clone(),
            },
        ])
        .script_src_attr([
            CspSource::SelfKeyword,
            CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha512,
                value: sha512_hash.clone(),
            },
        ])
        .style_src_elem([
            CspSource::from(style_nonce.clone()),
            CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha384,
                value: sha384_hash.clone(),
            },
        ])
        .style_src_attr([
            CspSource::from(attr_nonce.clone()),
            CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha256,
                value: sha256_hash.clone(),
            },
        ])
        .trusted_types_tokens([
            TrustedTypesToken::policy(trusted_policy),
            TrustedTypesToken::allow_duplicates(),
        ])
        .require_trusted_types_for_scripts();

    options = options
        .script_src_nonce(script_nonce.clone())
        .script_src_hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
        .style_src_nonce(style_nonce.clone())
        .style_src_hash(CspHashAlgorithm::Sha256, sha256_hash.clone())
        .style_src_elem_nonce(style_nonce.clone())
        .style_src_elem_hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
        .style_src_attr_nonce(attr_nonce.clone())
        .style_src_attr_hash(CspHashAlgorithm::Sha384, sha384_hash)
        .script_src_elem_nonce(script_nonce.clone())
        .script_src_elem_hash(CspHashAlgorithm::Sha512, sha512_hash.clone())
        .script_src_attr_nonce(attr_nonce.clone())
        .script_src_attr_hash(CspHashAlgorithm::Sha256, sha256_hash)
        .add_source(
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

criterion_group!(
    name = shield_benches;
    config = Criterion::default();
    targets = bench_secure_all_features
);
criterion_main!(shield_benches);
