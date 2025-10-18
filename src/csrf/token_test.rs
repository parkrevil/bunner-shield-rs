use super::*;

fn secret() -> [u8; 32] {
    [0x7F; 32]
}

mod issue {
    use super::*;

    #[test]
    fn given_valid_length_when_issue_then_returns_base64url_token_and_verifies() {
        let service = HmacCsrfService::new(secret());

        let token = service.issue(32).expect("issue should succeed");
        // token is base64url (no padding) and should verify
        assert!(service.verify(&token).is_ok());
    }

    #[test]
    fn given_multiple_requests_when_issue_then_returns_distinct_tokens() {
        let service = HmacCsrfService::new(secret());

        let first = service.issue(16).expect("first issue should succeed");
        let second = service.issue(16).expect("second issue should succeed");

        assert_ne!(first, second);
    }

    #[test]
    fn given_counter_near_overflow_when_issue_then_wraps_without_duplicates() {
        use core::sync::atomic::Ordering;

        let service = HmacCsrfService::new(secret());
        service.counter.store(u64::MAX - 1, Ordering::Relaxed);

        let first = service.issue(32).expect("issue before wrap should succeed");
        let second = service.issue(32).expect("issue after wrap should succeed");

        assert_ne!(
            first, second,
            "wrapping counter must not reuse the same token"
        );
        assert!(service.verify(&first).is_ok());
        assert!(service.verify(&second).is_ok());
    }

    #[test]
    fn given_parallel_requests_when_issue_then_tokens_remain_unique() {
        use std::collections::HashSet;
        use std::sync::{Arc, Barrier};
        use std::thread;

        let service = Arc::new(HmacCsrfService::new(secret()));
        let workers = 32;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::with_capacity(workers);

        for _ in 0..workers {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                service.issue(48)
            }));
        }

        let mut tokens = HashSet::with_capacity(workers);
        for handle in handles {
            let token = handle
                .join()
                .expect("thread panicked")
                .expect("issuing token must succeed");
            let inserted = tokens.insert(token);
            assert!(inserted, "duplicate token detected under parallel load");
        }

        assert_eq!(tokens.len(), workers);
    }

    #[test]
    fn given_zero_length_when_issue_then_returns_invalid_length_error() {
        let service = HmacCsrfService::new(secret());

        let error = service.issue(0).expect_err("expected invalid length error");

        assert_eq!(error, CsrfTokenError::InvalidTokenLength(0));
    }

    #[test]
    fn given_length_above_limit_when_issue_then_returns_invalid_length_error() {
        let service = HmacCsrfService::new(secret());

        let error = service
            .issue(100)
            .expect_err("expected invalid length error");

        assert_eq!(error, CsrfTokenError::InvalidTokenLength(100));
    }

    #[test]
    fn given_tampered_token_when_verify_then_returns_signature_error() {
        let service = HmacCsrfService::new(secret());
        let mut token = service.issue(32).expect("issue should succeed");
        // Flip one character safely by appending 'A' if possible, or toggling last char
        if let Some(last) = token.pop() {
            let flipped = if last == 'A' { 'B' } else { 'A' };
            token.push(flipped);
        }
        let err = service.verify(&token).expect_err("expected verification error");
        assert!(matches!(err, CsrfTokenError::InvalidSignature | CsrfTokenError::InvalidEncoding));
    }
}

mod expiry_v2 {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    #[test]
    fn given_v2_token_when_within_max_age_then_verify_with_max_age_succeeds() {
        let service = HmacCsrfService::new(secret());
        let token = service.issue(64).expect("token");
        // Decode and extract issued timestamp
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        assert_eq!(raw[0], super::TOKEN_VERSION_V2);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[1..9]);
        let issued = u64::from_be_bytes(ts);

        assert!(service
            .verify_with_max_age(&token, 60, issued)
            .is_ok());
        assert!(service
            .verify_with_max_age(&token, 60, issued + 30)
            .is_ok());
    }

    #[test]
    fn given_v2_token_when_beyond_max_age_then_verify_with_max_age_fails() {
        let service = HmacCsrfService::new(secret());
        let token = service.issue(64).expect("token");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        assert_eq!(raw[0], super::TOKEN_VERSION_V2);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[1..9]);
        let issued = u64::from_be_bytes(ts);

        let err = service
            .verify_with_max_age(&token, 10, issued + 11)
            .unwrap_err();
        assert_eq!(err, CsrfTokenError::Expired);
    }

    #[test]
    fn given_v1_token_when_verify_with_max_age_then_returns_missing_timestamp() {
        // Build a legacy v1 token manually: [1][nonce(8)][mac_trunc(16)]
        let service = HmacCsrfService::new(secret());
        let nonce: u64 = 0x0102030405060708;

        // mac = HMAC(secret, nonce_be)
        let mut mac = HmacSha256::new_from_slice(&secret()).unwrap();
        mac.update(&nonce.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mac_trunc = &full[..16];

        let mut raw = Vec::with_capacity(1 + 8 + 16);
        raw.push(super::TOKEN_VERSION_V1);
        raw.extend_from_slice(&nonce.to_be_bytes());
        raw.extend_from_slice(mac_trunc);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

        // Signature still validates under generic verify
        assert!(service.verify(&token).is_ok());
        // Expiry-aware verification refuses v1 tokens
        let err = service
            .verify_with_max_age(&token, 60, 0)
            .expect_err("expected missing timestamp error");
        assert_eq!(err, CsrfTokenError::MissingTimestamp);
    }
}

mod replay_v2 {
    use super::*;

    #[test]
    fn given_v2_token_when_first_seen_then_consume_ok_otherwise_replayed() {
        let service = HmacCsrfService::new(secret());
        let store = InMemoryReplayStore::new();
        let token = service.issue(64).expect("token");

        assert!(service.verify_and_consume(&token, &store).is_ok());
        let err = service
            .verify_and_consume(&token, &store)
            .expect_err("expected replay error");
        assert_eq!(err, CsrfTokenError::Replayed);
    }
}
