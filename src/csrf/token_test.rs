use super::*;

fn secret() -> [u8; 32] {
    [0x7F; 32]
}

mod issue {
    use super::*;

    #[test]
    fn given_valid_length_when_issue_then_returns_hex_token_of_requested_size() {
        let service = HmacCsrfService::new(secret());

        let token = service.issue(32).expect("issue should succeed");

        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
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
        service
            .counter
            .store(u64::MAX - 1, Ordering::Relaxed);

        let first = service.issue(32).expect("issue before wrap should succeed");
        let second = service.issue(32).expect("issue after wrap should succeed");

        assert_ne!(first, second, "wrapping counter must not reuse the same token");
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
}
