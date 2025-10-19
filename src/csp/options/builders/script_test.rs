use super::*;

mod nonce_value {
    use super::*;

    #[test]
    fn given_nonce_value_when_configured_then_token_is_present() {
        let options = CspOptions::new().script_src(|s| {
            s.nonce_value(CspNonce {
                value: " helper-nonce ".to_string(),
            })
        });
        let script_value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value");
        assert!(script_value.contains("'nonce-helper-nonce'"));
    }
}

mod nonce {
    use super::*;

    #[test]
    fn given_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().script_src(|s| s.nonce("  inline-nonce  "));
        let script_value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value");
        assert!(script_value.contains("'nonce-inline-nonce'"));
    }
}

mod hash {
    use super::*;

    #[test]
    fn given_hash_when_configured_then_token_is_present() {
        let options =
            CspOptions::new().script_src(|s| s.hash(CspHashAlgorithm::Sha512, " 'hash-value' "));
        let script_value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value");
        assert!(script_value.contains("'sha512-hash-value'"));
    }
}

mod strict_dynamic {
    use super::*;

    #[test]
    fn given_strict_dynamic_when_configured_then_token_is_present() {
        let options = CspOptions::new().script_src(|s| s.strict_dynamic());
        let script_value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value");
        assert!(script_value.contains("'strict-dynamic'"));
    }
}

mod elem_nonce {
    use super::*;

    #[test]
    fn given_elem_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().script_src(|s| s.elem_nonce(" elem-nonce "));
        let elem_value = options
            .directive_value(CspDirective::ScriptSrcElem.as_str())
            .expect("script-src-elem value");
        assert!(elem_value.contains("'nonce-elem-nonce'"));
    }
}

mod elem_hash {
    use super::*;

    #[test]
    fn given_elem_hash_when_configured_then_token_is_present() {
        let options =
            CspOptions::new().script_src(|s| s.elem_hash(CspHashAlgorithm::Sha256, " elem-hash "));
        let elem_value = options
            .directive_value(CspDirective::ScriptSrcElem.as_str())
            .expect("script-src-elem value");
        assert!(elem_value.contains("'sha256-elem-hash'"));
    }
}

mod attr_nonce {
    use super::*;

    #[test]
    fn given_attr_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().script_src(|s| s.attr_nonce(" attr-nonce "));
        let attr_value = options
            .directive_value(CspDirective::ScriptSrcAttr.as_str())
            .expect("script-src-attr value");
        assert!(attr_value.contains("'nonce-attr-nonce'"));
    }
}

mod attr_hash {
    use super::*;

    #[test]
    fn given_attr_hash_when_configured_then_token_is_present() {
        let options =
            CspOptions::new().script_src(|s| s.attr_hash(CspHashAlgorithm::Sha384, " attr-hash "));
        let attr_value = options
            .directive_value(CspDirective::ScriptSrcAttr.as_str())
            .expect("script-src-attr value");
        assert!(attr_value.contains("'sha384-attr-hash'"));
    }
}

mod runtime_nonce {
    use super::*;

    #[test]
    fn given_script_runtime_nonce_when_render_then_replaces_placeholders() {
        let options = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::new())
            .script_src(|s| s.runtime_nonce());

        let header = options.render_with_runtime_nonce("abc123");
        assert!(header.contains("script-src 'nonce-abc123'"));
    }
}
