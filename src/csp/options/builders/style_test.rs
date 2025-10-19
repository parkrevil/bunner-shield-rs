use super::*;

mod nonce {
    use super::*;

    #[test]
    fn given_style_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().style_src(|s| s.nonce(" style-nonce "));
        let style_value = options
            .directive_value(CspDirective::StyleSrc.as_str())
            .expect("style-src value");
        assert!(style_value.contains("'nonce-style-nonce'"));
    }
}

mod hash {
    use super::*;

    #[test]
    fn given_style_hash_when_configured_then_token_is_present() {
        let options =
            CspOptions::new().style_src(|s| s.hash(CspHashAlgorithm::Sha384, " style-hash "));
        let style_value = options
            .directive_value(CspDirective::StyleSrc.as_str())
            .expect("style-src value");
        assert!(style_value.contains("'sha384-style-hash'"));
    }
}

mod elem_nonce {
    use super::*;

    #[test]
    fn given_style_elem_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().style_src(|s| s.elem_nonce(" style-elem-nonce "));
        let elem_value = options
            .directive_value(CspDirective::StyleSrcElem.as_str())
            .expect("style-src-elem value");
        assert!(elem_value.contains("'nonce-style-elem-nonce'"));
    }
}

mod elem_hash {
    use super::*;

    #[test]
    fn given_style_elem_hash_when_configured_then_token_is_present() {
        let options = CspOptions::new()
            .style_src(|s| s.elem_hash(CspHashAlgorithm::Sha512, " style-elem-hash "));
        let elem_value = options
            .directive_value(CspDirective::StyleSrcElem.as_str())
            .expect("style-src-elem value");
        assert!(elem_value.contains("'sha512-style-elem-hash'"));
    }
}

mod attr_nonce {
    use super::*;

    #[test]
    fn given_style_attr_nonce_when_configured_then_token_is_present() {
        let options = CspOptions::new().style_src(|s| s.attr_nonce(" style-attr-nonce "));
        let attr_value = options
            .directive_value(CspDirective::StyleSrcAttr.as_str())
            .expect("style-src-attr value");
        assert!(attr_value.contains("'nonce-style-attr-nonce'"));
    }
}

mod attr_hash {
    use super::*;

    #[test]
    fn given_style_attr_hash_when_configured_then_token_is_present() {
        let options = CspOptions::new()
            .style_src(|s| s.attr_hash(CspHashAlgorithm::Sha256, " style-attr-hash "));
        let attr_value = options
            .directive_value(CspDirective::StyleSrcAttr.as_str())
            .expect("style-src-attr value");
        assert!(attr_value.contains("'sha256-style-attr-hash'"));
    }
}
