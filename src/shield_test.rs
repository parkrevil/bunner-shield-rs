use super::Shield;

mod new {
    use super::*;

    #[test]
    fn given_default_state_when_new_then_returns_shield() {
        let expected = Shield;
        let actual = Shield::new();

        assert_eq!(actual, expected);
    }
}
