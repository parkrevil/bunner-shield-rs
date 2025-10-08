pub trait Executor {
    type Output;

    fn validate_options(&self) -> Result<(), String>;
    fn execute(&self) -> Self::Output;
}
