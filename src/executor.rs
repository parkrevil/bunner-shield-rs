#[allow(dead_code)]
pub trait Executor {
    type Output;

    fn execute(&self) -> Self::Output;
}
