#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Shield;

impl Shield {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
