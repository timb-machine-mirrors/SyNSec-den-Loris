use serde_derive::{Deserialize, Serialize};
use std::fmt::{self, Formatter};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RulePath {
    base: String,
    name: String,
}

impl fmt::Display for RulePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_full())
    }
}

impl RulePath {
    #[must_use]
    pub fn new(base: &str, name: &str) -> Self {
        Self { base: base.to_string().to_owned(), name: name.to_string().to_owned() }
    }

    pub fn append(&self, name: &str) -> RulePath {
        RulePath {
            base: self.get_full(),
            name: name.to_string().to_owned(),
        }
    }

    pub fn get_full(&self) -> String {
        if self.base.is_empty() {
            return  self.name.clone()
        }
        format!("{}.{}", self.base, self.name)
    }

    pub fn get_symbol(&self) -> String {
        return self.name.clone();
    }

    pub fn starts_with(&self, path: &RulePath) -> bool {
        self.get_full().starts_with(&path.get_full())
    }
}
