pub trait Expression {
    fn contains_ident(&self, ident: &str) -> bool;
}
