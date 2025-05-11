use crate::grammar::{
    attribute::AttrExpr,
    expression::Expression,
};

pub trait Rule {
    type Expr: Expression;

    fn name(&self) -> &String;
    fn typ(&self) -> RuleType;
    fn expr(&self) -> &Self::Expr;
    fn attr(&self) -> &Option<AttrExpr>;
}

/// All possible rule types
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleType {
    /// The normal rule type
    Normal,
    /// Silent rules are just like normal rules
    /// — when run, they function the same way —
    /// except they do not produce pairs or tokens.
    /// If a rule is silent, it will never appear in a parse result.
    /// (their syntax is `_{ ... }`)
    Silent,
}

/// A grammar rule
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AstRule<Ex> {
    /// The name of the rule
    pub name: String,
    /// The rule's type (silent, atomic, ...)
    pub ty: RuleType,
    /// The rule's expression
    pub expr: Ex,
    /// The rule's attribute
    pub attribute: Option<AttrExpr>,
}

impl<Ex> Rule for AstRule<Ex>
    where
        Ex: Expression,
{
    type Expr = Ex;

    fn name(&self) -> &String {
        &self.name
    }

    fn typ(&self) -> RuleType {
        self.ty
    }

    fn expr(&self) -> &Self::Expr {
        &self.expr
    }

    fn attr(&self) -> &Option<AttrExpr> {
        &self.attribute
    }
}

impl<Ex> Default for AstRule<Ex>
where
    Ex: Default,
{
    fn default() -> Self {
        Self {
            name: String::default(),
            ty: RuleType::Normal,
            expr: Ex::default(),
            attribute: None,
        }
    }
}

impl<Ex> AstRule<Ex> {
    /// Creates an [`AstRule`] with `expr`. Other fields are ignored.
    pub fn from_expr(expr: Ex) -> Self {
        Self {
            name: String::default(),
            ty: RuleType::Normal,
            expr,
            attribute: None,
        }
    }
}
