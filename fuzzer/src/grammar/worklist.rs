use crate::grammar::{
    attribute::AttrExpr,
    expression::Expression,
    rule::Rule,
};
use crate::input::{
    rule::RulePath,
};

#[derive(Clone, Debug)]
pub struct Element<Ex> {
    path: RulePath,
    expr: Ex,
    attr: Option<AttrExpr>,
    index_in_seq: usize,
    mutable: bool
}

pub struct Worklist<Ex> {
    stack: Vec<Element<Ex>>,
}

impl<Ex> Element<Ex>
where
    Ex: Clone + Expression,
{
    #[must_use]
    fn new(path: RulePath, expr: Ex, attr: Option<AttrExpr>, index_in_seq: usize, mutable: bool) -> Self {
        Self { path, expr, attr, index_in_seq, mutable }
    }

    pub fn get_path(&self) -> RulePath {
        self.path.clone()
    }

    pub fn get_expr(&self) -> Ex {
        self.expr.clone()
    }

    pub fn get_attr(&self) -> Option<AttrExpr> {
        self.attr.clone()
    }

    pub fn get_index_in_seq(&self) -> usize {
        self.index_in_seq
    }

    pub fn mutable(&self) -> bool {
        self.mutable
    }
}

impl<Ex> Worklist<Ex>
where
    Ex: Clone + Expression,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
        }
    }

    pub fn add_expression(
        &mut self,
        path: RulePath,
        expr: Ex,
        attr: Option<AttrExpr>,
        index_in_seq: usize,
        mutable: bool
    ) -> Result<(), String> {
        if let Some(attr) = attr {
            if expr.contains_ident(&attr.lhs_ident()?) {
                self.push(Element::new(path, expr, Some(attr), index_in_seq, mutable));
                return Ok(())
            } else {
                self.push(Element::new(path, expr, None, index_in_seq, mutable));
            }
        } else {
            self.push(Element::new(path, expr, None, index_in_seq, mutable));
        }
        Ok(())
    }

    pub fn add_rule<R>(
        &mut self,
        rule: &R,
        base: Option<RulePath>,
        index_in_seq: usize,
        mutable: bool,
    ) -> Result<(), String>
    where
        R: Rule<Expr=Ex>,
    {
        let path = match base {
            None => RulePath::new("", rule.name()),
            Some(base) => base.append(rule.name())
        };
        let expr = rule.expr().to_owned();
        let attr = rule.attr().to_owned();
        if let Some(attr) = attr {
            if attr.writes_self() | expr.contains_ident(&attr.lhs_ident()?) {
                self.push(Element::new(path, expr, Some(attr), index_in_seq, mutable));
            } else {
                self.push(Element::new(path, expr, None, index_in_seq, mutable));
            }
        } else {
            self.push(Element::new(path, expr, None, index_in_seq, mutable));
        }
        Ok(())
    }

    fn push(&mut self, element: Element<Ex>) {
        self.stack.push(element);
    }

    pub fn pop(&mut self) -> Option<Element<Ex>> {
        self.stack.pop()
    }

    pub fn first(&self) -> Option<&Element<Ex>> {
        self.stack.last()
    }
}
