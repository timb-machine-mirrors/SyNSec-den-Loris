use std::{
    collections::HashMap,
    marker::PhantomData,
};
use libafl::{
    inputs::HasTargetBytes,
    state::HasRand,
};
use libafl_bolts::{
    HasLen,
    rands::Rand,
};

use crate::generator::{
    attribute::Attribute,
    utils,
};
use crate::grammar::{
    automaton::State,
    attribute::{AttrExpr, AttrName},
    base::{Expr as BaseExpr, LorisBaseGrammar},
    fast::{Expr as FastExpr, LorisFastGrammar},
    fast2::LorisFastGrammar2,
    LorisGrammar,
    rule::{AstRule, Rule},
    worklist::Worklist,
};
use crate::input::{
    field::{FastGrammarField, GrammarField, GrammarString},
    grammar::{BaseGrammarInput, FastGrammarInput},
    rule::RulePath,
};

pub trait LorisGrammarGenerator<'a, G, S>
where
    G: LorisGrammar,
    S: HasRand,
{
    type GrammarInput: std::fmt::Debug + HasTargetBytes;
    fn from_grammar(grammar: &'a G) -> Self;
    fn generate_example(&self, state: &mut S) -> Self::GrammarInput;
    fn generate_from_symbol(&self, state: &mut S, symbol: &str) -> Self::GrammarInput;
    fn generate_index(&self, index: usize, input: &mut Self::GrammarInput, state: &mut S);
    fn generate_continue(&self, input: &mut Self::GrammarInput, state: &mut S);
}

pub struct LorisBaseGrammarGenerator<'a, S>
where
    S: HasRand,
{
    grammar: &'a LorisBaseGrammar,
    phantom: PhantomData<S>,
}

impl<'a, S> LorisGrammarGenerator<'a, LorisBaseGrammar, S> for LorisBaseGrammarGenerator<'a, S>
where
    S: HasRand,
{
    type GrammarInput = BaseGrammarInput;

    #[must_use]
    fn from_grammar(grammar: &'a LorisBaseGrammar) -> Self {
        Self {
            grammar,
            phantom: PhantomData,
        }
    }

    fn generate_example(&self, state: &mut S) -> Self::GrammarInput {
        self.generate_from_symbol(state, self.grammar.start_symbol.as_str())
    }

    fn generate_from_symbol(&self, state: &mut S, symbol: &str) -> Self::GrammarInput {
        let mut worklist = Worklist::<BaseExpr>::new();
        let start_rule = self.grammar.get(symbol).expect("cannot find start rule");
        let has_attr = start_rule.attribute.is_some();
        worklist.add_rule(start_rule, None, 0, false).expect("cannot add the start rule");

        let mut attributes: HashMap<String, Attribute> = HashMap::new();

        self.process_ident(
            state,
            &mut worklist,
            &mut attributes,
            has_attr,
        ).expect("failed to process all terms")
    }

    fn generate_index(&self, index: usize, input: &mut Self::GrammarInput, state: &mut S) {
        todo!()
    }

    fn generate_continue(&self, input: &mut Self::GrammarInput, state: &mut S) {
        todo!()
    }
}

impl<'a, S> LorisBaseGrammarGenerator<'a, S>
where
    S: HasRand,
{
    fn process_ident(
        &self,
        state: &mut S,
        worklist: &mut Worklist<BaseExpr>,
        attributes: &mut HashMap<String, Attribute>,
        parent_has_attr: bool,
    ) -> Result<BaseGrammarInput, String> {
        let path = worklist.first().unwrap().get_path();
        let attr = worklist.first().unwrap().get_attr();

        let mut result = self.process_stack(
            state,
            worklist,
            attributes,
            parent_has_attr || attr.is_some()
        )?;
        if let Some(attr) = attr {
            if attr.writes_self() {
                result = self.process_attribute(path.clone(), attr, attributes)?;
            }
            if !parent_has_attr {
                result.reduce_fields_forced(&path);
            }
        } else {
            if !parent_has_attr {
                result.try_reduce_fields(&path);
            }
        }
        let l = result.string.len();
        let m = result.any_mutable();
        attributes.insert(format!("{}.{}", path.get_full(), AttrName::Length), Attribute::Number(l, m));
        let v = result.string.clone();
        attributes.insert(format!("{}.{}", path.get_full(), AttrName::Value), Attribute::String(v, m));

        Ok(result)
    }

    fn process_stack(
        &self,
        state: &mut S,
        worklist: &mut Worklist<BaseExpr>,
        attributes: &mut HashMap<String, Attribute>,
        parent_has_attr: bool,
    ) -> Result<BaseGrammarInput, String> {
        let mut result = BaseGrammarInput::new();

        while let Some(element) = worklist.pop() {

            let path = element.get_path();
            let expr = element.get_expr();
            let attr = element.get_attr();
            let index_in_seq = element.get_index_in_seq();
            let mutable = element.mutable();
            // if attr.is_some() { println!("#[{:?}]", attr.clone().unwrap()); }
            // println!("{index_in_seq} {}: {:?}", path, expr);
            match expr {
                // Matches an exact string, e.g. `"a"`
                BaseExpr::Str(string) => {
                    result.push_back(&mut GrammarField::new(path.append("string"), string, index_in_seq, mutable));
                }
                // Matches one character in the range, e.g. `'a'..'z'`
                BaseExpr::Range(from, to) => {
                    let random_u8 = state.rand_mut().between(from as u64, to as u64) as u8;
                    result.push_back(&mut GrammarField::new(path, vec![random_u8], index_in_seq, true));
                }
                // Matches the rule with the given name, e.g. `a`
                BaseExpr::Ident(ref name) => {
                    if let Some(new_rule) = self.grammar.get(name) {
                        let mut rule_worklist = Worklist::new();
                        rule_worklist.add_rule(new_rule, Some(path.clone()), 0, mutable)?;
                        let mut res = self.process_ident(state, &mut rule_worklist, attributes, parent_has_attr)?;
                        if let Some(attr) = attr {
                            if attr.writes_ident(name) {
                                res = self.process_attribute(path, attr, attributes)?;
                            }
                        }
                        result.append(&mut res);
                    } else {
                        return Err(format!("no such rule: {}", name));
                    }
                }
                // Matches a sequence of two expressions, e.g. `expr1 ~ expr2`
                BaseExpr::Seq(expr1, expr2) => {
                    worklist.add_expression(path.clone(), *expr2, attr.clone(), index_in_seq + 1, mutable)?;
                    worklist.add_expression(path, *expr1, attr, index_in_seq, mutable)?;
                }
                // Matches a right associative sequence of two expression, e.g. `expr1 < expr2`
                BaseExpr::RightSeq(expr1, expr2) => {
                    let mut inner_worklist = Worklist::new();
                    inner_worklist.add_expression(path.clone(), *expr2, attr.clone(), index_in_seq + 1, mutable)?;
                    let mut e2_res = self.process_stack(state, &mut inner_worklist, attributes, parent_has_attr)?;

                    let mut inner_worklist = Worklist::new();
                    inner_worklist.add_expression(path, *expr1, attr, index_in_seq, mutable)?;
                    let mut e1_res = self.process_stack(state, &mut inner_worklist, attributes, parent_has_attr)?;

                    result.append(&mut e1_res);
                    result.append(&mut e2_res);
                },
                // Matches either of two expressions, e.g. `expr1 | expr2`
                BaseExpr::Choice(expr1, expr2) => {
                    if state.rand_mut().below(2) == 0 {
                        worklist.add_expression(path, *expr1, attr, index_in_seq, true)?;
                    } else {
                        worklist.add_expression(path, *expr2, attr, index_in_seq, true)?;
                    }
                }
                // Optionally matches an expression, e.g. `e?`
                BaseExpr::Opt(expr) => {
                    if state.rand_mut().below(2) == 0 {
                        worklist.add_expression(path, *expr, attr, index_in_seq, mutable)?;
                    }
                }
                // Matches an expression an exact number of times, e.g. `expr{n}`
                BaseExpr::RepExact(expr, num_reps) => {
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression at least a number of times, e.g. `expr{n,}`
                BaseExpr::RepMin(expr, min_reps) => {
                    let mut num_reps = state.rand_mut().next() as usize;
                    let mut idx = index_in_seq;
                    if min_reps > 0 {
                        num_reps %= usize::MAX - (min_reps - 1);
                        num_reps += min_reps;
                    }
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression at most a number of times, e.g. `expr{,n}`
                BaseExpr::RepMax(expr, max_reps) => {
                    let num_reps = state.rand_mut().below(max_reps as u64 + 1) as usize;
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression a number of times within a range, e.g. `expr{m, n}`
                BaseExpr::RepMinMax(expr, min_reps, max_reps) => {
                    let num_reps = state.rand_mut().between(min_reps as u64, max_reps as u64) as usize;
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
            }
        }

        Ok(result)
    }

    fn process_attribute(
        &self,
        base_path: RulePath,
        attr: AttrExpr,
        attributes: &mut HashMap<String, Attribute>,
    ) -> Result<BaseGrammarInput
        , String> {
        let mut result = BaseGrammarInput::new();
        match attr {
            AttrExpr::BinOp { lhs, op, rhs } => {
                let rhs = utils::process_attribute_rhs(base_path.clone(), *rhs, attributes)?;
                match *lhs {
                    AttrExpr::Attr {ident, name} => {
                        let new_path = base_path.append(&ident);
                        let lhs_name = new_path.append(&name.to_string().to_owned()).get_full();
                        let lhs_length_name = new_path.append(&format!("{}", AttrName::Length)).get_full();
                        let attribute = match name {
                            AttrName::Value => {
                                let string = utils::process_attribute_assignment(lhs_name, op, &rhs, attributes)?;
                                string
                            },
                            AttrName::Length => unimplemented!("AttrName::Length"),
                            AttrName::Reps => unimplemented!("AttrName::Reps"),
                        };
                        let len = attributes.get(&lhs_length_name);
                        let (string, mutable) = match (attribute, len) {
                            (Attribute::Number(n, m1), Some(Attribute::Number(l, m2))) => {
                                // TODO: check for overflow
                                let mut n = n.to_le_bytes().to_vec();
                                n.truncate(*l);
                                (n, m1 | m2)
                            },
                            (Attribute::String(v, m), _) => {
                                (v, m)
                            },
                            (_, l) => unimplemented!("{:?} for AttrName::Length", l),
                        };
                        result.string = string.clone();
                        result.fields.push_back(GrammarField::new(new_path, string, 0xffff, mutable));
                    },
                    expr => unreachable!("Expected AttrExpr::Attr on LHS got {:?}", expr),
                };
            },
            expr => unreachable!("Expected an AttrExpr::BinOp got {:?}", expr),
        };

        Ok(result)
    }
}

pub struct LorisFastGrammarGenerator<'a, S>
where
    S: HasRand,
{
    grammar: &'a LorisFastGrammar,
    phantom: PhantomData<S>,
}

impl<'a, S> LorisGrammarGenerator<'a, LorisFastGrammar, S> for LorisFastGrammarGenerator<'a, S>
where
    S: HasRand,
{
    type GrammarInput = BaseGrammarInput;

    #[must_use]
    fn from_grammar(grammar: &'a LorisFastGrammar) -> Self {
        Self {
            grammar,
            phantom: PhantomData,
        }
    }

    fn generate_example(&self, state: &mut S) -> Self::GrammarInput {
        self.generate_from_symbol(state, self.grammar.start_symbol.as_str())
    }

    fn generate_from_symbol(&self, state: &mut S, symbol: &str) -> Self::GrammarInput {
        let mut worklist = Worklist::<FastExpr>::new();
        let start_rule = self.grammar.get(symbol).expect("cannot find start rule");
        let has_attr = start_rule.attribute.is_some();
        worklist.add_rule(start_rule, None, 0, false).expect("cannot add the start rule");

        let mut attributes: HashMap<String, Attribute> = HashMap::new();

        self.process_ident(
            state,
            &mut worklist,
            &mut attributes,
            has_attr,
        ).expect("failed to process all terms")
    }

    fn generate_index(&self, index: usize, input: &mut Self::GrammarInput, state: &mut S) {
        todo!()
    }

    fn generate_continue(&self, input: &mut Self::GrammarInput, state: &mut S) {
        todo!()
    }
}

impl<'a, S> LorisFastGrammarGenerator<'a, S>
where
    S: HasRand,
{
    fn process_ident(
        &self,
        state: &mut S,
        worklist: &mut Worklist<FastExpr>,
        attributes: &mut HashMap<String, Attribute>,
        parent_has_attr: bool,
    ) -> Result<BaseGrammarInput, String> {
        let path = worklist.first().unwrap().get_path();
        let attr = worklist.first().unwrap().get_attr();

        let mut result = self.process_stack(
            state,
            worklist,
            attributes,
            parent_has_attr || attr.is_some()
        )?;
        if let Some(attr) = attr {
            if attr.writes_self() {
                result = self.process_attribute(path.clone(), attr, attributes)?;
            }
            if !parent_has_attr {
                result.reduce_fields_forced(&path);
            }
        } else {
            if !parent_has_attr {
                result.try_reduce_fields(&path);
            }
        }
        let l = result.string.len();
        let m = result.any_mutable();
        attributes.insert(format!("{}.{}", path.get_full(), AttrName::Length), Attribute::Number(l, m));
        let v = result.string.clone();
        attributes.insert(format!("{}.{}", path.get_full(), AttrName::Value), Attribute::String(v, m));

        Ok(result)
    }

    fn process_stack(
        &self,
        state: &mut S,
        worklist: &mut Worklist<FastExpr>,
        attributes: &mut HashMap<String, Attribute>,
        parent_has_attr: bool,
    ) -> Result<BaseGrammarInput, String> {
        let mut result = BaseGrammarInput::new();

        while let Some(element) = worklist.pop() {

            let path = element.get_path();
            let expr = element.get_expr();
            let attr = element.get_attr();
            let index_in_seq = element.get_index_in_seq();
            let mutable = element.mutable();
            // if attr.is_some() { println!("#[{:?}]", attr.clone().unwrap()); }
            // println!("{index_in_seq} {}: {:?}", path, expr);
            match expr {
                // Matches an exact string, e.g. `"a"`
                FastExpr::Str(string) => {
                    result.push_back(&mut GrammarField::new(path.append("string"), string, index_in_seq, mutable));
                }
                // Matches one character in the range, e.g. `'a'..'z'`
                FastExpr::Range(from, to) => {
                    let random_u8 = state.rand_mut().between(from as u64, to as u64) as u8;
                    result.push_back(&mut GrammarField::new(path, vec![random_u8], index_in_seq, true));
                }
                // Matches the rule with the given name, e.g. `a`
                FastExpr::Ident(ref name) => {
                    if let Some(new_rule) = self.grammar.get(name) {
                        let mut rule_worklist = Worklist::new();
                        rule_worklist.add_rule(new_rule, Some(path.clone()), 0, mutable)?;
                        let mut res = self.process_ident(state, &mut rule_worklist, attributes, parent_has_attr)?;
                        if let Some(attr) = attr {
                            if attr.writes_ident(name) {
                                res = self.process_attribute(path, attr, attributes)?;
                            }
                        }
                        result.append(&mut res);
                    } else {
                        return Err(format!("no such rule: {}", name));
                    }
                }
                // Matches a sequence of two expressions, e.g. `expr1 ~ expr2`
                FastExpr::Seq(seq) => {
                    let mut idx = index_in_seq;
                    for expr in seq.into_iter().rev() {
                        worklist.add_expression(path.clone(), expr, attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                }
                // Matches a right associative sequence of two expression, e.g. `expr1 < expr2`
                FastExpr::RightSeq(expr1, expr2) => {
                    let mut inner_worklist = Worklist::new();
                    inner_worklist.add_expression(path.clone(), *expr2, attr.clone(), index_in_seq + 1, mutable)?;
                    let mut e2_res = self.process_stack(state, &mut inner_worklist, attributes, parent_has_attr)?;

                    let mut inner_worklist = Worklist::new();
                    inner_worklist.add_expression(path, *expr1, attr, index_in_seq, mutable)?;
                    let mut e1_res = self.process_stack(state, &mut inner_worklist, attributes, parent_has_attr)?;

                    result.append(&mut e1_res);
                    result.append(&mut e2_res);
                },
                // Matches either of two expressions, e.g. `expr1 | expr2`
                FastExpr::Choice(choice) => {
                    let n = choice.len();
                    let idx = state.rand_mut().below(n as u64) as usize;
                    let expr = choice.get(idx).unwrap().clone();
                    worklist.add_expression(path, expr, attr, index_in_seq, true)?;
                }
                // Optionally matches an expression, e.g. `e?`
                FastExpr::Opt(expr) => {
                    if state.rand_mut().below(2) == 0 {
                        worklist.add_expression(path, *expr, attr, index_in_seq, mutable)?;
                    }
                }
                // Matches an expression an exact number of times, e.g. `expr{n}`
                FastExpr::RepExact(expr, num_reps) => {
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression at least a number of times, e.g. `expr{n,}`
                FastExpr::RepMin(expr, min_reps) => {
                    let mut num_reps = state.rand_mut().next() as usize;
                    let mut idx = index_in_seq;
                    if min_reps > 0 {
                        num_reps %= usize::MAX - (min_reps - 1);
                        num_reps += min_reps;
                    }
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression at most a number of times, e.g. `expr{,n}`
                FastExpr::RepMax(expr, max_reps) => {
                    let num_reps = state.rand_mut().below(max_reps as u64 + 1) as usize;
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
                // Matches an expression a number of times within a range, e.g. `expr{m, n}`
                FastExpr::RepMinMax(expr, min_reps, max_reps) => {
                    let num_reps = state.rand_mut().between(min_reps as u64, max_reps as u64) as usize;
                    let mut idx = index_in_seq;
                    for _ in 0..num_reps {
                        worklist.add_expression(path.clone(), *expr.clone(), attr.clone(), idx, mutable)?;
                        idx += 1;
                    }
                    attributes.insert(format!("{}.{}.{}", path.get_full(), expr.generate_name(), AttrName::Reps), Attribute::Number(num_reps, true));
                }
            }
        }

        Ok(result)
    }

    fn process_attribute(
        &self,
        base_path: RulePath,
        attr: AttrExpr,
        attributes: &mut HashMap<String, Attribute>,
    ) -> Result<BaseGrammarInput, String> {
        let mut result = BaseGrammarInput::new();
        match attr {
            AttrExpr::BinOp { lhs, op, rhs } => {
                let rhs = utils::process_attribute_rhs(base_path.clone(), *rhs, attributes)?;
                match *lhs {
                    AttrExpr::Attr {ident, name} => {
                        let new_path = if ident == "self" {
                            base_path
                        } else {
                            base_path.append(&ident)
                        };
                        let lhs_name = new_path.append(&name.to_string().to_owned()).get_full();
                        let lhs_length_name = new_path.append(&format!("{}", AttrName::Length)).get_full();
                        let attribute = match name {
                            AttrName::Value => {
                                let string = utils::process_attribute_assignment(lhs_name, op, &rhs, attributes)?;
                                string
                            },
                            AttrName::Length => unimplemented!("AttrName::Length"),
                            AttrName::Reps => unimplemented!("AttrName::Reps"),
                        };
                        let len = attributes.get(&lhs_length_name);
                        let (string, mutable) = match (attribute, len) {
                            (Attribute::Number(n, m1), Some(Attribute::Number(l, m2))) => {
                                // TODO: check for overflow
                                let mut n = n.to_le_bytes().to_vec();
                                n.truncate(*l);
                                (n, m1 | m2)
                            },
                            (Attribute::String(v, m), _) => {
                                (v, m)
                            },
                            (_, l) => unimplemented!("{:?} for AttrName::Length", l),
                        };
                        result.string = string.clone();
                        result.fields.push_back(GrammarField::new(new_path, string, 0xffff, mutable));
                    },
                    expr => unreachable!("Expected AttrExpr::Attr on LHS got {:?}", expr),
                };
            },
            expr => unreachable!("Expected an AttrExpr::BinOp got {:?}", expr),
        };

        Ok(result)
    }
}

pub struct LorisFastGrammarGenerator2<'a, S>
where
    S: HasRand,
{
    grammar: &'a LorisFastGrammar2,
    phantom: PhantomData<S>,
}

impl<'a, S> LorisGrammarGenerator<'a, LorisFastGrammar2, S> for LorisFastGrammarGenerator2<'a, S>
where
    S: HasRand,
{
    type GrammarInput = FastGrammarInput;

    #[must_use]
    fn from_grammar(grammar: &'a LorisFastGrammar2) -> Self {
        Self {
            grammar,
            phantom: PhantomData,
        }
    }

    fn generate_example(&self, state: &mut S) -> Self::GrammarInput {
        let mut input = FastGrammarInput::new();
        let pda = self.grammar.start();
        self.generate_continue(pda, &mut input, state);
        input
    }

    fn generate_from_symbol(&self, state: &mut S, symbol: &str) -> Self::GrammarInput {
        todo!()
    }

    fn generate_index(&self, index: usize, input: &mut Self::GrammarInput, state: &mut S) {
        let pda = self.grammar.start();
        self.generate_pda_index(index, pda, input, state);
    }

    fn generate_continue(&self, input: &mut Self::GrammarInput, state: &mut S) {
        let pda = self.grammar.start();

        // hacky
        if input.fields().len() == 0 && input.string().len() > 0 {
            let string = input.string().clone();
            assert!(string.len() == 2 || string.len() == 3);
            let indices1 = Self::states_generate(pda, pda.init(), vec![string[0]]);
            for index1 in indices1 {
                let indices2 = Self::states_generate(pda, index1, vec![string[1]]);
                if indices2.len() > 0 {
                    // EMM messages
                    match string.len() {
                        /* EMM Messages */
                        2 => {
                            assert_eq!(indices2.len(), 1);
                            let index2 = indices2[0];
                            input.push_back(FastGrammarField::new(index1, vec![string[0]], true));
                            input.push_back(FastGrammarField::new(index2, vec![string[1]], false));
                            break;
                        },
                        /* ESM Messages */
                        3 => {
                            for index2 in indices2 {
                                let indices3 = Self::states_generate(pda, index2, vec![string[2]]);
                                if indices3.len() > 0 {
                                    assert_eq!(indices3.len(), 1);
                                    let index3 = indices3[0];
                                    input.push_back(FastGrammarField::new(index1, vec![string[0]], true));
                                    input.push_back(FastGrammarField::new(index2, vec![string[1]], false));
                                    input.push_back(FastGrammarField::new(index3, vec![string[2]], false));
                                }
                            }

                        },
                        _ => panic!("Cannot handle")
                    }
                }
            }
        }

        self.generate_continue(pda, input, state);
    }
}

impl<'a, S> LorisFastGrammarGenerator2<'a, S>
where
    S: HasRand,
{
    fn generate_continue(&self, pda: &<LorisFastGrammar2 as LorisGrammar>::Rule,
                         input: &mut FastGrammarInput, state: &mut S) {
        loop {
            // println!("{:?}", input);
            let idx = match self.get_next_rule(pda, input, state) {
                // Reached a final state with no next
                None => break,
                Some(idx) => idx,
            };
            // println!("DEBUG generate_continue:next_rule_idx={}", idx);

            if self.generate_pda_index(idx, pda, input, state) == false {
                break;
            }

            // If a final state is generated, stop with a 50% chance.
            if pda.is_final(idx) &&
                state.rand_mut().below(2u64) == 0 {
                break;
            }
        }
    }

    /// Returns the init state index if `input` has no fields, randomly chosen index from next
    /// vector, or `None` if the next vector is empty
    fn get_next_rule(&self, pda: &<LorisFastGrammar2 as LorisGrammar>::Rule,
                     input: &FastGrammarInput, state: &mut S) -> Option<usize> {
        input.fields()
            .last()
            .map_or(Some(self.grammar.start().init()), |last| {
                let next = pda.states().get(last.state()).unwrap().next();
                if next.len() == 0 {
                    None
                } else {
                    let idx = state.rand_mut().below(next.len() as u64) as usize;
                    Some(next[idx])
                }
            })
    }

    fn generate_pda_index(&self, index: usize, pda: &<LorisFastGrammar2 as LorisGrammar>::Rule,
                          input: &mut FastGrammarInput, state: &mut S) -> bool {
        let g_state = pda.states().get(index).unwrap();
        if g_state.rule.attr().is_some() {
            let string = self.generate_expr_with_attr(g_state.rule.clone(), state);
            input.push_back(FastGrammarField::new(index, string, true));
        } else {
            let expr = g_state.rule.expr().clone();
            let string = self.generate_expr(expr, state);
            input.push_back(FastGrammarField::new(index, string, true));
        }
        return true;
    }

    fn generate_expr_with_attr(&self, expr: AstRule<FastExpr>, state: &mut S) -> GrammarString {
        let mut attributes = HashMap::new();
        let attr = expr.attribute.unwrap();
        let expr = expr.expr;
        let string = self.generate_expr_int(expr, Some(attr.clone()), state, Some(&mut attributes));
        // println!("DEBUG generate_expr_with_attr:string={:?}", string);
        // println!("DEBUG generate_expr_with_attr:attributes={:?}", attributes);
        if attr.writes_self() {
            self.process_attribute(attr, &attributes)
        } else {
            string
        }
    }

    fn generate_expr(&self, expr: FastExpr, state: &mut S) -> GrammarString {
        self.generate_expr_int(expr, None, state, None)
    }

    fn generate_expr_int(&self, expr: FastExpr, attr: Option<AttrExpr>, state: &mut S,
                         attributes: Option<&mut HashMap<String, Attribute>>) -> GrammarString {
        match expr {
            FastExpr::Str(string) => string,
            FastExpr::Range(from, to) => {
                let random_u8 = state.rand_mut().between(from as u64, to as u64) as u8;
                vec![random_u8]
            },
            FastExpr::Ident(name) => {
                eprintln!("DEBUG generate_expr_int:ident={}", name);
                let new_pda = self.grammar.get(name.as_str()).unwrap();
                // println!("DEBUG generate_expr_int:new_pda({})={:?}", name, new_pda);
                let mut new_input = FastGrammarInput::new();
                self.generate_continue(new_pda, &mut new_input, state);
                let mut string = new_input.to_vec();
                if let Some(attributes) = attributes {
                    attributes.insert(format!("{}.{}", name, AttrName::Length),
                                      Attribute::Number(string.len(), false));
                    attributes.insert(format!("{}.{}", name, AttrName::Value),
                                      Attribute::String(string.clone(), false));
                    if let Some(attr) = attr {
                        if attr.writes_ident(name.as_str()) {
                            string = self.process_attribute(attr, attributes);
                        }
                    }
                }
                string
            },
            FastExpr::Seq(seq) => {
                let mut string = GrammarString::new();
                match attributes {
                    None => {
                        for expr in seq.into_iter() {
                            let str = self.generate_expr_int(expr, None, state, None);
                            string.extend(str);
                        }
                        string
                    },
                    Some(attributes) => {
                        for expr in seq.into_iter() {
                            let str = self.generate_expr_int(expr, attr.clone(), state, Some(attributes));
                            string.extend(str);
                        }
                        string
                    },
                }
            },
            FastExpr::RightSeq(expr1, expr2) => {
                let (string2, string1) = match attributes {
                    None => (self.generate_expr_int(*expr2, None, state, None),
                             self.generate_expr_int(*expr1, None, state, None)),
                    Some(attributes) => (self.generate_expr_int(*expr2, attr.clone(), state, Some(attributes)),
                                         self.generate_expr_int(*expr1, attr, state, Some(attributes))),
                };

                [string1, string2].concat()
            },
            FastExpr::Choice(choice) => {
                let n = choice.len();
                let idx = state.rand_mut().below(n as u64) as usize;
                let expr = choice.get(idx).unwrap().clone();
                match attributes {
                    None => self.generate_expr_int(expr, None, state, None),
                    Some(attributes) => self.generate_expr_int(expr, attr.clone(), state, Some(attributes)),
                }
            },
            FastExpr::Opt(expr) => {
                if state.rand_mut().below(2) == 0 {
                    return GrammarString::default()
                }
                match attributes {
                    None => self.generate_expr_int(*expr, None, state, None),
                    Some(attributes) => self.generate_expr_int(*expr, attr.clone(), state, Some(attributes)),
                }
            },
            FastExpr::RepExact(expr, n) => {
                let mut string = GrammarString::new();
                match attributes {
                    None => {
                        for _ in 0..n {
                            let str = self.generate_expr_int(*expr.clone(), None, state, None);
                            string.extend(str);
                        }
                        string
                    },
                    Some(attributes) => {
                        attributes.insert(format!("{}.{}", expr.generate_name(), AttrName::Reps),
                                          Attribute::Number(n, false));
                        for _ in 0..n {
                            let str = self.generate_expr_int(*expr.clone(), attr.clone(), state, Some(attributes));
                            string.extend(str);
                        }
                        string
                    }
                }
            },
            FastExpr::RepMin(expr, min) => {
                let mut n = state.rand_mut().next() as usize;
                if min > 0 {
                    n %= usize::MAX - (min - 1);
                    n += min;
                }
                self.generate_expr_int(FastExpr::RepExact(expr, n), attr, state, attributes)
            },
            FastExpr::RepMax(expr, max) => {
                let n = state.rand_mut().below(max as u64 + 1) as usize;
                self.generate_expr_int(FastExpr::RepExact(expr, n), attr, state, attributes)
            },
            FastExpr::RepMinMax(expr, min, max) => {
                let n = state.rand_mut().between(min as u64, max as u64) as usize;
                self.generate_expr_int(FastExpr::RepExact(expr, n), attr, state, attributes)
            },
        }
    }

    fn process_attribute(&self, attr: AttrExpr, attributes: &HashMap<String, Attribute>)
        -> GrammarString {
        match attr {
            AttrExpr::BinOp { lhs, op, rhs } => {
                // println!("attributes={:?}", attributes);
                let rhs_copy = rhs.clone();
                let rhs = utils::process_attribute_rhs(RulePath::default(), *rhs, attributes).unwrap();
                match *lhs {
                    AttrExpr::Attr {ident, name} => {
                        // println!("DEBUG process_attribute:ident={}, name={:?}", ident, name);

                        let lhs_value_name = format!("{}.{}", ident, AttrName::Value);
                        let lhs_length_name = format!("{}.{}", ident, AttrName::Length);

                        let lhs_attr = match name {
                            AttrName::Value =>
                                utils::process_attribute_assignment(lhs_value_name, op, &rhs, attributes)
                                    .unwrap(),
                            expr => unimplemented!("{:?}", expr),
                        };
                        // println!("process_attribute:lhs_length_name={}, lhs_attr={:?}", lhs_length_name, lhs_attr);

                        let lhs_len = attributes.get(&lhs_length_name);
                        let (string, mutable) = match (lhs_attr, lhs_len) {
                            (Attribute::Number(n, m1), Some(Attribute::Number(l, m2))) => {
                                let mut n = n.to_be_bytes().to_vec();
                                let split_idx = n.len().saturating_sub(*l);
                                let tail = n.split_off(split_idx);
                                let zeros = vec![0; n.len()];
                                assert_eq!(n, zeros, "while process_attribute:ident={}, name={:?}, rhs={:?}", ident, name, *rhs_copy);
                                (tail, m1 | m2)
                            },
                            (Attribute::String(v, m), _) => {
                                (v, m)
                            },
                            (_, l) => unimplemented!("{:?} for AttrName::Length", l),
                        };
                        string
                    },
                    expr => unreachable!("Expected AttrExpr::Attr on LHS got {:?}", expr),
                }
            },
            expr => unreachable!("Expected an AttrExpr::BinOp got {:?}", expr),
        }
    }

    fn states_generate(pda: &<LorisFastGrammar2 as LorisGrammar>::Rule, index: usize, string: GrammarString) -> Vec<usize> {
        let indices: Vec<usize> = pda.states()[index].next()
            .iter()
            .filter_map(|idx| {
                match pda.states()[*idx].rule.expr.clone() {
                    FastExpr::Str(str) => {
                        if str == string {
                            return Some(*idx);
                        }
                        None
                    },
                    _ => None,
                }
            })
            .collect();
        indices
    }
}