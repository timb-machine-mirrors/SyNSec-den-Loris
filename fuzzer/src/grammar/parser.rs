//! Types and helpers for the loris's own grammar parser.

use std::{
    collections::HashMap,
    iter::Peekable,
};
use pest::{
    error::{Error},
    iterators::{Pairs},
    Parser,
    pratt_parser::PrattParser,
    Span,
};

use crate::grammar::{
    rule::RuleType,
    attribute::{AttrExpr, AttrName, AttrOp},
    utils,
    validator::LorisGrammarValidator,
};

#[derive(Parser)]
#[grammar = "grammar/dsl.pest"]
pub struct LorisParser;

/// The loris grammar rule
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserRule<'i, PEx: 'i> {
    pub name: String,
    pub span: Span<'i>,
    pub ty: RuleType,
    pub node: ParserNode<'i, PEx>,
    pub attribute: Option<AttrExpr>,
}

/// The loris grammar node
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserNode<'i, PEx: 'i> {
    pub expr: PEx,
    pub span: Span<'i>,
}

pub trait LorisGrammarParser<'i, R, Ex, PEx: 'i>: Parser<Rule> + LorisGrammarValidator<'i, PEx> {
    fn compile_helper(grammar_str: &'i mut String, start_rule: Rule) -> Result<Vec<R>, String> {
        utils::replace_builtin_rules(grammar_str)
            .expect("failed to replace builtin rules");

        let pairs = Self::parse(start_rule, grammar_str.as_str())
            .expect("failed to parse grammar string");

        let rules = Self::consume_rules(pairs)
            .expect("failed to consume all rules");

        Ok(rules)
    }

    fn consume_rules(pairs: Pairs<'i, Rule>) -> Result<Vec<R>, Vec<Error<Rule>>> {
        let rules = Self::consume_rules_with_spans(pairs)?;
        let errors = Self::validate_ast(&rules);
        if errors.is_empty() {
            Ok(rules.into_iter().map(Self::convert_rule).collect())
        } else {
            Err(errors)
        }
    }

    fn convert_rule(rule: ParserRule<'_, PEx>) -> R;

    fn convert_node(node: ParserNode<'_, PEx>) -> Ex;

    fn unaries(
        pairs: Peekable<Pairs<'i, Rule>>,
        pratt: &PrattParser<Rule>,
    ) -> Result<ParserNode<'i, PEx>, Vec<Error<Rule>>>;

    fn consume_rules_with_spans(
        pairs: Pairs<'i, Rule>,
    ) -> Result<Vec<ParserRule<'i, PEx>>, Vec<Error<Rule>>> {
        use pest::pratt_parser::{Assoc::*, Op};
        let pratt = PrattParser::new()
            .op(Op::infix(Rule::choice_operator, Left))
            .op(Op::infix(Rule::right_sequence_operator, Right))
            .op(Op::infix(Rule::sequence_operator, Left));
        let attr_pratt = PrattParser::new()
            .op(Op::infix(Rule::assignment_operator, Right) |
                Op::infix(Rule::assignment_by_xor_operator, Right) |
                Op::infix(Rule::assignment_by_or_operator, Right) |
                Op::infix(Rule::assignment_by_and_operator, Right) |
                Op::infix(Rule::assignment_by_lsh_operator, Right) |
                Op::infix(Rule::assignment_by_rsh_operator, Right))
            .op(Op::infix(Rule::attribute_or_op, Left))
            .op(Op::infix(Rule::attribute_xor_op, Left))
            .op(Op::infix(Rule::attribute_and_op, Left))
            .op(Op::infix(Rule::attribute_lsh_op , Left) | Op::infix(Rule::attribute_rsh_op, Left))
            .op(Op::infix(Rule::attribute_sub_op, Left));

        pairs
            .filter(|pair| pair.as_rule() == Rule::grammar_rule)
            .map(|pair| {
                let mut pairs = pair.into_inner().peekable();

                let attribute = if pairs.peek().unwrap().as_rule() != Rule::identifier {
                    let attribute = pairs.next().unwrap();
                    let mut attribute_pairs = attribute.into_inner().peekable();
                    attribute_pairs.next().unwrap();  // opening_brack
                    let attr_expr_pairs = attribute_pairs.next().unwrap().into_inner().peekable();
                    Some(Self::consume_attr_expr(attr_expr_pairs, &attr_pratt))
                } else {
                    None
                };

                let span = pairs.next().unwrap().as_span();
                let name = span.as_str().to_owned();

                pairs.next().unwrap(); // assignment_operator

                let ty = if pairs.peek().unwrap().as_rule() != Rule::opening_brace {
                    match pairs.next().unwrap().as_rule() {
                        Rule::silent_modifier => RuleType::Silent,
                        _ => unreachable!(),
                    }
                } else {
                    RuleType::Normal
                };

                pairs.next().unwrap(); // opening_brace

                // skip initial infix operators
                let mut inner_nodes = pairs.next().unwrap().into_inner().peekable();
                if inner_nodes.peek().unwrap().as_rule() == Rule::choice_operator {
                    inner_nodes.next().unwrap();
                }

                let node = Self::consume_expr(inner_nodes, &pratt)?;

                Ok(ParserRule {
                    name,
                    span,
                    ty,
                    node,
                    attribute,
                })
            })
            .collect()
    }

    fn consume_expr(
        pairs: Peekable<Pairs<'i, Rule>>,
        pratt: &PrattParser<Rule>
    ) -> Result<ParserNode<'i, PEx>, Vec<Error<Rule>>>;

    fn consume_attr_expr(
        pairs: Peekable<Pairs<Rule>>,
        pratt: &PrattParser<Rule>,
    ) -> AttrExpr {
        pratt
            .map_primary(|primary| match primary.as_rule() {
                Rule::attr => {
                    let mut attr_pairs = primary.into_inner().peekable();
                    match attr_pairs.peek().unwrap().as_rule() {
                        Rule::identifier => {
                            let ident = attr_pairs.next().unwrap();
                            attr_pairs.next().unwrap();  // member_operator
                            let attr_name = attr_pairs.next().unwrap();
                            let attr_name = match attr_name.as_rule() {
                                Rule::attr_length => AttrName::Length,
                                Rule::attr_value => AttrName::Value,
                                Rule::attr_reps => AttrName::Reps,
                                rule => unreachable!("AttrExpr::parse expected attr_name, found {:?}", rule),
                            };
                            AttrExpr::Attr {
                                ident: ident.as_span().as_str().to_owned(),
                                name: attr_name,
                            }
                        },
                        Rule::string => {
                            let string = attr_pairs.next().unwrap();
                            let string  = utils::unescape(string.as_str()).expect("incorrect string literal");
                            AttrExpr::Literal(string[1..string.len()-1].to_vec())
                        },
                        Rule::number => {
                            let number = attr_pairs.next().unwrap();
                            let number_inner = number.into_inner().next().unwrap();
                            let number_str = number_inner.as_str();
                            let n = match number_inner.as_rule() {
                                Rule::hex => {
                                    let mut hex_paris = number_inner.into_inner();
                                    hex_paris.next().unwrap();  // hex_prefix
                                    let number_str = hex_paris
                                        .filter(|pair| pair.as_rule() == Rule::hex_digit)
                                        .fold("".to_string(), |curr, next| curr + next.as_str());
                                    usize::from_str_radix(number_str.as_str(), 16)
                                        .expect("incorrect number literal")
                                },
                                Rule::decimal => usize::from_str_radix(number_str, 10)
                                    .expect("incorrect number literal"),
                                rule => unreachable!("AttrExpr::parse expected number, found {:?}", rule),
                            };
                            AttrExpr::Number(n)
                        },
                        _ => unreachable!("attr"),
                    }
                },
                rule => unreachable!("AttrExpr::parse expected attr_expr, found {:?}", rule),
            })
            .map_infix(|lhs, op, rhs| {
                let op = match op.as_rule() {
                    Rule::assignment_operator => AttrOp::Assign,
                    Rule::assignment_by_rsh_operator => AttrOp::AssignByRsh,
                    Rule::assignment_by_lsh_operator => AttrOp::AssignByLsh,
                    Rule::assignment_by_and_operator => AttrOp::AssignByAnd,
                    Rule::assignment_by_or_operator => AttrOp::AssignByOr,
                    Rule::assignment_by_xor_operator => AttrOp::AssignByXor,
                    Rule::attribute_rsh_op => AttrOp::Rsh,
                    Rule::attribute_lsh_op => AttrOp::Lsh,
                    Rule::attribute_and_op => AttrOp::And,
                    Rule::attribute_xor_op => AttrOp::Xor,
                    Rule::attribute_or_op => AttrOp::Or,
                    Rule::attribute_sub_op => AttrOp::Sub,
                    rule => unreachable!("AttrExpr::parse expected infix operation, found {:?}", rule),
                };
                AttrExpr::BinOp {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                }
            })
            .parse(pairs)
    }
}

pub fn to_hash_map<'a, 'i: 'a, PEx: 'i>(
    rules: &'a [ParserRule<'i, PEx>]
) -> HashMap<String, &'a ParserNode<'i, PEx>> {
    rules.iter().map(|r| (r.name.clone(), &r.node)).collect()
}
