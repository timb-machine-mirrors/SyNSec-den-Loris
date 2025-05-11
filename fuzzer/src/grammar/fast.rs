use pest::{
    error::{Error, ErrorVariant},
    iterators::{Pair, Pairs},
    pratt_parser::PrattParser,
};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    iter::Peekable,
    path::Path,
};

use crate::grammar::{
    expression::Expression,
    LorisGrammar,
    parser::{self, LorisGrammarParser, LorisParser, ParserNode, ParserRule, Rule},
    rule::AstRule,
    utils,
    validator::LorisGrammarValidator,
};

/// All possible parser expressions
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParserExpr<'i> {
    /// Matches an exact string, e.g. `"a"`
    Str(Vec<u8>),
    /// Matches one character in the range, e.g. `'a'..'z'`
    Range(u8, u8),
    /// Matches the rule with the given name, e.g. `a`
    Ident(String),
    /// Matches a sequence of two expressions, e.g. `e1 ~ e2`
    Seq(Vec<ParserNode<'i, ParserExpr<'i>>>),
    /// Matches a right associative sequence of two expressions, e.g. `e1 < e2`
    RightSeq(Box<ParserNode<'i, ParserExpr<'i>>>, Box<ParserNode<'i, ParserExpr<'i>>>),
    /// Matches either of two expressions, e.g. `e1 | e2`
    Choice(Vec<ParserNode<'i, ParserExpr<'i>>>),
    /// Optionally matches an expression, e.g. `e?`
    Opt(Box<ParserNode<'i, ParserExpr<'i>>>),
    /// Matches an expression an exact number of times, e.g. `e{n}`
    RepExact(Box<ParserNode<'i, ParserExpr<'i>>>, usize),
    /// Matches an expression at least a number of times, e.g. `e{n,}`
    RepMin(Box<ParserNode<'i, ParserExpr<'i>>>, usize),
    /// Matches an expression at most a number of times, e.g. `e{,n}`
    RepMax(Box<ParserNode<'i, ParserExpr<'i>>>, usize),
    /// Matches an expression a number of times within a range, e.g. `e{m, n}`
    RepMinMax(Box<ParserNode<'i, ParserExpr<'i>>>, usize, usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    /// Matches an exact string, e.g. `"a"`
    Str(Vec<u8>),
    /// Matches one character in the range, e.g. `'a'..'z'`
    Range(u8, u8),
    /// Matches the rule with the given name, e.g. `a`
    Ident(String),
    /// Matches a sequence of two expressions, e.g. `e1 ~ e2`
    Seq(Vec<Expr>),
    /// Matches a right associative sequence of two expressions, e.g. `e1 < e2`
    RightSeq(Box<Expr>, Box<Expr>),
    /// Matches either of two expressions, e.g. `e1 | e2`
    Choice(Vec<Expr>),
    /// Optionally matches an expression, e.g. `e?`
    Opt(Box<Expr>),
    /// Matches an expression an exact number of times, e.g. `e{n}`
    RepExact(Box<Expr>, usize),
    /// Matches an expression at least a number of times, e.g. `e{n,}`
    RepMin(Box<Expr>, usize),
    /// Matches an expression at most a number of times, e.g. `e{,n}`
    RepMax(Box<Expr>, usize),
    /// Matches an expression a number of times within a range, e.g. `e{m, n}`
    RepMinMax(Box<Expr>, usize, usize),
}

impl Expression for Expr {
    fn contains_ident(&self, ident: &str) -> bool {
        match self {
            Expr::Ident(string) => string == ident,
            Expr::Seq(seq) |
            Expr::Choice(seq) => {
                seq.iter().any(|e| e.contains_ident(ident))
            }
            Expr::RightSeq(expr1, expr2) => {
                if expr1.contains_ident(ident) {
                    return true;
                }
                expr2.contains_ident(ident)
            },
            Expr::Opt(expr) |
            Expr::RepExact(expr, _) |
            Expr::RepMin(expr, _) |
            Expr::RepMax(expr, _) |
            Expr::RepMinMax(expr, _, _) => expr.contains_ident(ident),
            _ => false
        }
    }
}

impl Default for Expr {
    fn default() -> Self {
        Expr::Str(vec![])
    }
}

impl Expr {
    pub fn generate_name(&self) -> String {
        match self {
            Expr::Ident(name) => name.clone(),
            Expr::Opt(expr) => expr.generate_name(),
            Expr::RepExact(expr, _) => expr.generate_name(),
            Expr::RepMin(expr, _) => expr.generate_name(),
            Expr::RepMax(expr, _) => expr.generate_name(),
            Expr::RepMinMax(expr, _, _) => expr.generate_name(),
            expr => unimplemented!("{:?}::generate_name", expr),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LorisFastGrammar {
    pub rules: HashMap<String, AstRule<Expr>>,
    pub start_symbol: String,
}

impl<'i> LorisGrammarParser<'i, AstRule<Expr>, Expr, ParserExpr<'i>> for LorisParser {
    fn convert_rule(rule: ParserRule<'_, ParserExpr<'_>>) -> AstRule<Expr> {
        let ParserRule { name, ty, node, attribute, .. } = rule;
        let expr = LorisParser::convert_node(node);
        AstRule { name, ty, expr, attribute }
    }

    fn convert_node(node: ParserNode<'_, ParserExpr<'_>>) -> Expr {
        match node.expr {
            ParserExpr::Str(string) => Expr::Str(string),
            ParserExpr::Range(start, end) => Expr::Range(start, end),
            ParserExpr::Ident(ident) => Expr::Ident(ident),
            ParserExpr::Seq(seq) => Expr::Seq(seq.into_iter().map(LorisParser::convert_node).collect()),
            ParserExpr::RightSeq(node1, node2) => Expr::RightSeq(
                Box::new(LorisParser::convert_node(*node1)),
                Box::new(LorisParser::convert_node(*node2)),
            ),
            ParserExpr::Choice(choice) => Expr::Choice(choice.into_iter().map(LorisParser::convert_node).collect()),
            ParserExpr::Opt(node) => Expr::Opt(Box::new(LorisParser::convert_node(*node))),
            ParserExpr::RepExact(node, num) => Expr::RepExact(Box::new(LorisParser::convert_node(*node)), num),
            ParserExpr::RepMin(node, max) => Expr::RepMin(Box::new(LorisParser::convert_node(*node)), max),
            ParserExpr::RepMax(node, max) => Expr::RepMax(Box::new(LorisParser::convert_node(*node)), max),
            ParserExpr::RepMinMax(node, min, max) => {
                Expr::RepMinMax(Box::new(LorisParser::convert_node(*node)), min, max)
            }
        }
    }

    fn unaries(
        mut pairs: Peekable<Pairs<'i, Rule>>,
        pratt: &PrattParser<Rule>,
    ) -> Result<ParserNode<'i, ParserExpr<'i>>, Vec<Error<Rule>>> {
        let pair = pairs.next().unwrap();

        let node = match pair.as_rule() {
            Rule::opening_paren => {
                let node = LorisParser::unaries(pairs, pratt)?;
                let end = node.span.end_pos();

                ParserNode {
                    expr: node.expr,
                    span: pair.as_span().start_pos().span(&end),
                }
            }
            other_rule => {
                let node = match other_rule {
                    Rule::expression => LorisParser::consume_expr(pair.into_inner().peekable(), pratt)?,
                    Rule::identifier => ParserNode {
                        expr: ParserExpr::Ident(pair.as_str().to_owned()),
                        span: pair.clone().as_span(),
                    },
                    Rule::string => {
                        let string = utils::unescape(pair.as_str()).expect("incorrect string literal");
                        ParserNode {
                            expr: ParserExpr::Str(string[1..string.len() - 1].to_owned()),
                            span: pair.clone().as_span(),
                        }
                    }
                    Rule::range => {
                        let mut pairs = pair.into_inner();
                        let pair = pairs.next().unwrap();
                        let start = utils::unescape(pair.as_str()).expect("incorrect char literal");
                        let start_pos = pair.clone().as_span().start_pos();
                        pairs.next();
                        let pair = pairs.next().unwrap();
                        let end = utils::unescape(pair.as_str()).expect("incorrect char literal");
                        let end_pos = pair.clone().as_span().end_pos();

                        ParserNode {
                            expr: ParserExpr::Range(
                                start[1],
                                end[1],
                            ),
                            span: start_pos.span(&end_pos),
                        }
                    }
                    _ => unreachable!(),
                };

                pairs.fold(
                    Ok(node),
                    |node: Result<ParserNode<'i, ParserExpr>, Vec<Error<Rule>>>, pair| {
                        let node = node?;

                        let node = match pair.as_rule() {
                            Rule::optional_operator => {
                                let start = node.span.start_pos();
                                ParserNode {
                                    expr: ParserExpr::Opt(Box::new(node)),
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            Rule::repeat_exact => {
                                let mut inner = pair.clone().into_inner();

                                inner.next().unwrap(); // opening_brace

                                let number = inner.next().unwrap();
                                let num = if let Ok(num) = number.as_str().parse::<usize>() {
                                    num
                                } else {
                                    return Err(vec![Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "number cannot overflow u32".to_owned(),
                                        },
                                        number.as_span(),
                                    )]);
                                };

                                if num == 0 {
                                    let error: Error<Rule> = Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "cannot repeat 0 times".to_owned(),
                                        },
                                        number.as_span(),
                                    );

                                    return Err(vec![error]);
                                }

                                let start = node.span.start_pos();
                                ParserNode {
                                    expr: ParserExpr::RepExact(Box::new(node), num),
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            Rule::repeat_min => {
                                let mut inner = pair.clone().into_inner();

                                inner.next().unwrap(); // opening_brace

                                let min_number = inner.next().unwrap();
                                let min = if let Ok(min) = min_number.as_str().parse::<usize>() {
                                    min
                                } else {
                                    return Err(vec![Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "number cannot overflow u32".to_owned(),
                                        },
                                        min_number.as_span(),
                                    )]);
                                };

                                let start = node.span.start_pos();
                                ParserNode {
                                    expr: ParserExpr::RepMin(Box::new(node), min),
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            Rule::repeat_max => {
                                let mut inner = pair.clone().into_inner();

                                inner.next().unwrap(); // opening_brace
                                inner.next().unwrap(); // comma

                                let max_number = inner.next().unwrap();
                                let max = if let Ok(max) = max_number.as_str().parse::<usize>() {
                                    max
                                } else {
                                    return Err(vec![Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "number cannot overflow u32".to_owned(),
                                        },
                                        max_number.as_span(),
                                    )]);
                                };

                                if max == 0 {
                                    let error: Error<Rule> = Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "cannot repeat 0 times".to_owned(),
                                        },
                                        max_number.as_span(),
                                    );

                                    return Err(vec![error]);
                                }

                                let start = node.span.start_pos();
                                ParserNode {
                                    expr: ParserExpr::RepMax(Box::new(node), max),
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            Rule::repeat_min_max => {
                                let mut inner = pair.clone().into_inner();

                                inner.next().unwrap(); // opening_brace

                                let min_number = inner.next().unwrap();
                                let min = if let Ok(min) = min_number.as_str().parse::<usize>() {
                                    min
                                } else {
                                    return Err(vec![Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "number cannot overflow u32".to_owned(),
                                        },
                                        min_number.as_span(),
                                    )]);
                                };

                                inner.next().unwrap(); // comma

                                let max_number = inner.next().unwrap();
                                let max = if let Ok(max) = max_number.as_str().parse::<usize>() {
                                    max
                                } else {
                                    return Err(vec![Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "number cannot overflow u32".to_owned(),
                                        },
                                        max_number.as_span(),
                                    )]);
                                };

                                if max == 0 {
                                    let error: Error<Rule> = Error::new_from_span(
                                        ErrorVariant::CustomError {
                                            message: "cannot repeat 0 times".to_owned(),
                                        },
                                        max_number.as_span(),
                                    );

                                    return Err(vec![error]);
                                }

                                let start = node.span.start_pos();
                                ParserNode {
                                    expr: ParserExpr::RepMinMax(Box::new(node), min, max),
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            Rule::closing_paren => {
                                let start = node.span.start_pos();

                                ParserNode {
                                    expr: node.expr,
                                    span: start.span(&pair.as_span().end_pos()),
                                }
                            }
                            _ => unreachable!(),
                        };

                        Ok(node)
                    },
                )?
            }
        };

        Ok(node)
    }

    fn consume_expr(pairs: Peekable<Pairs<'i, Rule>>, pratt: &PrattParser<Rule>) -> Result<ParserNode<'i, ParserExpr<'i>>, Vec<Error<Rule>>> {
        let term = |pair: Pair<'i, Rule>| LorisParser::unaries(pair.into_inner().peekable(), pratt);
        let infix = |lhs: Result<ParserNode<'i, ParserExpr>, Vec<Error<Rule>>>,
                     op: Pair<'i, Rule>,
                     rhs: Result<ParserNode<'i, ParserExpr>, Vec<Error<Rule>>>| match op.as_rule() {
            Rule::sequence_operator => {
                let lhs = lhs?;
                let lhs_expr = lhs.expr.clone();
                let rhs = rhs?;
                let rhs_expr = rhs.expr.clone();

                let start = lhs.span.start_pos();
                let end = rhs.span.end_pos();
                let span = start.span(&end);

                let expr = match (lhs_expr, rhs_expr) {
                    (ParserExpr::Seq(mut lhs_seq), ParserExpr::Seq(mut rhs_seq)) => {
                        lhs_seq.append(&mut rhs_seq);
                        ParserExpr::Seq(lhs_seq)
                    },
                    (ParserExpr::Seq(mut seq), _) => {
                        seq.push(rhs);
                        ParserExpr::Seq(seq)
                    }
                    _ => ParserExpr::Seq(vec![lhs, rhs]),
                };

                Ok(ParserNode { expr, span })
            }
            Rule::right_sequence_operator => {
                let lhs = lhs?;
                let rhs = rhs?;

                let start = lhs.span.start_pos();
                let end = rhs.span.end_pos();

                Ok(ParserNode {
                    expr: ParserExpr::RightSeq(Box::new(lhs), Box::new(rhs)),
                    span: start.span(&end),
                })
            }
            Rule::choice_operator => {
                let lhs = lhs?;
                let lhs_expr = lhs.expr.clone();
                let rhs = rhs?;
                let rhs_expr = rhs.expr.clone();

                let start = lhs.span.start_pos();
                let end = rhs.span.end_pos();
                let span = start.span(&end);

                let expr = match (lhs_expr, rhs_expr) {
                    (ParserExpr::Choice(mut lhs_ch), ParserExpr::Choice(mut rhs_ch)) => {
                        lhs_ch.append(&mut rhs_ch);
                        ParserExpr::Choice(lhs_ch)
                    },
                    (ParserExpr::Choice(mut ch), _) => {
                        ch.push(rhs);
                        ParserExpr::Choice(ch)
                    },
                    _ => ParserExpr::Choice(vec![lhs, rhs])
                };

                Ok(ParserNode { expr, span })
            }
            _ => unreachable!(),
        };

        pratt.map_primary(term).map_infix(infix).parse(pairs)
    }
}

impl<'i> LorisGrammarValidator<'i, ParserExpr<'i>> for LorisParser {
    fn validate_repetition(rules: &[ParserRule<'i, ParserExpr<'i>>]) -> Vec<Error<Rule>> {
        let mut result = vec![];
        let map = parser::to_hash_map(rules);

        for rule in rules {
            let mut errors = rule.node
                .clone()
                .filter_map_top_down(|node| match node.expr {
                    ParserExpr::RepMin(ref other, _) => {
                        if Self::is_non_failing(&other.expr, &map, &mut vec![]) {
                            Some(Error::new_from_span(
                                ErrorVariant::CustomError {
                                    message:
                                    "expression inside repetition cannot fail and will repeat \
                                     infinitely"
                                        .to_owned()
                                },
                                node.span
                            ))
                        } else if Self::is_non_progressing(&other.expr, &map, &mut vec![]) {
                            Some(Error::new_from_span(
                                ErrorVariant::CustomError {
                                    message:
                                    "expression inside repetition is non-progressing and will repeat \
                                     infinitely"
                                        .to_owned(),
                                },
                                node.span
                            ))
                        } else {
                            None
                        }
                    }
                    _ => None
                });

            result.append(&mut errors);
        }

        result
    }

    fn is_non_failing(
        expr: &ParserExpr<'i>,
        rules: &HashMap<String, &ParserNode<'i, ParserExpr<'i>>>,
        trace: &mut Vec<String>,
    ) -> bool {
        match *expr {
            ParserExpr::Str(ref string) => string.is_empty(),
            ParserExpr::Ident(ref ident) => {
                if !trace.contains(ident) {
                    if let Some(node) = rules.get(ident) {
                        trace.push(ident.clone());
                        let result = Self::is_non_failing(&node.expr, rules, trace);
                        trace.pop().unwrap();

                        return result;
                    }
                }

                false
            }
            ParserExpr::Opt(_) => true,
            ParserExpr::Seq(ref seq) => {
                seq.iter().fold(true, |p, n| p && Self::is_non_failing(&n.expr, rules, trace))
            }
            ParserExpr::Choice(ref choice) => {
                choice.iter().fold(false, |p, n| p || Self::is_non_failing(&n.expr, rules, trace))
            }
            _ => false,
        }
    }

    fn is_non_progressing(
        expr: &ParserExpr<'i>,
        rules: &HashMap<String, &ParserNode<'i, ParserExpr<'i>>>,
        trace: &mut Vec<String>,
    ) -> bool {
        match *expr {
            ParserExpr::Str(ref string) => string.is_empty(),
            ParserExpr::Ident(ref ident) => {
                if ident == "soi" || ident == "eoi" {
                    return true;
                }

                if !trace.contains(ident) {
                    if let Some(node) = rules.get(ident) {
                        trace.push(ident.clone());
                        let result = Self::is_non_progressing(&node.expr, rules, trace);
                        trace.pop().unwrap();

                        return result;
                    }
                }

                false
            }
            ParserExpr::Seq(ref seq) => {
                seq.iter().fold(true, |p, n| p && Self::is_non_progressing(&n.expr, rules, trace))
            }
            ParserExpr::Choice(ref choice) => {
                choice.iter().fold(false, |p, n| p || Self::is_non_progressing(&n.expr, rules, trace))
            }
            _ => false,
        }
    }

    fn validate_choices(
        _rules: &[ParserRule<'i, ParserExpr<'i>>]
    ) -> Vec<Error<Rule>> {
        // TODO: implement this
        vec![]
    }

    fn validate_whitespace_comment(
        rules: &[ParserRule<'i, ParserExpr<'i>>]
    ) -> Vec<Error<Rule>> {
        let map = parser::to_hash_map(rules);

        rules
            .iter()
            .filter_map(|rule| {
                if rule.name == "WHITESPACE" || rule.name == "COMMENT" {
                    if Self::is_non_failing(&rule.node.expr, &map, &mut vec![]) {
                        Some(Error::new_from_span(
                            ErrorVariant::CustomError {
                                message: format!(
                                    "{} cannot fail and will repeat infinitely",
                                    &rule.name
                                ),
                            },
                            rule.node.span,
                        ))
                    } else if Self::is_non_progressing(&rule.node.expr, &map, &mut vec![]) {
                        Some(Error::new_from_span(
                            ErrorVariant::CustomError {
                                message: format!(
                                    "{} is non-progressing and will repeat infinitely",
                                    &rule.name
                                ),
                            },
                            rule.node.span,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    fn validate_left_recursion(
        node: &ParserNode<'i, ParserExpr<'i>>,
        rules: &HashMap<String, &ParserNode<'i, ParserExpr<'i>>>,
        trace: &mut Vec<String>
    ) -> Option<Error<Rule>> {
        match node.expr.clone() {
            ParserExpr::Ident(other) => {
                if trace[0] == other {
                    trace.push(other);
                    let chain = trace
                        .iter()
                        .map(|ident| ident.as_ref())
                        .collect::<Vec<_>>()
                        .join(" -> ");

                    return Some(Error::new_from_span(
                        ErrorVariant::CustomError {
                            message: format!(
                                "rule {} is left-recursive ({}); pest::pratt_parser might be useful \
                                 in this case",
                                node.span.as_str(),
                                chain
                            )
                        },
                        node.span
                    ));
                }

                if !trace.contains(&other) {
                    if let Some(node) = rules.get(&other) {
                        trace.push(other);
                        let result = Self::validate_left_recursion(node, rules, trace);
                        trace.pop().unwrap();

                        return result;
                    }
                }

                None
            }
            ParserExpr::Seq(_) => {
                // TODO: implement this
                None
            }
            ParserExpr::Choice(_) => {
                // TODO: implement this
                None
            }
            ParserExpr::Opt(ref node) => Self::validate_left_recursion(node, rules, trace),
            _ => None,
        }
    }
}

impl LorisGrammar for LorisFastGrammar {
    type Rule = AstRule<Expr>;

    fn from_file(path: &Path, start: String) -> Result<Self, String> {
        let mut grammar = fs::read_to_string(path).expect("cannon read file");
        let rules: Vec<Self::Rule> = LorisParser::compile_helper(&mut grammar, Rule::grammar_rules)?;

        // panic if there are multiple rules with the same name
        let mut names =  BTreeSet::<String>::new();
        rules
            .iter()
            .for_each(|rule| {
                if names.contains(rule.name.as_str()) {
                    panic!("multiple definitions of symbol found: {}", rule.name.as_str());
                }
                names.insert(rule.name.clone());
            });
        let name2rule_map: HashMap<String, Self::Rule> = rules
            .iter()
            .map(|rule| (rule.name.to_string(), rule.clone()))
            .collect();
        if name2rule_map.contains_key(start.as_str()) == false {
            panic!("no such symbol: {}", start)
        }

        Ok(LorisFastGrammar {
            rules: name2rule_map,
            start_symbol: start,
        })
    }

    fn start(&self) -> &Self::Rule {
        self.get(self.start_symbol.as_str()).unwrap()
    }

    fn start_mut(&mut self) -> &mut Self::Rule {
        let ss = self.start_symbol.clone();
        self.get_mut(ss.as_str()).unwrap()
    }

    fn get(&self, name: &str) -> Option<&Self::Rule> {
        self.rules.get(name)
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut Self::Rule> {
        self.rules.get_mut(name)
    }
}

impl<'i> ParserNode<'i, ParserExpr<'i>> {
    /// will remove nodes that do not match `f`
    pub fn filter_map_top_down<F, T>(self, mut f: F) -> Vec<T>
        where
            F: FnMut(ParserNode<'i, ParserExpr<'i>>) -> Option<T>,
    {
        pub fn filter_internal<'i, F, T>(node: ParserNode<'i, ParserExpr<'i>>, f: &mut F, result: &mut Vec<T>)
            where
                F: FnMut(ParserNode<'i, ParserExpr<'i>>) -> Option<T>,
        {
            if let Some(value) = f(node.clone()) {
                result.push(value);
            }

            match node.expr {
                // TODO: Use box syntax when it gets stabilized.
                ParserExpr::Seq(seq) => {
                    seq.into_iter().for_each(|n| filter_internal(n, f, result));
                }
                ParserExpr::Choice(choice) => {
                    choice.into_iter().for_each(|n| filter_internal(n, f, result));
                }
                ParserExpr::RepExact(node, _) => {
                    filter_internal(*node, f, result);
                }
                ParserExpr::RepMin(node, _) => {
                    filter_internal(*node, f, result);
                }
                ParserExpr::RepMax(node, _) => {
                    filter_internal(*node, f, result);
                }
                ParserExpr::RepMinMax(node, ..) => {
                    filter_internal(*node, f, result);
                }
                ParserExpr::Opt(node) => {
                    filter_internal(*node, f, result);
                }
                _ => (),
            }
        }

        let mut result = vec![];

        filter_internal(self, &mut f, &mut result);

        result
    }
}
