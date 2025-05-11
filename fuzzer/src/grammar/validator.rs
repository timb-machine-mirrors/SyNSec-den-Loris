use std::collections::HashMap;
use pest::{
    error::{Error, InputLocation},
};

use crate::grammar::{
    parser::{self, ParserNode, ParserRule, Rule},
};

pub trait LorisGrammarValidator<'i, PEx: 'i> {
    fn validate_ast(rules: &Vec<ParserRule<'i, PEx>>) -> Vec<Error<Rule>> {
        let mut errors = vec![];

        errors.extend(Self::validate_repetition(rules));
        errors.extend(Self::validate_choices(rules));
        errors.extend(Self::validate_whitespace_comment(rules));
        errors.extend(Self::validate_left_recursion_wrapper(rules));

        errors.sort_by_key(|error| match error.location {
            InputLocation::Span(span) => span,
            _ => unreachable!(),
        });

        errors
    }

    fn validate_repetition(rules: &[ParserRule<'i, PEx>]) -> Vec<Error<Rule>>;

    fn is_non_failing(
        expr: &PEx,
        rules: &HashMap<String, &ParserNode<'i, PEx>>,
        trace: &mut Vec<String>,
    ) -> bool;

    fn is_non_progressing(
        expr: &PEx,
        rules: &HashMap<String, &ParserNode<'i, PEx>>,
        trace: &mut Vec<String>,
    ) -> bool;

    fn validate_choices(
        rules: &[ParserRule<'i, PEx>]
    ) -> Vec<Error<Rule>>;

    fn validate_whitespace_comment(
        rules: &[ParserRule<'i, PEx>]
    ) -> Vec<Error<Rule>>;

    fn validate_left_recursion_wrapper(
        rules: &[ParserRule<'i, PEx>]
    ) -> Vec<Error<Rule>> {
        let rules = parser::to_hash_map(rules);

        let mut errors = vec![];

        for (name, node) in &rules {
            let name = name.clone();

            if let Some(error) = Self::validate_left_recursion(node, &rules, &mut vec![name]) {
                errors.push(error);
            }
        }

        errors
    }

    fn validate_left_recursion(
        node: &ParserNode<'i, PEx>,
        rules: &HashMap<String, &ParserNode<'i, PEx>>,
        trace: &mut Vec<String>,
    ) -> Option<Error<Rule>>;
}