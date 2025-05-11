use std::{
    collections::HashMap,
    path::Path,
};

use crate::grammar::{
    automaton::{Automaton, GrammarState},
    fast::{Expr, LorisFastGrammar},
    LorisGrammar,
    rule::AstRule,
};

type Pda = Automaton<GrammarState<AstRule<Expr>>>;

/// [`LorisFastGrammar2`] is a [`LorisGrammar`] based on [`LorisFastGrammar`] with productions rules
/// stored in automatons.
///
/// [`LorisFastGrammar`]: crate::grammar::fast::LorisFastGrammar
#[derive(Clone, Debug)]
pub struct LorisFastGrammar2 {
    pub rules: HashMap<String, Pda>,
    pub start_symbol: String,
}

impl LorisGrammar for LorisFastGrammar2 {
    type Rule = Pda;

    fn from_file(path: &Path, start: String) -> Result<Self, String> {
        let fast_grammar = LorisFastGrammar::from_file(path, start.clone()).unwrap();

        let pda_map: HashMap<String, Self::Rule> = fast_grammar.rules
            .iter()
            .map(|(name, rule)| (name.to_owned(), to_automaton(rule)))
            .collect();

        Ok(LorisFastGrammar2 {
            rules: pda_map,
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

/// Returns a PDA, adding rule
fn to_automaton(rule: &AstRule<Expr>) -> Pda {
    let mut pda = Automaton::new();
    pda.add_rule(GrammarState::new(rule.clone()));
    pda
}

impl LorisFastGrammar2 {
    /// Expands expressions as much as possible removing Idents
    fn expand_automaton_expr(&self, expr: Expr, index: usize) -> Option<Pda> {
        match expr {
            // Matches the state rule which is an Ident with the given name and
            // replaces the state with the PDA of the Ident name
            Expr::Ident(name) => {
                if let Some(new_pda) = self.get(name.as_str()) {
                    Some(new_pda.clone())
                } else {
                    None
                }
            }
            // Matches a sequences of expressions
            Expr::Seq(seq) => {
                let mut new_pda = Automaton::new();
                for expr in seq {
                    new_pda.add_rule(GrammarState::new(AstRule::from_expr(expr)));
                }
                Some(new_pda)
            }
            Expr::RightSeq(expr1, expr2) => {
                let mut new_pda = Automaton::new();
                new_pda.add_rule(GrammarState::new(AstRule::from_expr(*expr1)));
                new_pda.add_rule(GrammarState::new(AstRule::from_expr(*expr2)));
                Some(new_pda)
            }
            Expr::Choice(choices) => {
                let mut new_pda = Automaton::new();
                new_pda.add_choices(
                    choices
                        .iter()
                        .map(|expr| GrammarState::new(AstRule::from_expr(expr.clone())))
                        .collect());
                Some(new_pda)
            }
            Expr::Opt(expr) => {
                let mut new_pda = Automaton::new();
                new_pda.add_optional_rule(GrammarState::new(AstRule::from_expr(*expr)));
                Some(new_pda)
            }
            _ => None,
        }
    }

    /// Expands the `pda` once (single step) using grammar rules
    /// Returns true if expansion is successful
    pub fn expand_automaton_ss(
        &mut self, pda: &mut Pda
    ) -> bool {
        for (i, g_state) in pda.states_mut().iter().enumerate() {
            let rule = g_state.rule.clone();
            let expr = rule.expr.clone();
            let attr = rule.attribute.clone();

            // Skip the rule if it has any attributes
            if attr.is_some() {
                let mut new_pda = Automaton::new();
                new_pda.add_rule(GrammarState::new(rule));
                continue;
            }
            let new_pda = self.expand_automaton_expr(expr, i);
            if let Some(new_pda) = new_pda {
                pda.insert_pda(new_pda, i);
                return true;
            }
        }
        false
    }

    /// Run different optimizations on all the PDAs of this grammar
    pub fn optimize(&mut self) {
        let rules: Vec<String> = self.rules
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        rules
            .into_iter()
            .for_each(|name| {
                if let Some(mut pda) = self.rules.remove(name.as_str()) {
                    while self.expand_automaton_ss(&mut pda) {}
                    Self::optimize_automaton(&mut pda);
                    self.rules.insert(name, pda);
                }
            });
    }

    /// Run different optimizations on a given PDA
    pub fn optimize_automaton(pda: &mut Pda) {
        // Remove empty Str expressions
        let mut to_removed = vec![];
        for (i, r) in pda.states_mut().iter().enumerate() {
            let expr = r.rule.expr.clone();
            match expr {
                Expr::Str(string) => {
                    if string.is_empty() {
                        to_removed.push(i);
                    }
                },
                _ => {},
            }
        }
        for index in to_removed.into_iter().rev() {
            pda.remove(index);
        }
    }
}
