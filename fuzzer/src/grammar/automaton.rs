use std::{
    collections::HashSet,
    fmt::{self, Debug, Formatter}
};

pub trait State {
    /// Adds a new transition from `self` to the state at index `to`.
    /// If there is a transition to `to` does nothing.
    fn add_transition(&mut self, to: usize);

    /// Removes the transition to `to`.
    /// Returns true if there was such a transition.
    fn remove_transition(&mut self, to: usize) -> bool;

    /// Returns a ref to the slice of next states.
    fn next(&self) -> &[usize];

    /// Returns a name for the state.
    fn generate_name(&self) -> String;

    /// Adjusts all the transitions, adding `offset` to transition indices.
    fn rebase(&mut self, offset: isize);

    /// Rebases all the transitions with indices greater than `index` by `offset`.
    fn rebase_next_after(&mut self, index: usize, offset: isize);

}

/// `GrammarState` is an [`Automaton`] state
#[derive(Clone, Debug, Default)]
pub struct GrammarState<R> {
    /// The indices of possible next `GrammarState`s in the `Automaton`
    next: Vec<usize>,
    /// The grammar production rule of this state
    pub rule: R
}

impl<R> State for GrammarState<R>
where
    R: Debug,
{
    fn add_transition(&mut self, index: usize) {
        if self.next.contains(&index) {
            return;
        }
        self.next.push(index);
    }

    fn remove_transition(&mut self, to: usize) -> bool {
        let orig_len = self.next.len();
        self.next.retain(|t| *t != to);
        return orig_len != self.next.len();
    }

    fn next(&self) -> &[usize] {
        return &self.next;
    }

    fn generate_name(&self) -> String {
        format!("{:?}", &self.rule)
    }

    fn rebase(&mut self, offset: isize) {
        for i in 0..self.next.len() {
            self.next[i] = offset.checked_add(self.next[i] as isize).unwrap() as usize;
        }
    }

    fn rebase_next_after(&mut self, index: usize, offset: isize) {
        for i in 0..self.next.len() {
            if self.next[i] > index {
                self.next[i] = offset.checked_add(self.next[i] as isize).unwrap() as usize;
            }
        }
    }
}

impl<E> GrammarState<E> {
    #[must_use]
    pub fn new(expr: E) -> Self {
        Self {
            next: vec![],
            rule: expr,
        }
    }
}

/// [`Automaton`] implementation using a vector.
/// It is used to represent [`LorisGrammar`]
///
/// [`LorisGrammar`]: crate::grammar::LorisGrammar
#[derive(Clone, Debug)]
pub struct Automaton<S> {
    /// The starting state index in `states`
    init: usize,
    /// The list of indices of possible final states in `states`
    finals: Vec<usize>,
    /// The list of states
    states: Vec<S>,
}

impl<S> fmt::Display for Automaton<S>
where
    S: Clone + Default + Debug + State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut string = "digraph {\n".to_string();
        for (i, s) in self.states().iter().enumerate() {
            string += format!("{} [label={:?}]\n", i, s.generate_name()).as_str();
        }
        for (from, s) in self.states().iter().enumerate() {
            for to in s.next() {
                string += format!("{} -> {}\n", from, to).as_str();
            }
        }
        string += "}";
        write!(f, "{}", string)
    }
}

impl<S> Automaton<S>
where
    S: Clone + Default + Debug + State,
{
    /// Creates an `Automaton`. To make sure we have one and only one
    #[must_use]
    pub fn new() -> Self {
        Self {
            init: 0,
            finals: vec![0],
            states: vec![S::default()],
        }
    }

    /// The index of the init rule
    pub fn init(&self) -> usize {
        self.init
    }

    /// The ref to the slice of `states`
    pub fn states(&self) -> &[S] {
        &self.states
    }

    /// The ref to the vector of `states` (mutable)
    pub fn states_mut(&mut self) -> &mut Vec<S> {
        &mut self.states
    }

    /// Returns true if the state at `index` is a final state
    pub fn is_final(&self, index: usize) -> bool {
        self.finals.contains(&index)
    }

    /// Rebases all the states, `finals`, and the `init`, adding `offset`.
    fn rebase(&mut self, offset: isize) {
        self.init = offset.checked_add(self.init as isize).unwrap() as usize;
        self.states.iter_mut().for_each(|s| s.rebase(offset));
        for i in 0..self.finals.len() {
            self.finals[i] = offset.checked_add(self.finals[i] as isize).unwrap() as usize;
        }
    }

    /// Same as `rebase` for indices greater than `index` by `offset`.
    fn rebase_after(&mut self, index: usize, offset: isize) {
        self.states.iter_mut().for_each(|s| s.rebase_next_after(index, offset));
        for i in 0..self.finals.len() {
            if self.finals[i] > index {
                self.finals[i] = offset.checked_add(self.finals[i] as isize).unwrap() as usize;
            }
        }
    }

    /// Adds a rule to the `Automaton` with a transition from each of the current `finals` to this
    /// rule and redefines the `finals` to this rule
    pub fn add_rule(&mut self, rule: S) {
        assert_eq!(rule.next().len(), 0);

        let index = self.states.len();
        for fi in self.finals.iter() {
            self.states[*fi].add_transition(index);
        }
        self.finals = vec![index];
        self.states.push(rule);
    }

    /// Adds a list of rules as a choice list with a transition from each of the current `finals` to
    /// each of these rules and redefines the `finals` to these rules
    pub fn add_choices(&mut self, rules: Vec<S>) {
        let index = self.states.len();
        for fi in self.finals.iter() {
            for ri in 0..rules.len() {
                assert_eq!(rules[ri].next().len(), 0);
                self.states[*fi].add_transition(index + ri);
            }
        }
        self.finals = (index..index+rules.len()).collect();
        self.states.extend(rules);
    }

    /// Adds an optional rule with a transition from each of the current `finals` to this rule and
    /// updates the `finals` with this rule (keeping the current `finals`)
    pub fn add_optional_rule(&mut self, rule: S) {
        assert_eq!(rule.next().len(), 0);

        let index = self.states.len();
        for fi in self.finals.iter() {
            self.states[*fi].add_transition(index);
        }
        self.finals.push(index);
        self.states.push(rule);
    }

    /// Insert `pda` at index, removing the state at `index`.
    pub fn insert_pda(&mut self, mut pda: Self, index: usize) {
        // The offset is the number of new states we insert minus one because we remove the state at
        // index.
        let offset = (pda.states.len() - 1) as isize;

        // Rebase each state after index by offset
        self.states.iter_mut().for_each(|s| s.rebase_next_after(index, offset));

        // Split the states to [left, old_state, right]. old_state will be replaced by the pda.
        let (left, right) = self.states.split_at_mut(index);
        let (old_state, right) = right.split_at_mut(1);

        // Rebase the pda to the index it will be inserted
        pda.rebase(index as isize);

        // Add a transition from each final state of the pda to nexts of old_state
        let mut new_finals = pda.finals.clone();
        for f in new_finals {
            for next in old_state[0].next() {
                pda.states[f-index].add_transition(*next);
            }
        }

        // Concat the states of the new automaton
        self.states = [left, pda.states(), right].concat();

        // Rebase final indices. If old_state is a final, remove it from finals.
        let mut final_at_index = false;
        let mut to_remove = 0;
        for i in 0..self.finals.len() {
            if self.finals[i] > index {
                self.finals[i] = offset.checked_add(self.finals[i] as isize).unwrap() as usize;
            }
            if self.finals[i] == index {
                final_at_index = true;
                to_remove = i;
            }
        }
        if final_at_index {
            self.finals.remove(to_remove);
            self.finals.append(&mut pda.finals);
        }
    }

    /// Removes and returns the state at `index`. If `index` is `init`, does nothing and returns
    /// None
    pub fn remove(&mut self, index: usize) -> Option<S> {
        // Do not remove the init state
        if index == self.init {
            return None
        }
        // Remove the index from finals remember it.
        let is_final = self.finals.contains(&index);
        self.finals.retain(|f| *f != index);

        // Shift all the state back by 1
        self.rebase_after(index, -1);

        // Add a transition from all the states with a transition to the removed states to its nexts
        // If removed is a final, add all the states with a transitions to the removed to finals.
        let removed = self.states.remove(index);
        let next = removed.next();
        let mut finals: HashSet<usize> = HashSet::from_iter(self.finals.clone().into_iter());
        for (i, s) in self.states_mut().iter_mut().enumerate() {
            if s.remove_transition(index) {
                for to in next {
                    s.add_transition(*to);
                }
                if is_final {
                    finals.insert(i);
                }
            }
        }
        self.finals = finals.into_iter().collect();

        Some(removed)
    }
}

#[cfg(test)]
mod tests {
    use crate::grammar::automaton::{Automaton, GrammarState};

    #[test]
    fn it_works() {
        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("start".to_string()));
        pda.add_choices(
            vec![GrammarState::new("ch1".to_string()), GrammarState::new("ch2".to_string()),
                 GrammarState::new("ch3".to_string())]);
        pda.add_rule(GrammarState::new("combine".to_string()));
        pda.add_choices(
            vec![GrammarState::new("ch4".to_string()), GrammarState::new("ch5".to_string()),
                 GrammarState::new("ch6".to_string())]);
        pda.add_optional_rule(GrammarState::new("opt".to_string()));
        panic!("{:?}", pda);
    }

    #[test]
    fn test_insert_pda() {
        let mut start_pda = Automaton::<GrammarState<String>>::new();
        start_pda.add_rule(GrammarState::new("start".to_string()));

        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("message".to_string()));
        start_pda.insert_pda(pda, 1);

        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("emmMessage".to_string()));
        start_pda.insert_pda(pda, 2);

        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("securityModeCommandHdr".to_string()));
        pda.add_rule(GrammarState::new("nasSecAlgo_T3V".to_string()));
        start_pda.insert_pda(pda, 3);

        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("emmHdr".to_string()));
        pda.add_rule(GrammarState::new("Str(93)".to_string()));
        start_pda.insert_pda(pda, 4);

        panic!("{:?}", start_pda);

    }

    #[test]
    fn test_remove() {
        let mut pda = Automaton::<GrammarState<String>>::new();
        pda.add_rule(GrammarState::new("start".to_string()));
        pda.add_rule(GrammarState::new("r1".to_string()));
        let mut new_pda = Automaton::<GrammarState<String>>::new();
        new_pda.add_optional_rule(GrammarState::new("r1".to_string()));
        pda.insert_pda(new_pda, 2);
        let mut new_pda = Automaton::<GrammarState<String>>::new();
        new_pda.add_choices(
            vec![GrammarState::new("ch1".to_string()), GrammarState::new("ch2".to_string())]);
        pda.insert_pda(new_pda, 3);
        println!("{:?}", pda);
        pda.remove(2);
        panic!("{:?}", pda);
    }
}
