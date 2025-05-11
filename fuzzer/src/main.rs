extern crate pest;
#[macro_use]
extern crate pest_derive;

mod corpus;
mod feedback;
mod generator;
mod grammar;
mod input;
mod observer;
mod state;
mod stateful;

use clap::{self, arg, ArgAction, Command, value_parser};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    Evaluator,
    events::SimpleEventManager,
    executors::{
        Executor, ExitKind,
        forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
        HasObservers,
    },
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    feedback_and_fast, feedback_or,
    fuzzer::{Fuzzer, StdFuzzer},
    generators::Generator,
    inputs::{BytesInput, Input, HasTargetBytes, UsesInput},
    monitors::{OnDiskTOMLMonitor, SimpleMonitor},
    mutators::{
        grimoire::{GrimoireExtensionMutator, GrimoireRandomDeleteMutator,
                   GrimoireRecursiveReplacementMutator, GrimoireStringReplacementMutator},
        havoc_mutations, Mutator, StdScheduledMutator
    },
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        generalization::GeneralizationStage,
        logics::IfStage,
        mutational::{MutatedTransform, MutatedTransformPost, StdMutationalStage},
    },
    state::{HasCorpus, HasRand, StdState, UsesState},
};
use libafl_bolts::{
    AsMutSlice, current_nanos, Error,
    rands::{Rand, StdRand},
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::tuple_list
};
use nix::sys::signal::Signal;
use std::{
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use crate::corpus::utils::CorpusUtils;
use crate::feedback::MismatchFeedback;
use crate::generator::{
    mutator::{GrammarRandomMutatorLast, LorisHavocMutator, LorisSpliceMutator},
    LorisGenerator,
    transition::TransitionGenerator,
    utils::toss_biased_coin,
};
use crate::grammar::{
    fast2::LorisFastGrammar2,
    LorisGrammar
};
use crate::input::{
    state::{StateDescList},
    LorisInput,
};
use crate::observer::{
    shmem::ShMemInfo,
    variable::VariableObserver,
};
use crate::state::NopState;

const COV_MAP_SIZE: usize = 8 * 1024 * 1024;

fn get_args() -> clap::ArgMatches {
    let mut cmd = Command::new("Loris")
        .about("Shannon Fuzzer")
        .subcommand_required(true)
        .args_conflicts_with_subcommands(true)
        .subcommand(
            Command::new("fuzz")
                .about("Start fuzzing with FirmWire")
                .arg(arg!(--grammar <PATH> "Grammar file path")
                    .required_unless_present_any(["afl", "grimoire", "no-grammar"]))
                .arg(arg!(--"start-symbol" <SYMBOL>)
                    .default_value("start")
                )
                .arg(arg!(--afl "Use AFL++ components"))
                .arg(arg!(--grimoire "Use Grimoire mutations"))
                .arg(arg!(--"no-grammar" "Do not use Loris grammar"))
                .arg(arg!(-i --"corpus-dir" <PATH> "Input directory with test cases (or '-' to resume)"))
                .arg(arg!(-o --"output-dir" <PATH> "Output directory for fuzzer findings"))
                .arg(arg!(-m <M> "Generate each seed M times and evaluate (0: generage once and add)")
                    .value_parser(value_parser!(usize))
                    .default_value("0")
                )
                .arg(arg!(--single "fuzz for a single iteration")
                    .action(ArgAction::SetTrue)
                )
                .arg(arg!(--reload "load and evaluate an existing corpus")
                    .action(ArgAction::SetTrue)
                )
                .arg(arg!(--"debug-child" "If not set, the child's stdout and stderr will be redirected to /dev/null")
                    .action(ArgAction::SetTrue)
                )
                .arg(arg!(<arguments> ... "arguments to executable (pass after --)" )
                    .trailing_var_arg(true)
                    .required(false)
                )
        )
        .subcommand(
            Command::new("fuzz-triage")
                .about("Invoke the fuzzer, but without an AFL front end. Enables debug hooks and saves code coverage")
                .arg(arg!(-i --"corpus-dir" <PATH> "Input directory with test cases"))
                .arg(arg!(--"debug-child" "If not set, the child's stdout and stderr will be redirected to /dev/null")
                    .action(ArgAction::SetTrue)
                )
                .arg(arg!(<arguments> ... "arguments to executable (pass after --)" )
                    .trailing_var_arg(true)
                    .required(false)
                )
        )
        .subcommand(
            Command::new("example")
                .about("Generate examples from grammar")
                .arg(arg!(--grammar <PATH> "Grammar file path")
                    .required(true)
                )
                .arg(arg!(--"start-symbol" <SYMBOL>)
                    .default_value("start")
                )
                .arg(arg!(-f --format <F> "Output format (0: binary, 1: JSON, 2: Pretty JSON)")
                    .value_parser(value_parser!(u32))
                    .default_value("0")
                )
                .arg(arg!(--debug "Print debugging information").action(ArgAction::SetTrue))
                .arg(arg!(-n <N> "Generate N examples and exit")
                    .value_parser(value_parser!(usize))
                    .default_value("1")
                )
                .arg(arg!(-m <M> "Mutate each example M times")
                    .value_parser(value_parser!(usize))
                    .default_value("0")
                )
        )
        .subcommand(
            Command::new("test")
                .about("Test single transitions from `baseband-analyzer`")
                .arg(arg!(-i --"corpus-dir" <PATH> "Input directory with test cases"))
                .arg(arg!(-o --"output-dir" "Output directory for fuzzer findings"))
                .arg(arg!(--"debug-child" "If not set, the child's stdout and stderr will be redirected to /dev/null")
                    .action(ArgAction::SetTrue)
                )
                .arg(arg!(<arguments> ... "arguments to executable (pass after --)" )
                    .trailing_var_arg(true)
                    .required(false)
                )
        );
    let matches = cmd.get_matches_mut();

    matches
}

fn setup_dirs<P>(in_dir: P, out_dir: P) -> (PathBuf, PathBuf)
where
    P: Into<PathBuf>,
{
    let o: PathBuf = out_dir.into();
    if o.exists() {
        let stats = o.join("fuzzer_stats.toml");
        if stats.exists() {
            panic!(
                "The job output directory already exists. To resume an old session, pass \
                '--reload' and use a new output directory with existing corpus as input \
                directory. Otherwise, use an empty output directory."
            )
        }
    }
    (in_dir.into(), o)
}

fn print_example(path: &str, start: &str, format: u32, _n: usize, mutate: usize, debug: bool) {
    let path = Path::new(path);
    let start = start.to_string();
    let mut state: NopState<LorisInput> = NopState::new();

    let mut grammar = LorisFastGrammar2::from_file(path, start.clone())
        .expect("failed to load grammar");
    grammar.optimize();
    // println!("{:?}", grammar);
    let mut generator = LorisGenerator::from(&grammar);
    let generator_copy = LorisGenerator::from(&grammar);
    let mut mutator = GrammarRandomMutatorLast::new(&generator_copy);
    let mut input: LorisInput = generator.generate(&mut state)
        .expect("cannot generate example");
    // println!("{:?}", input.to_vec());

    if mutate > 0 {
        for _ in 0..mutate {
            let res = mutator.try_mutate(&mut state, &mut input);
            if debug { println!("{res:?}"); }
        }
    }

    match format {
        0 => {
            let mut out = std::io::stdout();
            let bytes = input.to_vec();
            out.write_all(bytes.as_slice()).unwrap();
        },
        1 => {
            let s = serde_json::to_string(&input).unwrap();
            println!("{s}");
        },
        2 => {
            let s = serde_json::to_string_pretty(&input).unwrap();
            println!("{s}");
        },
        f => {
            println!("{f}: invalid format")
        }
    }
}

fn fuzz_ex(path: &str, start: &str, arguments: Vec<&String>, debug_child: bool, one: bool) {
    let path = Path::new(path);
    let start = start.to_string();
    let grammar = LorisFastGrammar2::from_file(path, start).expect("failed to load grammar");
    let mut generator = LorisGenerator::from(&grammar);

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
    let mut cov_shmem = shmem_provider.new_shmem(cov_shmem_info.size).unwrap();
    cov_shmem.write_to_env(cov_shmem_info.env_name.as_str()).unwrap();
    let cov_map = cov_shmem.as_mut_slice();

    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );

    let mut objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
        .unwrap();

    // the Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    // let ui = TuiUI::new("Loris 0.1".to_string(), true);
    // let monitor = TuiMonitor::new(ui);

    // the event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // a queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // a fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // create the executor for the forkserver
    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(1000),
        Signal::SIGKILL,
    )
        .expect("Failed to create the executor");

    state
        .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 1)
        .expect("failed to generate the initial corpus");

    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrammarRandomMutatorLast::new(&generator),
        ), 1
    );
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    if one {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    } else {
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    }
}

fn fuzz(
    path: &str,
    start: &str,
    arguments: Vec<&String>,
    corpus_dir: PathBuf,
    output_dir: PathBuf,
    gens: usize,
    reload: bool,
    debug_child: bool,
    one: bool)
{
    let path = Path::new(path);
    let start = start.to_string();
    let mut grammar = LorisFastGrammar2::from_file(path, start)
        .expect("failed to load grammar");
    grammar.optimize();
    let loris_generator = LorisGenerator::from(&grammar);
    let generator = TransitionGenerator::new(&loris_generator);

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    // let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
    let mut cov_shmem = shmem_provider.new_shmem(COV_MAP_SIZE).unwrap();
    cov_shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let cov_map = cov_shmem.as_mut_slice();

    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

    let time_observer = TimeObserver::new("time");

    let var_observer = VariableObserver::<UnixShMemProvider, StateDescList>::builder()
        .shmem_provider(&mut shmem_provider)
        .build::<StateDescList>("var_observer")
        .unwrap();

    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer),
        MismatchFeedback::new(&var_observer)
    );

    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );


    let monitor = OnDiskTOMLMonitor::new(
        output_dir.join("fuzzer_stats.toml"),
        SimpleMonitor::new(|s| println!("{s}"))
    );

    let mut mgr = SimpleEventManager::new(monitor);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        OnDiskCorpus::new(output_dir.join("corpus")).unwrap(),
        OnDiskCorpus::new(output_dir.join("crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
        .unwrap();

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(time_observer, edges_observer, var_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(1000),
        Signal::SIGKILL,
    )
        .expect("Failed to create the executor");

    // Load initial inputs
    let in_dirs = [corpus_dir];
    let mut corpus_utils = CorpusUtils::new(&in_dirs);
    loop {
        match corpus_utils.load_next_input() {
            Ok((mut input, _)) => {
                if reload {
                    let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, input);
                } else {
                    if gens == 0 {
                        generator.generate_continue(&mut input, &mut state);
                        let _ = fuzzer.add_input(&mut state, &mut executor, &mut mgr, input);
                    } else {
                        for _ in 0..gens {
                            let mut input_clone = input.clone();
                            generator.generate_continue(&mut input_clone, &mut state);
                            let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, input_clone);
                        }
                    }
                }
            },
            Err(Error::IteratorEnd(_, _)) => break,
            Err(e) => {
                println!("{e:?}");
                break;
            },
        }
    }

    let havoc_mutation_stage = IfStage::new(toss_biased_coin(33), tuple_list!(
        StdMutationalStage::with_max_iterations(LorisHavocMutator::new(), 2),
    ));

    let grammar_mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrammarRandomMutatorLast::new(&loris_generator),
            LorisSpliceMutator::new()
        ), 1);

    let mut stages = tuple_list!(
        StdMutationalStage::new(grammar_mutator),
        havoc_mutation_stage,
    );

    if one {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    } else {
        loop {
            if let Err(e) = fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr) {
                println!("error in the fuzzing loop: {e:?}");
            }
            thread::sleep(Duration::from_millis(1000));
        }
    }
}

fn fuzz_no_grammar(
    arguments: Vec<&String>,
    corpus_dir: PathBuf,
    output_dir: PathBuf,
    debug_child: bool,
    one: bool)
{
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
    let mut cov_shmem = shmem_provider.new_shmem(cov_shmem_info.size).unwrap();
    cov_shmem.write_to_env(cov_shmem_info.env_name.as_str()).unwrap();
    let cov_map = cov_shmem.as_mut_slice();

    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

    let time_observer = TimeObserver::new("time");

    let var_observer = VariableObserver::<UnixShMemProvider, StateDescList>::builder()
        .shmem_provider(&mut shmem_provider)
        .build::<StateDescList>("var_observer")
        .unwrap();

    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer),
        MismatchFeedback::new(&var_observer)
    );

    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    let monitor = OnDiskTOMLMonitor::new(
        output_dir.join("fuzzer_stats.toml"),
        SimpleMonitor::new(|s| println!("{s}"))
    );

    let mut mgr = SimpleEventManager::new(monitor);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        OnDiskCorpus::new(output_dir.join("corpus")).unwrap(),
        OnDiskCorpus::new(output_dir.join("crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
        .unwrap();

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(time_observer, edges_observer, var_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(1000),
        Signal::SIGKILL,
    )
        .expect("Failed to create the executor");

    // Load initial inputs
    let in_dirs = [corpus_dir];
    let mut corpus_utils = CorpusUtils::new(&in_dirs);
    loop {
        match corpus_utils.load_next_input() {
            Ok((input, _)) => {
                let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, input);
            },
            Err(Error::IteratorEnd(_, _)) => break,
            Err(e) => {
                println!("{e:?}");
                break;
            },
        }
    }

    let havoc_mutation_stage = StdMutationalStage::with_max_iterations(LorisHavocMutator::new(), 2);

    let mut stages = tuple_list!(havoc_mutation_stage);

    if one {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    } else {
        loop {
            if let Err(e) = fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr) {
                println!("error in the fuzzing loop: {e:?}");
            }
            thread::sleep(Duration::from_millis(1000));
        }
    }
}

fn fuzz_grimoire(arguments: Vec<&String>, corpus_dir: PathBuf, output_dir: PathBuf, debug_child: bool) {
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
    let mut cov_shmem = shmem_provider.new_shmem(cov_shmem_info.size).unwrap();
    cov_shmem.write_to_env(cov_shmem_info.env_name.as_str()).unwrap();
    let cov_map = cov_shmem.as_mut_slice();

    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, false, true),
        TimeFeedback::with_observer(&time_observer)
    );

    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    let monitor = OnDiskTOMLMonitor::new(
        output_dir.join("fuzzer_stats.toml"),
        SimpleMonitor::new(|s| println!("{s}"))
    );

    let mut mgr = SimpleEventManager::new(monitor);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        OnDiskCorpus::<BytesInput>::new(output_dir.join("corpus")).unwrap(),
        OnDiskCorpus::new(output_dir.join("crashes")).unwrap(),
        &mut feedback,
        &mut objective
    ).unwrap();

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let generalization = GeneralizationStage::new(&edges_observer);

    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(1000),
        Signal::SIGKILL,
    ).expect("Failed to create the executor");

    let in_dirs = [corpus_dir];
    let mut corpus_utils = CorpusUtils::new(&in_dirs);
    loop {
        match corpus_utils.load_next_input() {
            Ok((input, _)) => {
                // println!("input={input:?}");
                fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, input)
                    .expect("Failed to add input");
            },
            Err(Error::IteratorEnd(_, _)) => break,
            Err(e) => {
                println!("{e:?}");
                break;
            },
        }
    }

    let mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations(), 2);
    let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrimoireExtensionMutator::new(),
            GrimoireRecursiveReplacementMutator::new(),
            GrimoireStringReplacementMutator::new(),
            // give more probability to avoid large inputs
            GrimoireRandomDeleteMutator::new(),
            GrimoireRandomDeleteMutator::new(),
        ),
        3,
    );
    let mut stages = tuple_list!(
        generalization,
        StdMutationalStage::new(mutator),
        StdMutationalStage::transforming(grimoire_mutator),
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in the fuzzing loop");
}

fn fuzz_aflpp(arguments: Vec<&String>, corpus_dir: PathBuf, output_dir: PathBuf, debug_child: bool,
              one: bool) {
    // The unix shmem provider supported by AFL++ for shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
    // The coverage map shared between observer and executor
    let mut cov_shmem = shmem_provider.new_shmem(cov_shmem_info.size).unwrap();
    cov_shmem.write_to_env(cov_shmem_info.env_name.as_str()).unwrap();
    let cov_map = cov_shmem.as_mut_slice();

    // Create an observation channel using the signals map
    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let mut objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = OnDiskTOMLMonitor::new(
        output_dir.join("fuzzer_stats.toml"),
        SimpleMonitor::new(|s| println!("{s}"))
    );

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        OnDiskCorpus::<BytesInput>::new(output_dir.join("corpus")).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(output_dir.join("crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective
    ).unwrap();

    // A minimization+queue policy to get testcases from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(20000),
        Signal::SIGKILL,
    ).expect("Failed to create the executor");

    // Load the initial inputs from disk
    let in_dirs = [corpus_dir];
    let mut corpus_utils = CorpusUtils::new(&in_dirs);
    loop {
        match corpus_utils.load_next_input() {
            Ok((input, _)) => {
                fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, input)
                    .expect("Failed to add input");
            },
            Err(Error::IteratorEnd(_, _)) => break,
            Err(e) => {
                println!("{e:?}");
                break;
            },
        }
    }

    // Set up a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations(), 6);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    if one {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    } else {
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("error in the fuzzing loop");
    }
}

fn fuzz_triage(
    arguments: Vec<&String>,
    corpus_dir: PathBuf,
    debug_child: bool)
{
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    let in_idx = arguments.iter().position(|&arg| arg == "@@").unwrap();

    let in_dirs = [corpus_dir];
    let mut corpus_utils = CorpusUtils::new(&in_dirs);

    loop {
        let cov_shmem_info = ShMemInfo::new("__AFL_SHM_ID", COV_MAP_SIZE);
        let mut cov_shmem = shmem_provider.new_shmem(cov_shmem_info.size).unwrap();
        cov_shmem.write_to_env(cov_shmem_info.env_name.as_str()).unwrap();
        let cov_map = cov_shmem.as_mut_slice();

        let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("cov_shmem", cov_map)) };

        let time_observer = TimeObserver::new("time");

        let var_observer = VariableObserver::<UnixShMemProvider, StateDescList>::builder()
            .shmem_provider(&mut shmem_provider)
            .build::<StateDescList>("var_observer")
            .unwrap();

        let mut feedback = feedback_or!(
            MaxMapFeedback::tracking(&edges_observer, true, false),
            TimeFeedback::with_observer(&time_observer),
            MismatchFeedback::new(&var_observer)
        );

        let mut objective = feedback_and_fast!(
            CrashFeedback::new(),
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
        );

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
            .unwrap();

        let monitor = SimpleMonitor::new(|s| println!("{s}"));

        let mut mgr = SimpleEventManager::new(monitor);

        let scheduler = QueueScheduler::new();

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        match corpus_utils.load_next_input() {
            Ok((input, path)) => {
                let mut args = arguments.clone();
                let path_string = path.into_os_string().into_string().unwrap();
                args[in_idx] = &path_string;
                let forkserver = ForkserverExecutor::builder()
                    .debug_child(debug_child)
                    .shmem_provider(&mut shmem_provider)
                    .parse_afl_cmdline(args)
                    .build(tuple_list!(time_observer.clone(), edges_observer.clone(), var_observer.clone()))
                    .unwrap();
                let mut executor = TimeoutForkserverExecutor::with_signal(
                    forkserver,
                    Duration::from_millis(3000),
                    Signal::SIGKILL,
                )
                    .expect("Failed to create the executor");
                let exit_kind = fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &input)
                    .expect("Failed to execute input");
                if exit_kind == ExitKind::Timeout {
                    println!("ExitKind={exit_kind:?}");
                }
            },
            Err(Error::IteratorEnd(_, _)) => break,
            Err(e) => {
                println!("{e:?}");
                break;
            },
        }
    };
}

fn test(corpus_dir: PathBuf, output_dir: PathBuf, arguments: Vec<&String>, debug_child: bool) {
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let var_observer = VariableObserver::<UnixShMemProvider, StateDescList>::builder()
        .shmem_provider(&mut shmem_provider)
        .build::<StateDescList>("var_observer")
        .unwrap();

    let mut feedback = MismatchFeedback::new(&var_observer);
    let mut objective = MismatchFeedback::new(&var_observer);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(output_dir.join("mismatches")).unwrap(),
        &mut feedback,
        &mut objective,
    )
        .unwrap();

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let forkserver = ForkserverExecutor::builder()
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .build(tuple_list!(var_observer))
        .unwrap();
    let mut executor = TimeoutForkserverExecutor::with_signal(
        forkserver,
        Duration::from_millis(1000),
        Signal::SIGKILL,
    )
        .expect("failed to create the executor");

    let corpus_dirs = [corpus_dir];
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
        .unwrap_or_else(|err| {
            panic!(
                "Failed to load initial corpus at {:?}: {:?}",
                &corpus_dirs, err
            )
        });
}

fn main() {
    let args = get_args();

    if let Some(sub_args) = args.subcommand_matches("example") {
        let path = sub_args.get_one::<String>("grammar").unwrap();
        let start = sub_args.get_one::<String>("start-symbol").unwrap();
        let n = sub_args.get_one::<usize>("N").unwrap();
        let m = sub_args.get_one::<usize>("M").unwrap();
        let debug = sub_args.get_flag("debug");
        let format = sub_args.get_one::<u32>("format").unwrap();
        print_example(path, start, *format, *n, *m, debug);
    } else if let Some(sub_args) = args.subcommand_matches("fuzz") {
        let start = sub_args.get_one::<String>("start-symbol").unwrap();
        let afl = sub_args.get_flag("afl");
        let grimoire = sub_args.get_flag("grimoire");
        let no_grammar = sub_args.get_flag("no-grammar");
        let debug_child = sub_args.get_flag("debug-child");
        let arguments = sub_args.get_many::<String>("arguments").unwrap().collect::<Vec<_>>();
        let corpus_dir = sub_args.get_one::<String>("corpus-dir").unwrap();
        let output_dir = sub_args.get_one::<String>("output-dir").unwrap();
        let (in_dir, out_dir) = setup_dirs(corpus_dir, output_dir);
        let gens = sub_args.get_one::<usize>("M").unwrap();
        let one = sub_args.get_flag("single");
        let reload = sub_args.get_flag("reload");
        if afl {
            fuzz_aflpp(arguments, in_dir, out_dir, debug_child, one);
        } else if grimoire {
            fuzz_grimoire(arguments, in_dir, out_dir, debug_child);
        } else if no_grammar {
            fuzz_no_grammar(arguments, in_dir, out_dir, debug_child, one);
        } else {
            let grammar_path = sub_args.get_one::<String>("grammar").unwrap();
            fuzz(grammar_path, start, arguments, in_dir, out_dir, 
                 *gens, reload, debug_child, one);
        }
    } else if let Some(sub_args) = args.subcommand_matches("fuzz-triage") {
        let corpus_dir = sub_args.get_one::<String>("corpus-dir").unwrap();
        let debug_child = sub_args.get_flag("debug-child");
        let corpus_dir = PathBuf::from(corpus_dir);
        let arguments = sub_args.get_many::<String>("arguments").unwrap().collect::<Vec<_>>();
        fuzz_triage(arguments, corpus_dir, debug_child);
    } else if let Some(sub_args) = args.subcommand_matches("test") {
        let corpus_dir = sub_args.get_one::<String>("corpus-dir").unwrap();
        let corpus_dir = PathBuf::from(corpus_dir);
        let output_dir = sub_args.get_one::<String>("output-dir").unwrap();
        let output_dir = PathBuf::from(output_dir);
        let arguments = sub_args.get_many::<String>("arguments").unwrap().collect::<Vec<_>>();
        let debug_child = sub_args.get_flag("debug-child");
        test(corpus_dir, output_dir, arguments, debug_child);
    }
}
