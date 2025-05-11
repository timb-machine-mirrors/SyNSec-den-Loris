use core::marker::PhantomData;
use libafl::{
    Error,
    inputs::{Input, UsesInput},
};
use std::{
    fs,
    path::PathBuf
};

pub struct CorpusUtils<'a, I>
where
    I: Input,
{
    dirs: &'a [PathBuf],
    remaining_initial_files: Option<Vec<PathBuf>>,
    dont_reenter: Option<Vec<PathBuf>>,
    phantom: PhantomData<I>,
}

impl<'a, I> UsesInput for CorpusUtils<'a, I>
where
    I: Input,
{
    type Input = I;
}

impl<'a, I> CorpusUtils<'a, I>
where
    I: Input,
{
    #[must_use]
    pub fn new(in_dirs: &'a [PathBuf]) -> Self {
        Self {
            dirs: in_dirs,
            remaining_initial_files: None,
            dont_reenter: None,
            phantom: PhantomData,
        }
    }

    fn next_file(&mut self) -> Result<PathBuf, Error> {
        loop {
            if let Some(path) = self.remaining_initial_files.as_mut().and_then(Vec::pop) {
                let filename = path.file_name().unwrap().to_string_lossy();
                if filename.starts_with('.') {
                    continue;
                }

                let attributes = fs::metadata(&path);
                if attributes.is_err() {
                    continue
                }

                let attr = attributes.unwrap();
                if attr.is_file() && attr.len() > 0 {
                    return Ok(path);
                } else if attr.is_dir() {
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    path.read_dir()?
                        .try_for_each(|entry| {
                            entry.map(|e| files.push(e.path()))
                        })?;
                } else if attr.is_symlink() {
                    let path = fs::canonicalize(path)?;
                    let dont_reenter = self.dont_reenter.get_or_insert_with(Default::default);
                    if dont_reenter.iter().any(|p| path.starts_with(p)) {
                        continue;
                    }
                    if path.is_dir() {
                        dont_reenter.push(path.clone());
                    }
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    files.push(path);
                }
            } else {
                return Err(Error::iterator_end("No remaining files to load."))
            }
        }
    }

    fn continue_loading_next_initial_input(&mut self) -> Result<(I, PathBuf), Error> {
        match self.next_file() {
            Ok(path) => {
                println!("Loading file {:?} ...", &path);
                let input = I::from_file(&path)?;
                Ok((input, path))
            }
            Err(e) => return Err(e),
        }
    }

    pub fn load_next_input(&mut self) -> Result<(I, PathBuf), Error>{
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            if remaining.is_empty() {
                return Err(Error::iterator_end("No remaining files to load."));
            }
        } else {
            let files = self.dirs.iter().try_fold(Vec::new(), |mut res, file| {
                file.canonicalize().map(|canonicalized| {
                    res.push(canonicalized);
                    res
                })
            })?;
            self.dont_reenter = Some(files.clone());
            self.remaining_initial_files = Some(files);
        }
        self.continue_loading_next_initial_input()
    }
}
