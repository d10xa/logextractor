extern crate getopts;
extern crate sha1;
extern crate tempfile;

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

use getopts::Options;
use getopts::ParsingStyle;
use regex::Captures;
use regex::Regex;

#[derive(Debug)]
pub struct InnerTextIter<T: Read> {
    source: T,
    fixed_buffer: Vec<u8>,
    last_read_size: usize,
    reads_count: usize,
    prefix_finder: SequenceFinder,
    suffix_finder: SequenceFinder,
    read_index: usize,
}

#[derive(Hash, Eq, PartialEq)]
pub struct ShaString(String);

impl<R: Read> InnerTextIter<R> {
    pub fn new(source: R, prefix: Vec<u8>, suffix: Vec<u8>) -> InnerTextIter<R> {
        InnerTextIter {
            source,
            fixed_buffer: vec![0; 1024 * 256],
            last_read_size: 0,
            reads_count: 0,
            prefix_finder: SequenceFinder::new(prefix),
            suffix_finder: SequenceFinder::new(suffix),
            read_index: 0,
        }
    }
}

impl<I> Iterator for InnerTextIter<I> where I: Read {
    type Item = Vec<u8>;
    #[inline]
    fn next(&mut self) -> Option<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut is_prefix_found = false;
        loop {
            if self.last_read_size == 0 && self.reads_count != 0 {
                return None;
            } else {
                if self.read_index == 0 {
                    self.last_read_size = self.source.read(&mut self.fixed_buffer).unwrap();
                    self.reads_count += 1;
                }
                for b in self.fixed_buffer[self.read_index..self.last_read_size].iter() {
                    self.read_index += 1;
                    if !is_prefix_found && self.prefix_finder.push(b) {
                        is_prefix_found = true;
                    } else if is_prefix_found && self.suffix_finder.push(b) {
                        buffer.drain(
                            buffer.len() - (self.suffix_finder.seq.len() - 1)..buffer.len()
                        );
                        return Some(buffer);
                    } else if is_prefix_found {
                        buffer.push(*b);
                    }
                    // else skip byte
                }
                self.read_index = 0;
            }
        }
    }
}

#[test]
fn inner_text_iterator_test() {
    let text = InnerTextIter {
        source: "123>>hello<<456>>world<<789>><<".as_bytes(),
        fixed_buffer: vec![0; 3],
        last_read_size: 0,
        reads_count: 0,
        prefix_finder: SequenceFinder::new(Vec::from(">>".as_bytes())),
        suffix_finder: SequenceFinder::new(Vec::from("<<".as_bytes())),
        read_index: 0,
    };
    let strings: Vec<Vec<u8>> = text.collect();
    assert_eq!(strings, vec![b"hello".to_vec(), b"world".to_vec(), b"".to_vec()])
}

#[derive(Debug)]
struct Cfg {
    prefix: String,
    suffix: String,
    delimiter: String,
    free: Vec<String>,
    output_dir: Option<String>,
    enumerate_files: bool,
    unique: bool,
}

fn read_args_cfg(args: &Vec<String>) -> Result<Cfg, String> {
    let mut opts = Options::new();
    let program = args[0].clone();
    opts.reqopt("p", "prefix", "set prefix of text", "[PREFIX]");
    opts.reqopt("s", "suffix", "set suffix of text", "[SUFFIX]");
    opts.optopt("d", "delimiter", "stdout results delimiter", "[DELIMITER]");
    opts.optopt("o", "output-dir", "save results to files", "[PATH]");
    opts.optflag("e", "enumerate-files", "enumerate output files");
    opts.optflag("u", "unique", "do not make duplicates");
    opts.parsing_style(ParsingStyle::StopAtFirstFree);
    opts
        .parse(&args[1..])
        .map(|m| Cfg {
            prefix: m.opt_str("prefix").unwrap(),
            suffix: m.opt_str("suffix").unwrap(),
            delimiter: m.opt_str("delimiter").unwrap_or("\n".to_string()),
            free: m.free.clone(),
            output_dir: m.opt_str("output-dir"),
            enumerate_files: m.opt_present("enumerate-files"),
            unique: m.opt_present("unique"),
        })
        .map_err(|e| format!("{}\n{}", format_usage(&program, &opts), e))
}

#[test]
fn test_read_args_cfg() {
    let args =
        vec!["app", "-p", "<", "-s", ">", "-d", ",", "-o", ".", "-e", "-u"]
            .iter().map(|s| s.to_string()).collect();
    let cfg = read_args_cfg(&args).unwrap();
    assert_eq!("<", cfg.prefix);
    assert_eq!(">", cfg.suffix);
    assert_eq!(",", cfg.delimiter);
    assert_eq!(".", cfg.output_dir.unwrap());
    assert_eq!(true, cfg.enumerate_files);
    assert_eq!(true, cfg.unique);
}

#[test]
fn test_read_args_cfg_defaults() {
    let args =
        vec!["app", "-p", "<", "-s", ">"]
            .iter().map(|s| s.to_string()).collect();
    let cfg = read_args_cfg(&args).unwrap();
    assert_eq!("\n", cfg.delimiter);
    assert_eq!(None, cfg.output_dir);
    assert_eq!(false, cfg.enumerate_files);
    assert_eq!(false, cfg.unique);
}

fn format_usage(program: &str, opts: &Options) -> String {
    let brief =
        format!("\
        Usage:\n    \
        {program} -p <PREFIX> -s <SUFFIX> [-d DELIMITER] [COMMAND]\n\n\
        Examples:\n    \
        echo 'text #>hello<# text #>world<#' | {program} --prefix '#>' --suffix '<#'\n    \
        echo '<(aGVsbG8K)><(d29ybGQK)>' | {program} -p '<(' -s ')>' -d ''  base64 --decode\
        ", program = program);
    opts.usage(&brief)
}

fn main() {
    match read_args_cfg(&env::args().collect()) {
        Ok(cfg) => {
            run(cfg);
        }
        Err(msg) => {
            eprintln!("{}", msg);
        }
    }
}

fn run(cfg: Cfg) {
    let text =
        InnerTextIter::new(
            std::io::stdin(),
            cfg.prefix.as_bytes().to_vec(),
            cfg.suffix.as_bytes().to_vec(),
        );

    let option_filenames = match &cfg.output_dir {
        Some(dir) => {
            read_filenames(Path::new(&dir)).ok()
        }
        None => {
            None
        }
    };

    let mut counter: u64 = match (cfg.enumerate_files, &option_filenames) {
        (true, Some(filenames)) => {
            let max = extract_max_index_number(&filenames);
            max + 1
        }
        _ => 1
    };

    let mut hashes = match option_filenames {
        Some(filenames) => {
            extract_sha1_from_file_names(&filenames)
        }
        None => {
            HashSet::new()
        }
    };

    for i in text {
        let bytes_to_write: Result<Vec<u8>, String> = if !cfg.free.is_empty() {
            let result = run_process(&cfg.free, &i);
            result
        } else {
            Ok(i)
        };
        match bytes_to_write {
            Ok(b) => {
                let sha = ShaString(sha1str(&b));
                let unique_pass = !cfg.unique || !hashes.contains(&sha);
                if unique_pass {
                    write_result(&cfg, &b, &sha, &counter);
                    counter += 1;
                }
                if cfg.unique {
                    hashes.insert(sha);
                }
            }
            Err(msg) => {
                eprintln!("{}", msg)
            }
        }
    }
}

fn write_result(cfg: &Cfg, result: &[u8], sha: &ShaString, counter: &u64) {
    match &cfg.output_dir {
        Some(dir) => {
            let filename = match cfg.enumerate_files {
                true => {
                    format!("{}_{}", counter, sha.0)
                }
                false => {
                    format!("{}", sha.0)
                }
            };
            let file = Path::new(dir)
                .join(filename);
            File::create(file)
                .expect("error create file")
                .write_all(result)
                .expect("error write file");
        }
        None => {
            std::io::stdout()
                .write(result)
                .expect("stdout write error");
            if !cfg.delimiter.is_empty() {
                std::io::stdout().write(cfg.delimiter.as_bytes())
                    .expect("stdout write error");
            };
        }
    }
}

fn run_process(args: &[String], stdin_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut stdin_file = tempfile::tempfile().expect("tempfile()");
    stdin_file.write_all(stdin_bytes).expect("error write temp file");
    {
        use std::io::{Seek, SeekFrom};
        stdin_file.seek(SeekFrom::Start(0)).expect("error unwrap seek");
    }
    let child = Command::new(args.first().expect("arguments empty"))
        .args(&args[1..])
        .stdin(Stdio::from(stdin_file))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(output.stdout)
}

fn sha1str(s: &[u8]) -> String {
    let mut m = sha1::Sha1::new();
    m.update(s);
    m.digest().to_string()
}

fn extract_sha1_from_file_names(filenames: &Vec<String>) -> HashSet<ShaString> {
    fn extract_option_sha1(c: Captures) -> Option<String> {
        c.get(0).map(|v| v.as_str().to_string())
    }
    let re = Regex::new(r"[0-9a-f]{40}").unwrap();
    let set: HashSet<ShaString> = filenames.iter()
        .flat_map(|f| re.captures(f))
        .flat_map(extract_option_sha1)
        .map(ShaString)
        .collect();
    set
}

#[test]
fn test_extract_sha1_from_file_names() {
    let names: Vec<String> = vec![
        "42_34973274ccef6ab4dfaaf86599792fa9c3fe4689_____.txt", // valid
        "2_7448d8798a4380162d4b56f9b452e2f6f9e24e7a", // valid
        "a3db5c13ff90a36963278c6a39e4ee3c22e2a436aaaaaaaaaaaaaaaaaaaaaaaaaa", // valid
        "9c6b057a2b9d96a4067a749ee3b3b0158d390cfx", // last symbol is x
        "9c6b057a2b9d96a4067a749ee3b3b0158d390cf", // last symbol is absent
    ].iter().map(|s| s.to_string()).collect();

    let names = extract_sha1_from_file_names(&names);
    assert_eq!(3, names.len());
}

fn extract_max_index_number(filenames: &Vec<String>) -> u64 {
    filenames.iter().flat_map(|f| {
        let split: Vec<&str> = f.splitn(2, "_").collect();
        if split.len() > 0 {
            split[0].parse::<u64>().ok()
        } else { None }
    }).max().unwrap_or(0)
}

#[test]
fn test_extract_max_index_number() {
    let names: Vec<String> = vec![
        "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e_x",
        "42_34973274ccef6ab4dfaaf86599792fa9c3fe4689_____.txt",
        "2_7448d8798a4380162d4b56f9b452e2f6f9e24e7a",
    ].iter().map(|s| s.to_string()).collect();

    let max =
        extract_max_index_number(&names);
    assert_eq!(42, max);
}

fn read_filenames(p: &Path) -> io::Result<Vec<String>> {
    Ok(p.read_dir()?
        .map(|f| f.unwrap().file_name().to_string_lossy().to_string())
        .collect())
}

#[derive(Debug)]
pub struct SequenceFinder {
    seq: Vec<u8>,
    count: usize,
}

impl SequenceFinder {
    pub const fn new(seq: Vec<u8>) -> SequenceFinder {
        SequenceFinder {
            seq,
            count: 0,
        }
    }

    #[inline]
    pub fn push(&mut self, v: &u8) -> bool {
        if Some(v) == self.seq.get(self.count) {
            self.count += 1;
        } else {
            self.count = 0;
        }
        let m = self.matches();
        if m {
            self.clear();
        }
        m
    }

    #[inline]
    pub fn matches(&self) -> bool {
        self.count == self.seq.len()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

#[test]
fn sequence_finder_test() {
    let mut seq = Vec::new();
    seq.extend_from_slice("#>".as_bytes());
    let mut f = SequenceFinder::new(seq);
    let mut p = |c: u8| f.push(&c);
    assert_eq!(p(b'x'), false);
    assert_eq!(p(b'y'), false);
    assert_eq!(p(b'#'), false);
    assert_eq!(p(b'>'), true);
    assert_eq!(p(b'z'), false);
}

#[test]
fn sequence_finder_clear_test() {
    let mut seq = Vec::new();
    seq.extend_from_slice(">>".as_bytes());
    let mut f = SequenceFinder::new(seq);
    let mut p = |c: u8| f.push(&c);
    assert_eq!(p(b'>'), false);
    assert_eq!(p(b'>'), true);
    assert_eq!(p(b'>'), false);
    assert_eq!(p(b'>'), true);
}
