extern crate getopts;

use std::env;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::str;

use getopts::Options;
use getopts::ParsingStyle;

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
struct Cfg { prefix: String, suffix: String, delimiter: String, free: Vec<String> }

fn read_args_cfg() -> Result<Cfg, String> {
    let mut opts = Options::new();
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    opts.reqopt("p", "prefix", "set prefix of text", "[PREFIX]");
    opts.reqopt("s", "suffix", "set suffix of text", "[SUFFIX]");
    opts.optopt("d", "delimiter", "stdout results delimiter", "[DELIMITER]");
    opts.parsing_style(ParsingStyle::StopAtFirstFree);
    opts
        .parse(&args[1..])
        .map(|m| Cfg {
            prefix: m.opt_str("prefix").unwrap(),
            suffix: m.opt_str("suffix").unwrap(),
            delimiter: m.opt_str("delimiter").unwrap_or("\n".to_string()),
            free: m.free,
        })
        .map_err(|e| format!("{}\n{}", format_usage(&program, &opts), e))
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
    match read_args_cfg() {
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

    for i in text {
        if !cfg.free.is_empty() {
            let result = run_process(&cfg.free, &i);
            match result {
                Ok(new_bytes) => {
                    write_result(&cfg, &new_bytes);
                }
                Err(msg) => eprintln!("{}", msg)
            }
        } else {
            write_result(&cfg, &i);
        }
    }
}

fn write_result(cfg: &Cfg, result: &[u8]) {
    std::io::stdout()
        .write(result)
        .expect("stdout write error");
    if !cfg.delimiter.is_empty() {
        std::io::stdout().write(cfg.delimiter.as_bytes())
            .expect("stdout write error");
    };
}

fn run_process(args: &[String], stdin_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(args.first().expect("arguments empty"))
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    {
        let stdin = child.stdin.as_mut();
        stdin.unwrap().write_all(stdin_bytes).map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(output.stdout)
}

#[derive(Debug)]
struct SequenceFinder {
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
