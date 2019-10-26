extern crate dirs;
extern crate mailparse;
extern crate regex;
extern crate toml;
#[macro_use]
extern crate serde_derive;
extern crate structopt;
#[macro_use]
extern crate log;
extern crate fs2;
extern crate simplelog;

use fs2::*;
use mailparse::*;
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use simplelog::Config as LogConfig;
use simplelog::{LevelFilter, WriteLogger};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use structopt::StructOpt;
use subprocess::ExitStatus::*;
use subprocess::{Popen, PopenConfig, Redirection};

#[derive(Deserialize, Clone, Debug)]
struct Rule {
    headers: Option<Vec<HashMap<String, String>>>,
    body: Option<Vec<Vec<String>>>,
    raw: Option<Vec<Vec<String>>>,
    action: Option<Vec<Vec<String>>>,
    filter: Option<Vec<String>>,
}

impl Display for Rule {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let headertext: Option<String> = self.headers.as_ref().map(|vec| {
            vec.iter()
                .map(|hash| {
                    format!(
                        "({})",
                        hash.iter()
                            .map(|(key, value)| format!("({}: {})", key, value))
                            .collect::<Vec<String>>()
                            .join(" AND ")
                    )
                })
                .collect::<Vec<String>>()
                .join(" OR ")
        });

        let bodytext: Option<String> = self.body.as_ref().map(|vec| {
            vec.iter()
                .map(|vec2| format!("({})", vec2.join(" AND ")))
                .collect::<Vec<String>>()
                .join(" OR ")
        });

        let rawtext: Option<String> = self.raw.as_ref().map(|vec| {
            vec.iter()
                .map(|vec2| format!("({})", vec2.join(" AND ")))
                .collect::<Vec<String>>()
                .join(" OR ")
        });

        write!(
            f,
            "headers: {}; body: {}; raw: {}",
            headertext.unwrap_or_default(),
            bodytext.unwrap_or_default(),
            rawtext.unwrap_or_default()
        )
    }
}

struct Match {
    headers: bool,
    body: bool,
    raw: bool,
}
impl Match {
    fn matched(&self) -> bool {
        (self.headers && self.body && self.raw)
    }
}

struct Job {
    subprocess: Popen,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

impl Job {
    fn run(action: &[String], input: Option<&[u8]>) -> Job {
        let mut p = Popen::create(
            action,
            PopenConfig {
                stdin: if input.is_some() {
                    Redirection::Pipe
                } else {
                    Redirection::None
                },
                stdout: Redirection::Pipe,
                stderr: Redirection::Pipe,
                ..Default::default()
            },
        )
        .expect("Could not spawn child process");

        let mut stdout = None;
        let mut stderr = None;
        if let Ok((out, err)) = p.communicate_bytes(input) {
            stdout = out;
            stderr = err;
        }
        let _ = p.wait();

        Job {
            subprocess: p,
            stdout,
            stderr,
        }
    }

    fn success(&self) -> bool {
        self.subprocess.exit_status().map_or(false, |e| e.success())
    }

    fn found(program: String) -> bool {
        let which = vec!["which".to_string(), program];
        Job::run(&which, None).success()
    }
}

#[derive(Deserialize, Clone)]
struct Config {
    version: usize,
    rules: Vec<Rule>,
}

impl Config {
    fn new() -> Config {
        let mut conf = match dirs::home_dir() {
            Some(path) => path,
            _ => PathBuf::from(""),
        };
        conf.push(".mailproc.conf");
        let mut f =
            File::open(&conf).unwrap_or_else(|_| panic!("Could not open config file {:?}.", &conf));
        let mut buf = String::new();
        f.read_to_string(&mut buf)
            .unwrap_or_else(|_| panic!("Could not read config file: {:?}", &conf));
        let config: Config = toml::from_str(&buf)
            .unwrap_or_else(|_| panic!("Could not parse config file {:?}.", &conf));
        config
    }

    fn test(&self) -> bool {
        let mut success = true;
        for rule in &self.rules {
            if let Some(actions) = &rule.action {
                for action in actions {
                    success &= if !action.is_empty() {
                        let found = Job::found(action[0].clone());
                        if !found {
                            println!("{} not found", action[0]);
                        }
                        found
                    } else {
                        println!("Empty action for rule {:?}", rule);
                        false
                    }
                }
            }

            if let Some(filter) = &rule.filter {
                success &= if !filter.is_empty() {
                    let found = Job::found(filter[0].clone());
                    if !found {
                        println!("{} not found", filter[0]);
                    }
                    found
                } else {
                    println!("Empty filter for rule {:?}", rule);
                    false
                }
            }

            if let Some(headers_vec) = &rule.headers {
                if headers_vec.is_empty() {
                    println!("Empty headers set for rule {:?}", rule);
                    success &= false;
                }
                for headers_set in headers_vec {
                    if headers_set.is_empty() {
                        println!("Empty headers set in rule {:?}", rule);
                        success &= false;
                    }
                    for v in headers_set.values() {
                        success &= match Regex::new(&v) {
                            Ok(_) => true,
                            Err(e) => {
                                println!("Could not compile regex {}: {}", v, e);
                                false
                            }
                        }
                    }
                }
            }

            if let Some(body_vec) = &rule.body {
                if body_vec.is_empty() {
                    println!("Empty body set in rule {:?}", rule);
                    success &= false;
                }
                for body_set in body_vec {
                    if body_set.is_empty() {
                        println!("Empty body set in rule {:?}", rule);
                        success &= false;
                    }
                    for r in body_set {
                        success &= match Regex::new(&r) {
                            Ok(_) => true,
                            Err(e) => {
                                println!("Could not compile regex {}: {}", r, e);
                                false
                            }
                        }
                    }
                }
            }

            if let Some(raw_vec) = &rule.raw {
                if raw_vec.is_empty() {
                    println!("Empty raw set in rule {:?}", rule);
                    success &= false;
                }
                for raw_set in raw_vec {
                    if raw_set.is_empty() {
                        println!("Empty raw set in rule {:?}", rule);
                        success &= false;
                    }
                    for r in raw_set {
                        success &= match Regex::new(&r) {
                            Ok(_) => true,
                            Err(e) => {
                                println!("Could not compile regex {}: {}", r, e);
                                false
                            }
                        }
                    }
                }
            }
        }
        success
    }
}

#[derive(StructOpt, Debug)]
#[structopt(author = "")]
struct Opt {
    /// Test configuration and exit
    #[structopt(short = "t", long = "test")]
    test: bool,
}

fn init_log() {
    let mut log = match dirs::home_dir() {
        Some(path) => path,
        _ => PathBuf::from(""),
    };
    log.push("mailproc.log");
    let logfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .expect("Could not open log file");
    logfile.lock_exclusive().expect("Could not lock log file");

    WriteLogger::init(LevelFilter::Info, LogConfig::default(), logfile)
        .expect("Could not initialize write logger");
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let opt = Opt::from_args();
    let config = Config::new();

    init_log();

    if opt.test {
        let success = config.test();
        if !success {
            println!("Config FAIL");
            return 1;
        } else {
            println!("Config OK");
        }
        return 0;
    }

    let mut input_buf = Vec::<u8>::new();
    match std::io::stdin().read_to_end(&mut input_buf) {
        Ok(_) => (),
        Err(e) => {
            error!("Could not read stdin: {}", e);
            return 2;
        }
    }
    let parsed_mail = match mailparse::parse_mail(&input_buf) {
        Ok(m) => m,
        Err(e) => {
            error!("Could not parse mail: {}", e);
            return 3;
        }
    };

    info!(
        "Handling mail: From: {}, Subject: {}",
        parsed_mail
            .headers
            .get_first_value("From")
            .unwrap_or_default()
            .unwrap_or_default(),
        parsed_mail
            .headers
            .get_first_value("Subject")
            .unwrap_or_default()
            .unwrap_or_default(),
    );

    for rule in config.rules {
        // If there is a filter, then run it and collect the output
        let mut filter_res = match rule.filter {
            None => None,
            Some(ref filter) => Some(Job::run(&filter, Some(&input_buf))),
        };

        // If there was a filter, then grab its output if it was successful
        let filter_buffer = match filter_res {
            Some(ref mut job) if job.success() => job.stdout.take(),
            Some(ref job) => {
                error!(
                    "Rule filter failed: {:?} => {:?}: {:?}",
                    rule.filter,
                    job.subprocess.exit_status(),
                    job.stderr
                );
                None
            }
            _ => None,
        };

        // Parse the output from the filter if there was one
        let filter_parsed = match filter_buffer {
            Some(ref filtered) => match mailparse::parse_mail(filtered) {
                Ok(m) => Some(m),
                Err(e) => {
                    error!(
                        "Could not parse output from filter {:?}: {}",
                        rule.filter, e
                    );
                    None
                }
            },
            _ => None,
        };

        // Assign the buffer and parsed mail structs to original or filtered values
        let (buffer, parsed) = match (&filter_buffer, &filter_parsed) {
            (Some(ref b), Some(ref p)) => (b, p),
            _ => (&input_buf, &parsed_mail),
        };

        // And start the business of matching.
        // Create a Match struct for each of the message parts we can match,
        // then for each of those parts, test all the rules.
        let mut mail_match = Match {
            headers: rule.headers.is_none(),
            body: rule.body.is_none(),
            raw: rule.raw.is_none(),
        };

        if let Some(ref headers_vec) = rule.headers {
            for headers_set in headers_vec {
                let mut doaction = true;
                for (k, v) in headers_set {
                    let re = match Regex::new(&v) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Could not compile regex {}: {}", v, e);
                            doaction &= false;
                            continue;
                        }
                    };
                    doaction &= match parsed.headers.get_first_value(&k) {
                        Ok(Some(ref h)) => re.is_match(h),
                        _ => false,
                    }
                }
                mail_match.headers |= doaction;
            }
        }

        if let Some(ref body_vec) = rule.body {
            for body_set in body_vec {
                let mut doaction = true;
                for body_re in body_set {
                    let re = match Regex::new(&body_re) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Could not compile regex {}: {}", body_re, e);
                            doaction &= false;
                            continue;
                        }
                    };
                    doaction &= match parsed.get_body() {
                        Ok(ref b) => re.is_match(b),
                        _ => false,
                    }
                }
                mail_match.body |= doaction;
            }
        }

        if let Some(ref raw_vec) = rule.raw {
            for raw_set in raw_vec {
                let mut doaction = true;
                for raw_re in raw_set {
                    let re = match BytesRegex::new(&raw_re) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Could not compile regex {}: {}", raw_re, e);
                            doaction &= false;
                            continue;
                        }
                    };
                    doaction &= re.is_match(&buffer);
                }
                mail_match.raw |= doaction;
            }
        }

        if mail_match.matched() {
            info!("Matched rule: {}", rule);
            if let Some(ref actions) = rule.action {
                for action in actions {
                    info!("Doing action: {}", action.join(" "));
                    let job = Job::run(&action, Some(&buffer));
                    info!(
                        "Result: {}",
                        match job.subprocess.exit_status() {
                            Some(Exited(code)) => format!("Exited: {}", code),
                            Some(Signaled(code)) => format!("Signaled: {}", code),
                            Some(Other(code)) => format!("Other: {}", code),
                            Some(Undetermined) => "Undetermined".to_string(),
                            None => "None".to_string(),
                        }
                    );
                }
            } else {
                info!("No action, message dropped");
            }
            // break rule processing loop
            break;
        }
    }
    0
}
