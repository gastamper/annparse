use std::{io, fs, str::from_utf8, io::prelude::*, collections::HashSet};
extern crate reqwest;
extern crate regex;
use regex::Regex;
extern crate clap;
use clap::{Arg, App};
#[macro_use] extern crate log;
extern crate env_logger;
extern crate flate2;
use env_logger::Env;
use flate2::read::GzDecoder;
extern crate select;
use select::{document::Document, predicate::Name};

macro_rules! exit_out {
  ( $message: expr ) => {{
		info!("{}", $message);
    std::process::exit(0);
  }};
  ( $message: expr, $rc: expr ) => {{
    match $rc {
      0 => { info!("{}", $message); std::process::exit(0); },
      _ => { error!("{}", $message); std::process::exit($rc); },
    }
  }};
}

// Build final output (package list) from a mailing list entry
fn build_line(data: std::collections::HashSet<&str>) -> String{
	let mut newset = HashSet::new();
	// Matches only package name assuming no nonconventional naming
	let re = Regex::new(r"(.*)(?:(-[^-]*-[^-]*$))").unwrap();
	trace!("build_line: {:#?}", data);
    if data.len() == 0 { 
        exit_out!(String::from("Advisory appears to be empty."), 1);
    }
	for item in data {
		let packagename = re.captures(item).unwrap().get(1).map_or("", |m| m.as_str());
		debug!("Got package: {}", packagename);
		newset.insert(packagename);
	}
	let finalstr = newset.into_iter().collect::<Vec<&str>>().join(" ");
	debug!("Final package list: {}", finalstr);
    // Pad end in case another advisory follows
    String::from(finalstr + " ")
}

fn split_sort(s: &str) -> HashSet<&str> {
    let mut data = HashSet::new();
    // Messages are broadly split by two newlines between architectures, which gives the separate package groups
    // TODO: support multiple architectures
    for group in s.split("\n\n") {
        if group.contains("x86_64:") {
            for line in group.split("\n") {
                let hashsplit = line.split(" ");
                for item in hashsplit {
                    if item.ends_with(".rpm") {
                        trace!("split_sort: Inserting: {}", line);
                        data.insert(item);
                    }
                }
            }
        }
    }
    data
}

// Web handler using reqwest
fn handler(ref mut r: &String) -> reqwest::Response {
    let response = reqwest::get(*r);
    if let Err(e) = &response {
        if e.is_http() {
            match e.url() {
                None => exit_out!(String::from("No URL provided"), 1),
                Some(url) => exit_out!(format!("HTTP error making request to {}", url), 1),
            }
        }
        if e.is_serialization() {
            match e.get_ref() {
                Some(serde_error) => exit_out!(format!("HTTP request error while parsing information {}", serde_error), 1),
                None => exit_out!(String::from("Unspecified serialization error during HTTP request"), 1),
            }
        }
        if e.is_redirect() {
            exit_out!(String::from("HTTP request error: caught in redirect loop"), 1);
        }
        if e.is_client_error() {
            exit_out!(String::from("Client error during HTTP request"), 1);
        }
        if e.is_server_error() {
            exit_out!(String::from("Server error during HTTP request"), 1);
        }
        if format!("{}", e) == "relative URL without a base" {
            exit_out!(format!("HTTP request error: {}", e), 1);
        }
    }
    match &response {
        Err(e) => exit_out!(format!("HTTP request error: {}", e), 1),
        _ => (),
    };
    response.unwrap()
}

// Function to un-gzip any response
fn gzdecode(bytes: Vec<u8>) -> io::Result<String> {
    let mut gz = GzDecoder::new(&bytes[..]);
    let mut s = String::new();
    match gz.read_to_string(&mut s) {
        Ok(a) => 
            {
                trace!("Decompressed {} bytes", a);
                Ok(s)
            },
        Err(e) => 
            { 
                trace!("Text message: {}", e);
                Ok(from_utf8(&bytes).unwrap().to_string())
            },
    }
}

// Macro to pull a list of archives from the mailing list
macro_rules! get_archive_list {
    ($url:expr, $year:expr) => {{
        let resp = reqwest::get($url).unwrap();
        assert!(resp.status().is_success());
        let mut responsevec: Vec<String> = vec![];
    // Get only links from downloadable archives
        Document::from_read(resp)
            .unwrap()
            .find(Name("a"))
            .filter_map(|n| n.attr("href"))
            .filter(|l| l.contains(".txt.gz") || l.contains(".txt"))
            .filter(|l| l.contains($year))
            .for_each(|x| responsevec.push($url.to_string() + x));
        responsevec
    }};
}


fn main() {
    let matches = App::new("annparse")
                    .arg(Arg::with_name("url")
                    .short("u")
                    .long("url")
                    .help("URL of specific mailing list entry to parse")
                    .takes_value(true))
                    .arg(Arg::with_name("verbose")
                    .short("v")
                    .long("verbose")
                    .help("verbosity level")
                    .multiple(true))
                    .arg(Arg::with_name("advisory")
                    .short("a")
                    .long("advisory")
                    .help("Advisory to query")
                    .takes_value(true))
                    .arg(Arg::with_name("cr")
                    .short("c")
                    .long("cr")
                    .help("Use CR-announce instead of CentOS-aannounce"))
                    .arg(Arg::with_name("offline")
                    .short("o")
                    .long("offline")
                    .help("Offline mode (use local cache directory ./cache for archives)"))
                    .arg(Arg::with_name("cache_path")
                    .short("p")
                    .long("cache_path")
                    .help("Path to offline cache folder")
                    .takes_value(true)
                    .requires("offline")
                    .default_value("./cache"))
                    .get_matches();
    let verbosity = match matches.occurrences_of("verbose") {
        0 => "info",
        1 => "debug",
        2 | _ => "trace",
    };

    // Turn off logging from other packages
    let baseloglevel = ",tokio=info,hyper=info,tokio_reactor=info,reqwest=info,want=info,mio=info,html5ever=info";
    // If level is "info", strip logging so output is easily passed elsewhere
    if verbosity == "info" {
        use log::LevelFilter;
        let mut builder = env_logger::Builder::from_default_env();
        builder.format(|buf, record| writeln!(buf, "{}", record.args()))
            .filter(None, LevelFilter::Info).init();
    }
    else {
    // Permit overriding builtin logging via command line
    env_logger::from_env(Env::default().default_filter_or(format!("{},{}", verbosity, baseloglevel))).init();
    }
   
    if !matches.is_present("advisory") {
        error!("No advisory specified.");
        std::process::exit(1);
    }
 

    let mut archive_bundle: Vec<String> = vec![];

    fn build_offline(cache_path: &str) -> Vec<String> {
        let mut archive_bundle: Vec<String> = vec![];
        let dir = match fs::read_dir(cache_path) {
            Err(e) => {error!("Error reading cache folder {}: {}", cache_path, e); std::process::exit(e.raw_os_error().unwrap())},
            Ok(items) => items
        };
        for entry in dir {
            // Don't see how this could ever fail, famous last words
            let item = match entry {
                Err(e) => {exit_out!("Error reading cache folder: ".to_string() + &e.to_string(), e.raw_os_error().unwrap())},
                // Item(n) is of type DirEntry
                Ok(n) => n
            };
            // Try to read individual entry into a string so it can be push'd
            // TODO: fs::read should be match'd on its own to catch errors there
            let s = match gzdecode(fs::read(item.path()).unwrap()) {
                Err(e) => {exit_out!("Error reading cache item, ".to_string() + &e.to_string() + ": " + &item.path().to_str().unwrap().to_string(), 
                            e.raw_os_error().unwrap_or(127))},
                Ok(n) => n
            };
            archive_bundle.push(s);
            trace!("{:#?}", item);
        }
      archive_bundle
      }
    
    // If in offline mode
    if matches.is_present("offline") {
        // default to ./cache if no cache_path argument given
        let cache_path = match matches.is_present("cache_path") {
            true => matches.value_of("cache_path").unwrap(),
            false => "./cache",
        };
        archive_bundle = build_offline(cache_path);
        trace!("Cache length: {:#?}", archive_bundle.len());
    }


    // Parse year from advisory
    let year = match Regex::new(r"^.*-([0-9]{4}):[0-9]{4}$")
            .unwrap()
            .captures(matches.value_of("advisory")
            .unwrap_or(""))      
    {
        None => { exit_out!(String::from("Couldn't parse year from advisory."), 1); },
        Some(a) => a.get(1).map_or("", |m| m.as_str()),
    };

    if !matches.is_present("offline") {
        // Determine which list to use
        let addr = match matches.is_present("cr") {
            true => "https://lists.centos.org/pipermail/centos-cr-announce/",
            false => "https://lists.centos.org/pipermail/centos-announce/",
        };
        // Query mailing list for advisory
        let archive_list = get_archive_list!(addr, year);
        // Data pulled from archive_list
        trace!("Found archive links:\r\n{:#?}", archive_list);
        // Grab all archives, decode them, and dump into vector
        for link in archive_list {
            let mut decoded: Vec<u8> = vec![];
            let mut response = handler(&link.to_string());
            debug!("Status {} for {}", response.status(), response.url());
            if response.status().as_u16() == 200 {
                //response.copy_to(&mut decoded)?;
                response.copy_to(&mut decoded).unwrap();
                let undecoded = gzdecode(decoded).unwrap();
                archive_bundle.push(undecoded);
            }
        }
    }

    trace!("Archive bundle found, length {}", archive_bundle[0].len());
    // Uncomment to see full data from get_archive_list
    //trace!("Archive bundle: {:#?}", archive_bundle);
    if archive_bundle.len() == 0 {
        exit_out!("No archives found", 1);
    }
      
    let mut count = 0;
    let mut buf = String::new();
    let joined_bundle = archive_bundle.join("");
    let decoded_split = joined_bundle.split("Subject:");
    // Regex to parse `[CentOS-Announce|Centos-CR] CE**-YYYY:1234 advisory-title` from list 
    let subject_regex = Regex::new(r" \[(\w+-\w+|\w+-\w+-\w+)\] ([A-Z]{4}-[0-9]{4}:[0-9]{4})(?:\W)(.*)").unwrap();
    for message in decoded_split {
        let subject_regex_captures = subject_regex.captures(message);
        let advisory_match = match subject_regex_captures {
            None => "None",
            Some(a) => a.get(2).map_or("None", |m| m.as_str()),
        };
        if advisory_match != "None" {
            trace!("Advisory found: {}", advisory_match);
            if advisory_match == matches.value_of("advisory").unwrap_or("") {
                let data = split_sort(&message);
                debug!("Advisory matched: {}, {}", advisory_match, subject_regex.captures(message).unwrap().get(3).map_or("", |m| m.as_str()));
                buf.insert_str(0, &build_line(data));
                count += 1;
            }
        }
    }

    match count {
       0 => exit_out!("No matches found.", 1),
       _ => exit_out!(buf, 0)
    };
}
