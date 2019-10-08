extern crate reqwest;
use reqwest::Error;
use std::collections::HashSet;
extern crate regex;
use regex::Regex;
extern crate clap;
use clap::{Arg, App};
#[macro_use] extern crate log;
extern crate env_logger;
extern crate flate2;
use env_logger::Env;
use std::io::prelude::*;
use std::str::from_utf8;
use std::io;
use flate2::read::GzDecoder;
extern crate select;
use select::document::Document;
use select::predicate::Name;


fn exitout(arg: String) {
    error!("{}", arg);
    std::process::exit(1);
}

fn buildline(data: std::collections::HashSet<&str>, cr: bool) {
	let mut newset = HashSet::new();
	// Matches only package name assuming no nonconventional naming
	let re = Regex::new(r"(.*)(?:(-[^-]*-[^-]*$))").unwrap();
	trace!("{:#?}", data);
	for item in data {
		let packagename = re.captures(item).unwrap().get(1).map_or("", |m| m.as_str());
		debug!("Got package: {}", packagename);
		newset.insert(packagename);
	}
	let finalstr = newset.into_iter().collect::<Vec<&str>>().join(" ");
	debug!("Final package list: {}", finalstr);
    match cr { 
        true => info!("yum-config-mgr --enablerepo=cr; yum update {}; yum-config-mgr --disablerepo=cr", finalstr),
        false => info!("yum update {}", finalstr),
    }
}

fn splitsort(s: &str) -> HashSet<&str> {
    let mut data = HashSet::new();
    // Messages are broadly split by two newlines between architectures, which gives the separate package groups
    // TODO: support multiple architectures
    for group in s.split("\n\n") {
        if group.contains("x86_64:") {
            for line in group.split("\n") {
                let hashsplit = line.split(" ");
                for item in hashsplit {
                    if item.ends_with(".rpm") {
                        trace!("Inserting: {}", line);
                        data.insert(item);
                    }
                }
            }
        }
    }
    data
}

fn handler(ref mut r: &String) -> reqwest::Response {
    let response = reqwest::get(*r);
    if let Err(e) = &response {
        if e.is_http() {
            match e.url() {
                None => exitout(String::from("No URL provided")),
                Some(url) => exitout(format!("Error making request to {}", url)),
            }
        }
        if e.is_serialization() {
            match e.get_ref() {
                Some(serde_error) => exitout(format!("Error parsing information {}", serde_error)),
                None => exitout(String::from("Unspecified serialization error")),
            }
        }
        if e.is_redirect() {
            exitout(String::from("Caught in redirect loop"));
        }
        if e.is_client_error() {
            exitout(String::from("Client error"));
        }
        if e.is_server_error() {
            exitout(String::from("Server error"));
        }
        if format!("{}", e) == "relative URL without a base" {
            exitout(format!("{}", e));
        }
    }
    match &response {
        Err(e) => exitout(format!("{}", e)),
        _ => (),
    };
    response.unwrap()
}


fn gzdecode(bytes: Vec<u8>) -> io::Result<String> {
    let mut gz = GzDecoder::new(&bytes[..]);
    let mut s = String::new();
//    gz.read_to_string(&mut s)?;
    match gz.read_to_string(&mut s) {
        Ok(a) => 
            {
                trace!("GZdecoded {}", a);
                Ok(s)
            },
        Err(e) => 
            { 
                trace!("Text message: {}", e);
                Ok(from_utf8(&bytes).unwrap().to_string())
            },
    }
}
macro_rules! get_archive_list {
    ($url:expr) => {{
        let resp = reqwest::get($url).unwrap();
        assert!(resp.status().is_success());
        let mut responsevec: Vec<String> = vec![];
    // Get only links from downloadable archives
        Document::from_read(resp)
            .unwrap()
            .find(Name("a"))
            .filter_map(|n| n.attr("href"))
            .filter(|l| l.contains(".txt.gz") || l.contains(".txt"))
            .filter(|l| l.contains("2019"))
            .for_each(|x| responsevec.push($url.to_string() + x));
        responsevec
    }};
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

fn main() -> Result<(), Error> {
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
                    .arg(Arg::with_name("gzip")
                    .short("g")
                    .long("gzip")
                    .help("switch for testing parsing of gzip archives"))
                    .arg(Arg::with_name("advisory")
                    .short("a")
                    .long("advisory")
                    .help("Advisory to query")
                    .takes_value(true))
                    .arg(Arg::with_name("year")
                    .short("y")
                    .long("year")
                    .help("Year of archives to query")
                    .takes_value(true))
                    .arg(Arg::with_name("cr")
                    .short("c")
                    .long("cr")
                    .help("Use CR-announce instead of CentOS-aannounce"))
                    .get_matches();
    let verbosity = match matches.occurrences_of("verbose") {
        0 => "info",
        1 => "debug",
        2 | _ => "trace",
    };

    // Turn off logging from other packages
    let baseloglevel = ",tokio=info,hyper=info,tokio_reactor=info,reqwest=info,want=info,mio=info,html5ever=info";
    // Permit overriding builtin logging via command line
    env_logger::from_env(Env::default().default_filter_or(format!("{},{}", verbosity, baseloglevel))).init();
   
    // Work on parsing mailing list archives
    if matches.is_present("gzip") {
        if !matches.is_present("advisory") {
            error!("No advisory specified.");
            std::process::exit(1);
        }
        let mut archivebundle: Vec<String> = vec![];
//        let mut archivelist: Vec<String> = vec![];
//        let mut announceurl = reqwest::get("https://lists.centos.org/pipermail/centos-announce/").unwrap();
        let year = matches.value_of("year").unwrap_or("");
        let yearre = Regex::new(r"^([0-9]{4})$").unwrap();
            let m = yearre.captures(year);
            let ym = match m {
                None => "",
                Some(a) => a.get(1).map_or("", |m| m.as_str()),
            };
        if matches.is_present("year") && ym == "" {
            error!("Invalid year");
            std::process::exit(1);
        }
        let addr = match matches.is_present("cr") {
            true => "https://lists.centos.org/pipermail/centos-cr-announce/",
            false => "https://lists.centos.org/pipermail/centos-announce/",
        };
        let archivelist = match ym {
            "" => get_archive_list!(addr),
            str => get_archive_list!(addr, str),
        };

// this works
//        let year = "2019";
//        let archivelist = get_archive_list!("https://lists.centos.org/pipermail/centos-announce/", year);

        trace!("Found archive links:\r\n{:#?}", archivelist);
        // Grab all archives, decode them, and dump into vector
        for link in archivelist {
            let mut decoded: Vec<u8> = vec![];
            let mut response = handler(&link.to_string());
            debug!("Status {} for  {}", response.status(), response.url());
            if response.status().as_u16() == 200 {
                response.copy_to(&mut decoded)?;
                let undecoded = gzdecode(decoded).unwrap();
                archivebundle.push(undecoded);
            }
        }
        trace!("Archive bundle: {:#?}", archivebundle);
        if archivebundle.len() == 0 {
            error!("No archives found");
            std::process::exit(1);
        }
/*
        let archiveurl = "https://lists.centos.org/pipermail/centos-announce/2019-August.txt.gz";
        let mut archiveresp = handler(&archiveurl.to_string());
/*        let length = match archiveresp.content_length() {
            Some(a) => a,
            None => 0,
        };
        info!("GZIP decoding.  Status {}, message length {}", archiveresp.status(), length);*/
        archiveresp.copy_to(&mut gzdecoded)?;
        let decoded = gzdecode(gzdecoded).unwrap(); */
//        let decoded_split = decoded.split("Subject:");
        let mut am = false;
        let testo = archivebundle.join("");
        let decoded_split = testo.split("Subject:");
        // Regex to parse CE**-YYYY:1234
        let subjre = Regex::new(r" \[(\w+-\w+|\w+-\w+-\w+)\] ([A-Z]{4}-[0-9]{4}:[0-9]{4})(?:\W)(.*)").unwrap();
        for message in decoded_split {
            let smessage = subjre.captures(message);
            let advisorymatch = match smessage {
                None => "None",
                Some(a) => a.get(2).map_or("None", |m| m.as_str()),
            };
            if advisorymatch != "None" {
                trace!("Advisory found: {}", advisorymatch);
                if advisorymatch == matches.value_of("advisory").unwrap_or("") {
                    let mut data = splitsort(&message);
                    debug!("Advisory matched: {}, {}", advisorymatch, subjre.captures(message).unwrap().get(3).map_or("", |m| m.as_str()));
                    buildline(data, matches.is_present("cr"));

                }
            }
            am = match advisorymatch {
                "None" => false,
                _ => {
                    if advisorymatch == matches.value_of("advisory").unwrap_or("") { std::process::exit(0); } else { false }
                },
            };
        }
        if am == false {
            error!("No matches found.");
            std::process::exit(1);
        }
    }
    // Single message passed by URL
    else {
        let request_url = matches.value_of("url").unwrap_or("");
        if request_url == "" {
            exitout(String::from("No URL specified"));
            }
//	let request_url = format!("https://lists.centos.org/pipermail/centos-cr-announce/2019-September/006197.html");
    	info!("URL: {}", request_url);
	    let mut response = handler(&request_url.to_string()); 
	
        // Check if HTTP request worked; return status code and URL if failure
    	if ! response.status().is_success() {
    		exitout(format!("Error {} for {}", response.status(), request_url));
    	}
    	let out = response.text()?;
        buildline(splitsort(&out), matches.is_present("cr"));
    }
	Ok(())
}
