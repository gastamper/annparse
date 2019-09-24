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
use std::io;
use flate2::read::GzDecoder;

fn exitout(arg: String) {
    error!("{}", arg);
    std::process::exit(1);
}

fn buildline(data: std::collections::HashSet<&str>) {
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
    info!("yum-config-mgr --enablerepo=cr; yum update {}; yum-config-mgr --disablerepo=cr", finalstr);
}

fn splitsort(s: &str) -> HashSet<&str> {
    let mut data = HashSet::new();
    // Messages are broadly split by two newlines between architectures, which gives the separate package groups
    for group in s.split("\n\n") {
        if group.contains("x86_64:") {
            for line in group.split("\n") {
                trace!("Inserting: {}", line);
                let hashsplit = line.split(" ");
                for item in hashsplit {
                    if item.ends_with(".rpm") {
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
    gz.read_to_string(&mut s)?;
    trace!("gzdecoded {}", s);
    Ok(s)
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
                    .get_matches();
    let verbosity = match matches.occurrences_of("verbose") {
        0 => "info",
        1 => "debug",
        2 | _ => "trace",
    };

    // Turn off logging from other packages
    let baseloglevel = ",tokio=info,hyper=info,tokio_reactor=info,reqwest=info,want=info,mio=info";
    // Permit overriding builtin logging via command line
    env_logger::from_env(Env::default().default_filter_or(format!("{},{}", verbosity, baseloglevel))).init();
   
    // Work on parsing mailing list archives
    if matches.is_present("gzip") {
        let archiveurl = "https://lists.centos.org/pipermail/centos-announce/2019-August.txt.gz";
        let mut archiveresp = handler(&archiveurl.to_string());
        let length = match archiveresp.content_length() {
            Some(a) => a,
            None => 0,
        };
        info!("GZIP decoding.  Status {}, message length {}", archiveresp.status(), length);
//    let decoded = gzdecode(archiveresp.text()?.as_bytes().to_vec()).unwrap();
        let mut gzdecoded: Vec<u8> = vec![];
        archiveresp.copy_to(&mut gzdecoded)?;
        let decoded = gzdecode(gzdecoded).unwrap();
//    info!("len {}, data {}", decoded.len(), decoded);

        let decoded_split = decoded.split("Subject:");
    // Regex to parse CE**-YYYY:1234
        let subjre = Regex::new(r"(\]\W)([A-Z]{4}-[0-9]{4}:[0-9]{4})").unwrap();
        for message in decoded_split {
//            debug!("Message start:\n {}", message);
//            debug!("Message end");
            let smessage = subjre.captures(message);
            let advisorymatch = match smessage {
                None => "None",
                Some(a) => a.get(2).map_or("None", |m| m.as_str()),
            };
            trace!("Advisory found: {}", advisorymatch);
            if advisorymatch != "None" {
                if advisorymatch == matches.value_of("advisory").unwrap_or("") {
                    info!("Advisory matched");
                    // work on the thing here
     //               let mut newset = HashSet::new();
                    let mut data = splitsort(&message);
//                    let re = Regex::new(r"(.*)(?:(-[^-]*-[^-]*$))").unwrap();
                    trace!("Final data: {:#?}", data);
                    buildline(data);       

                }
            }
        }
    }

    let request_url = matches.value_of("url").unwrap_or("");
    if request_url == "" {
        exitout(String::from("No URL specified"));
        }
//	let request_url = format!("https://lists.centos.org/pipermail/centos-cr-announce/2019-September/006197.html");
	info!("URL: {}", request_url);
	//let mut response = reqwest::get(&request_url.to_string())?;
	let mut response = handler(&request_url.to_string()); 
	
    
    // Check if HTTP request worked; return status code and URL if failure
	if ! response.status().is_success() {
		exitout(format!("Error {} for {}", response.status(), request_url));
	}
	let out = response.text()?;

    // Valid list entries take the format:
    // [...]\n
    // syncing to the mirrors: (sha256sum Filename)\n
    // \n
    // [arch (x86_64, Source, etc)]\n
    // [sha256sum] [Filename]\n
    //
    // [...]\n
    // \n
    //
    // Split entries by two newlines in succession and then check if the current section
    // is applicable to the architecture supplied.

    buildline(splitsort(&out));

//  Logic for prepending/appending CR repository enabling
//  if opt.crrepo == true { info!("yum-config-mgr --enablerepo=cr; yum update
//  {};  yum-config-mgr --disablerepo=cr", finalstr); }
//  else { info!("yum update {}", finalstr); }
//  elif opt.pkgonly == true { info!("{}"); }
	Ok(())
}
