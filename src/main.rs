extern crate reqwest;
use reqwest::Error;
use std::collections::HashSet;
extern crate regex;
use regex::Regex;
extern crate clap;
use clap::{Arg, App};
#[macro_use] extern crate log;
extern crate env_logger;
use env_logger::Env;

fn exitout(arg: String) {
    error!("{}", arg);
    std::process::exit(1);
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
                    .get_matches();
    let verbosity = match matches.occurrences_of("verbose") {
        0 => "info",
        1 => "debug",
        2 | _ => "trace",
    };
    // Turn off logging from other packages
    let baseloglevel = ",tokio=info,hyper=info,tokio_reactor=info,reqwest=info,want=info,mio=info";
    env_logger::from_env(Env::default().default_filter_or(format!("{},{}", verbosity, baseloglevel))).init();
    
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
	let split = out.split("\n\n");
	let mut data = HashSet::new();;
	
	for s in split {
		let mut matched = false;
		for line in s.split("\n") {
			if matched == true { 
				trace!("Inserting: {}", line);
				let hashsplit = line.split("  ");
				for item in hashsplit {
					if item.ends_with(".rpm") {
						data.insert(item); 
					}
				}
			}
			// Find x86_64 heading and set flag to begin inserting lines into set
			if line == "x86_64:" { 
				debug!("Found x86_64");
				matched = true;
			}
		}
	}
	let mut newset = HashSet::new();
	// Matches only package name assuming no nonconventional naming
	let re = Regex::new(r"(.*)(?:(-[^-]*-[^-]*$))").unwrap();
	trace!("{:#?}", data);
	for item in data {
		let packagename = re.captures(item).unwrap();
		debug!("Got package: {}", packagename.get(1).map_or("", |m| m.as_str()));
		newset.insert(packagename.get(1).map_or("", |m| m.as_str()));
	}
	let finalstr = newset.into_iter().collect::<Vec<&str>>().join(" ");
	debug!("Final package list: {}", finalstr);

//  Logic for prepending/appending CR repository enabling
//  if opt.crrepo == true { info!("yum-config-mgr --enablerepo=cr; yum update
//  {};  yum-config-mgr --disablerepo=cr", finalstr); }
//  else { info!("yum update {}", finalstr); }
//  elif opt.pkgonly == true { info!("{}"); }
	info!("yum-config-mgr --enablerepo=cr; yum update {}; yum-config-mgr --disablerepo=cr", finalstr);
	Ok(())
}
