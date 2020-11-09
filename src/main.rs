extern crate reqwest;
use std::error::Error;
//use reqwest::Error;
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

// new stuff
use std::fs;

fn exitout(arg: String) {
    error!("{}", arg);
    std::process::exit(1);
}

// Build final output (package list) from a mailing list entry
fn buildline(data: std::collections::HashSet<&str>) -> String{
	let mut newset = HashSet::new();
	// Matches only package name assuming no nonconventional naming
	let re = Regex::new(r"(.*)(?:(-[^-]*-[^-]*$))").unwrap();
	trace!("buildline: {:#?}", data);
    if data.len() == 0 { 
        exitout(String::from("Advisory appears to be empty."));
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
                        trace!("splitsort: Inserting: {}", line);
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

// Function to un-gzip any response
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

// Macro to pull a list of archives from the mailing list
macro_rules! get_archive_list {
    // This branch is no longer used now that year is parsed from advisory
    ($url:expr) => {{
        let resp = reqwest::get($url).unwrap();
        assert!(resp.status().is_success());
        let mut responsevec: Vec<String> = vec![];
    // Get only links from downloadable archives
    // Check only current year unless year is specified
        let year = ((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() / 31557600000) + 1970).to_string();
        Document::from_read(resp)
            .unwrap()
            .find(Name("a"))
            .filter_map(|n| n.attr("href"))
            .filter(|l| l.contains(".txt.gz") || l.contains(".txt"))
            .filter(|l| l.contains(&year))
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


//fn main() -> Result<(),dyn Error> {
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
   
    // If no URL passed, advisory is required
    if !matches.is_present("url") {
        if !matches.is_present("advisory") {
            error!("No advisory specified.");
            std::process::exit(1);
        }
        
// TODO: filesystem work
/*        use std::fs;
        let path = std::path::Path::new("./2020-May.txt");
        let display = path.display();

        let mut file = match std::fs::File::open(&path) {
            Err(e) => panic!(e.to_string()),
            Ok(file) => file,
        };
        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(e) => exitout(e.to_string()),
            Ok(_) => trace!("{}", s),
        };
        std::process::exit(1);
*/
//let mut entries = fs::read_dir("./cache").unwrap().map(|res| res.map(|e| e.path())).collect::<Result<Vec<_>, io::Error>>();


//        let mut cache: Vec<String> = vec![];
        let mut archivebundle: Vec<String> = vec![];

        // If in offline mode
        if matches.is_present("offline") {
        // Get list of items in cache
        let dir = match fs::read_dir("./cache") {
            Err(e) => {error!("Error reading cache: {}", e); std::process::exit(e.raw_os_error().unwrap())},
            Ok(items) => items
        };

        let mut cache: Vec<String> = vec![];
        // Set cache so that entries can be pushed into it
//        let mut cache: Vec<String> = vec![];
        for entry in dir {
            // Don't see how this could ever fail, famous last words
            let item = match entry {
                Err(e) => {error!("Error reading cache: {}", e); std::process::exit(e.raw_os_error().unwrap())},
            // Item(n) is of type DirEntry
                Ok(n) => n
            };
            // Try to read individual entry into a string so it can be push'd
            let s = match fs::read_to_string(item.path()) {
                Err(e) => {error!("Error reading cache item: {:#?}: {}", item.path(), e); std::process::exit(e.raw_os_error().unwrap_or(127))},
                Ok(n) => n
            };
            archivebundle.push(s);
            trace!("{:#?}", item);

        }
        // Number of cache entries read = vector.len()
        trace!("Cache length: {:#?}", cache.len());
        //std::process::exit(1);
//        let mut archivebundle = cache;
        }

        // Determine which list to use
        let addr = match matches.is_present("cr") {
            true => "https://lists.centos.org/pipermail/centos-cr-announce/",
            false => "https://lists.centos.org/pipermail/centos-announce/",
        };


        // Parse year from advisory
        let a = match Regex::new(r"^.*-([0-9]{4}):[0-9]{4}$")
                .unwrap()
                .captures(matches.value_of("advisory")
                .unwrap_or(""))      
        {
            None => "",
            Some(a) => a.get(1).map_or("", |m| m.as_str()),
        };
        if a == "" {
            error!("Couldn't parse year from advisory.");
            std::process::exit(1);
        }
        if !matches.is_present("offline") {
        // Query mailing list for advisory
        let archivelist = get_archive_list!(addr, a);

        // Data pulled from archivelist
//        let mut archivebundle: Vec<String> = vec![];

        trace!("Found archive links:\r\n{:#?}", archivelist);
        // Grab all archives, decode them, and dump into vector
        for link in archivelist {
            let mut decoded: Vec<u8> = vec![];
            let mut response = handler(&link.to_string());
            debug!("Status {} for {}", response.status(), response.url());
            if response.status().as_u16() == 200 {
                //response.copy_to(&mut decoded)?;
                response.copy_to(&mut decoded).unwrap();
                let undecoded = gzdecode(decoded).unwrap();
                archivebundle.push(undecoded);
            }
        }
       }

        trace!("Archive bundle found, length {}", archivebundle[0].len());
        // Uncomment to see full data from get_archive_list
        //trace!("Archive bundle: {:#?}", archivebundle);
        if archivebundle.len() == 0 {
            error!("No archives found");
            std::process::exit(1);
        }
      
        let mut count = 0;
        let mut am = false;
        let mut buf = String::new();
        let joinedbundle = archivebundle.join("");
        let decoded_split = joinedbundle.split("Subject:");
        // Regex to parse `[CentOS-Announce|Centos-CR] CE**-YYYY:1234 advisory-title` from list 
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
                    let data = splitsort(&message);
                    debug!("Advisory matched: {}, {}", advisorymatch, subjre.captures(message).unwrap().get(3).map_or("", |m| m.as_str()));
//                    buildline(data);             
                    buf.insert_str(0, &buildline(data));
                    count += 1;

                }
            }
            // There can be multiple entries with same name, f.e. CESA-2020:4076
//            am = match advisorymatch {
//               "None" => false,
//                _ => {
//                    if advisorymatch == matches.value_of("advisory").unwrap_or("") { std::process::exit(0); } else { false }
//                },
//            };
        }
//        if am == false {
        if count == 0 {
            error!("No matches found.");
            std::process::exit(1);
        }
        else {
            info!("{}", buf);
            std::process::exit(0);
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
    	//let out = response.text()?;
    	let out = response.text().unwrap();
        info!("{}", buildline(splitsort(&out)));
    }
    std::process::exit(0);
}
