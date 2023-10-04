
use core::panic;
use std::path::Path;
use std::env;
use std::io::{self, BufRead, Write};
use std::fs;
use std::fs::File;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use ipinfo::{IpInfo, IpInfoConfig};
use color_eyre::eyre::Result;

// Taken from the rust-by-example book: https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/read_lines.html
// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn from_line(line: String) -> Option<Ipv4Addr> {
    match line.split_whitespace().nth(3) {
        Some(ip) =>  {
            // Why does it need to be mutable??
            let mut split = ip.split(":");
            if let Some(ip) = split.nth(0) {
                let addr: Ipv4Addr = ip.parse().expect("Not a valid ip");
                Some(addr)
            } else {
                None
            }
        },
        None => None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(e) = color_eyre::install() {
        panic!("Could not install color_eyre: {}", e);
    }
    let ipinfo_token = env::var("IPINFO_TOKEN").expect(
        "Set IPINFO_TOKEN with token from https://ipinfo.io/ "
    );
    let config = IpInfoConfig {
        token: Some(ipinfo_token),
        ..Default::default()
    };
    let mut ipinfo = IpInfo::new(config)
        .expect("should construct");

    let mut address_counts: HashMap<Ipv4Addr, u32> = HashMap::new();

    let mut total_files = 0;
    let mut total_lines = 0;
    let logdir = env::var("LOGDIR").expect(
        "Set LOGDIR to path to loadbalancer logfiles"
    );
    for rd in fs::read_dir(logdir).unwrap() {
        if let Ok(direntry) = rd {
            let path_buf = direntry.path();
            let filename = path_buf.to_str().unwrap();
            // Read all lines of filename into lines
            if let Ok(lines) = read_lines(filename) {
                for line in lines {
                    if let Ok(line) = line {
                        if let Some(ip) = from_line(line) {
                            if let Some(previous_count) = address_counts.get(&ip) {
                                address_counts.insert(ip, previous_count + 1);
                            } else {
                                address_counts.insert(ip, 1);
                            }
                        }
                        total_lines += 1;
                    }
                }
            }
        }
        total_files += 1;
    }
    // Finished processing Files

    // From all addresses take the ones that have at least 100 occurences and put it into a vector
    let mut address_vec: Vec<(&Ipv4Addr, &u32)> = address_counts.iter().filter(|w| w.1 > &100).collect();
    // Sort the vector so that the highest occurences are first
    address_vec.sort_by(|a, b| b.1.cmp(a.1));

    // Take the top 100
    let (top_, rest) = address_vec.split_at(100);
    let mut out_lines_csv: Vec<String> = Vec::new();

    for v in top_ {
        // There also is a batch lookup option
        // ipinfo.lookup_batch(ips, batch_config);
        let ipinfo_result =  ipinfo.lookup(&v.0.to_string()).await;
        match ipinfo_result {
            Ok(ipinfo_details) => {
                // println!("{:?}", ipinfo_details);
                let mut l = String::new();
                // IP, Count
                l.push_str(&format!("{}, {}, ", v.0, v.1));
                // Country Name
                if let Some(country_name) = ipinfo_details.country_name {
                    l.push_str(&format!("{}, ", country_name));
                }
                // City
                l.push_str(&format!("{}, ", ipinfo_details.city));
                // hostname
                if let Some(hostname) = ipinfo_details.hostname {
                    l.push_str(&format!("{}", hostname));
                }
                // Org
                if let Some(org) = ipinfo_details.org {
                    l.push_str(&format!("{}, ", org));
                }
                out_lines_csv.push(format!("{}\n", l));
            },
            Err(e) => println!("Error occured: {}", e)
        }
    }

    for v in rest.iter() {
        out_lines_csv.push(format!("{}, {}, -, -, -, -,\n", v.0, v.1));
    }

    let mut outfile = File::create("out.csv").unwrap();
    for l in out_lines_csv {
        if let Ok(_) = write!(outfile, "{}", l) {}
    }

    println!("Analyzed {} files with {} total lines and {} unique addresses.", total_files, total_lines, address_vec.len());

    Ok(())
}
