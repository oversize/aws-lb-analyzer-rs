use whois_rust::{WhoIs, WhoIsLookupOptions};
use std::path::Path;
use std::io::{self, BufRead};
use std::fs;
use std::fs::File;
use std::fs::read_to_string;
use std::collections::HashMap;
use std::net::Ipv4Addr;

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

fn main() {
    let whois_servers = String::from(r#"{
        "org": "whois.pir.org",
        "": "whois.ripe.net",
        "_": {
            "ip": {
                "host": "whois.arin.net",
                "query": "n + $addr\r\n"
            }
        }
    }"#);
    let mut address_counts: HashMap<Ipv4Addr, u32> = HashMap::new();
    let mut addresses = 0;
    for rd in fs::read_dir("/home/msch/src/oversize/lb-analyzer/s3/").unwrap() {
        if let Ok(direntry) = rd {
            let path_buf = direntry.path();
            let filename = path_buf.to_str().unwrap();
            // Read all lines of filename into lines
            if let Ok(lines) = read_lines(filename) {
                for line in lines {
                    if let Ok(line) = line {
                        if let Some(ip) = from_line(line) {
                            addresses += 1;
                            if let Some(previous_count) = address_counts.get(&ip) {
                                address_counts.insert(ip, previous_count + 1);
                            } else {
                                address_counts.insert(ip, 1);
                            }
                        }
                    }
                }
            }
        }
    }
    // Finished processing Files

    // From all addresses take the ones that have at least 100 occurences and put it into a vector
    let mut address_vec: Vec<(&Ipv4Addr, &u32)> = address_counts.iter().filter(|w| w.1 > &100).collect();
    // Sort the vector so that the highest occurences are first
    address_vec.sort_by(|a, b| b.1.cmp(a.1));
    // Take the top ten
    let (top_ten, _) = address_vec.split_at(10);
    println!("{:?}", address_vec);
    println!("Adresses: {}", addresses);
    println!("Unique adresses: {}", address_counts.len());

    let whois = WhoIs::from_string(whois_servers).unwrap();
    for t in top_ten.iter() {
        println!("{:?}", t);
        let opts = WhoIsLookupOptions::from_string(t.0.to_string()).unwrap();
        if let Ok(ripe_string) = whois.lookup(opts) {
            // println!("{:?}", ripe_string);
            let lines = ripe_string.split("\n");
            // println!("{:?}", lines);
            for line in lines.into_iter() {
                // println!("{:?}", line);
                if line.contains("descr:") {
                    let name = line.split(":").into_iter().nth(1).unwrap();
                    println!("{}", name);
                    continue;
                }
            }
        }
    }
    // println!("Top Ten {:#?}", top_ten);
    // println!("Top Ten {:#?}", top_ten.len());

}
