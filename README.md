# Aws Load Balancer Logs Analyzer

I needed to investigate the log files of an aws loadbalancer. In particular
i wanted to have the top 50 IP addresses. Ulitmatly i want to have something
similar to  what https://vegalog.net/ provides, only that its running locally,
and written in rust.

I'm fairly new to Rust so happy to receive any Feedback you might have
on how to improve the code.

## Usage

Download the logfiles you want to analyze into a local folder and unzip
them. They are stored as gzip's. Then set `LOGDIR` env var to point to that folder.

Signup for an IPINFO Token on https://ipinfo.io/ and provide that token
via the `IPINFO_TOKEN` env var.

On starting `lb-analyzer` will read all logs files in that directory and
count the occurences of ip addresses. It will produce a simple csv output
file that holds all these addresses with their occurence count. The
first 100 addresses will be looked up via the ipinfo.io service.
