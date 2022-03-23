<p align="center">
  <img src="https://raw.githubusercontent.com/bitinerant/myorigin/main/logo.png" />
</p>

<h2 align="center">MyOrigin</h2>

Fast, fault-tolerant public IP address retrieval from Python or CLI.

### Installation

```
pip install myorigin
```

### Command line usage

```
$ myorigin -v
08:54:32.904 INFO requests (need 2 matches):
08:54:33.552 INFO     http://zx2c4.com/ip → 88.123.8.180 (640 ms; 33 of 34 succeeded)
08:54:33.743 INFO     https://myip.dnsomatic.com/ → 429 Too Many Requests (30 of 35 succeeded)
08:54:34.573 INFO     http://ip.websupport.sk/ → 88.123.8.180 (814 ms; 34 of 34 succeeded)
08:54:34.584 INFO IP found: 88.123.8.180 (2 successes, 1 failures)
88.123.8.180
$ 
$ myorigin --help
usage: myorigin [-h] [-t TIMEOUT] [--minimum-match MINIMUM_MATCH]
                [--overkill OVERKILL] [--max-failures MAX_FAILURES]
                [--max-connections MAX_CONNECTIONS] [--dbfile DBFILE]
                [--show-api-providers] [-4] [-6] [-l LOGFILE] [-q] [-v]

optional arguments:
  -h, --help                         show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT      approximate timeout for http and https
                                     requests in milliseconds (default: 12000)
  --minimum-match MINIMUM_MATCH      an IP address is considered valid after
                                     this number of idential responses
                                     (default: 2)
  --overkill OVERKILL                number of initial requests to make beyond
                                     minimum-match (default: 0)
  --max-failures MAX_FAILURES        maximum number of failed requests allowed
                                     (default: 10)
  --max-connections MAX_CONNECTIONS  maximum number of simultaneous network
                                     connections allowed (default: 10)
  --dbfile DBFILE                    path for database file ('-' for memory-
                                     only; default:
                                     ~/.config/myorigin/data.sqlite)
  --show-api-providers               display the database of IP address API
                                     providers in a human-readable form and
                                     exit
  -4, --ipv4                         use IPv4 only; note this or --ipv6 is
                                     highly recommended if both IPv4 and IPv6
                                     are available, in order to avoid wasteful
                                     network traffic and unpredictable results
                                     (sometimes --minimum-match IPv4 addresses
                                     will be received first, and sometimes
                                     IPv6 will win)
  -6, --ipv6                         use IPv6 only
  -l LOGFILE, --logfile LOGFILE      path for log file (default: write to
                                     STDERR)
  -q, --quiet                        silence warning messages
  -v, --verbose                      increase verbosity
$ 
```

### Library import usage

```
>>> import myorigin
>>> args = myorigin.MyoriginArgs()
>>> args.minimum_match = 4
>>> myorigin.my_ip(args)
'88.123.8.180'
>>> 
>>> args.exception_level = 2
>>> args.ip_version = 6  # but there is no IPv6 on this LAN
>>> try:
...     myorigin.my_ip(args)
... except myorigin.NetworkError as e:
...     print(f"got error: {e}")
... 
got error: 10 requests failed; giving up
>>> 
```

### Features

* retrieves your IP address from any of 34 IP address providers
* confirms the correct IP address by checking muliple providers (default 2)
* recovers from failures by making additional requests of other providers
* keeps a record of past successes and prioritizes the fastest and most reliable providers from your location
* makes simultaneous IP address requests
* supports http, https, IPv4, IPv6

### Similiar projects

* [Go External IP](https://github.com/GlenDC/go-external-ip/): "a Golang library to get your external ip from multiple services"
* [gip](https://github.com/dalance/gip/): "a command-line tool to get global IP address"; written in Rust
* [Discovering public IP programmatically](https://stackoverflow.com/questions/613471): Stack Overflow discussion (16 answers)
* [PyNAT](https://github.com/aarant/pynat): "Discover external IP addresses and NAT topologies using STUN"


*Did you find a mistake or have a suggestion? With a GitHub account, it's easy to [suggest changes](https://github.com/bitinerant/myorigin/blob/main/README.md).* ☺

