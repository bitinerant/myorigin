<p align="center">
  <img src="https://raw.githubusercontent.com/bitinerant/myorigin/main/logo.png" />
</p>

<h2 align="center">MyOrigin</h2>

Fast, fault-tolerant public IP address retrieval from Python or CLI.

## Command line usage

```
$ myorigin -v
08:54:32.904 INFO requests (need 2 matches):
08:54:33.552 INFO     http://zx2c4.com/ip → 88.123.8.180 (640 ms; 33 of 34 succeeded)
08:54:33.743 INFO     https://myip.dnsomatic.com/ → 429 Too Many Requests (30 of 35 succeeded)
08:54:34.573 INFO     http://ip.websupport.sk/ → 88.123.8.180 (814 ms; 34 of 34 succeeded)
08:54:34.584 INFO IP found: 88.123.8.180 (2 successes, 1 failures)
88.123.8.180
$ myorigin --help
usage: myorigin [-h] [-t TIMEOUT] [--minimum-match MINIMUM_MATCH] [--overkill OVERKILL]
                [--max-failures MAX_FAILURES] [--show-api-providers] [-l LOGFILE] [-q] [-v]

Fast, fault-tolerant public IP address retrieval from Python or CLI.

optional arguments:
  -h, --help                     show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT  approximate timeout for http and https requests in milliseconds
                                 (default: 12000)
  --minimum-match MINIMUM_MATCH  an IP address is considered valid after this number of idential
                                 responses (default: 2)
  --overkill OVERKILL            number of initial requests to make beyond minimum-match (default:
                                 0)
  --max-failures MAX_FAILURES    maximum number of failed requests allowed (default: 10)
  --show-api-providers           display the database of IP address API providers in a human-
                                 readable form and exit
  -l LOGFILE, --logfile LOGFILE  path for log file (default: write to STDERR)
  -q, --quiet                    silence warning messages
  -v, --verbose                  increase verbosity
$ 
```

## Library import usage

```
>>> import myorigin
>>> args = myorigin.MyoriginArgs()
>>> args.minimum_match = 4
>>> myorigin.my_ip(args)
'88.123.8.180'
>>> 
```

*Did you find a mistake or have a suggestion? With just a GitHub account, it's easy to [suggest changes](https://github.com/bitinerant/myorigin/blob/main/README.md). ☺ *

