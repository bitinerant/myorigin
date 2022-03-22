import subprocess

print('''<p align="center">
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
'''
+ subprocess.Popen(['myorigin', '--help'], stdout=subprocess.PIPE).communicate()[0].decode()
+ '''$ 
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

### Similiar projects

* [Go External IP](https://github.com/GlenDC/go-external-ip/): "a Golang library to get your external ip from multiple services"
* [gip](https://github.com/dalance/gip/): "a command-line tool to get global IP address"; written in Rust
* [Discovering public IP programmatically](https://stackoverflow.com/questions/613471): Stack Overflow discussion (16 answers)
* [PyNAT](https://github.com/aarant/pynat): "Discover external IP addresses and NAT topologies using STUN"


*Did you find a mistake or have a suggestion? With a GitHub account, it's easy to [suggest changes](https://github.com/bitinerant/myorigin/blob/main/README.md).* ☺
''')

