import ipaddress
import re


class GrepIPs:
    def grep_ips(text, ip_version=0, global_ips_only=False, first_match_only=False):
        """
        If first_match_only == True, returns ipaddress.IPv4Address or ipaddress.IPv6Address or None
        If first_match_only == False, returns a possibly empty list of IPv4Address or IPv6Address
        """
        # see also https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
        ipv4 = r'(?<![0-9a-zA-Z.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9a-zA-Z.])'
        ipv6 = r'(?<![0-9a-zA-Z:])(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(?![0-9a-zA-Z:])'
        if ip_version == 4:
            ip_re = re.compile(f'({ipv4})')
        elif ip_version == 6:
            ip_re = re.compile(f'({ipv6})')
        else:
            ip_re = re.compile(f'((?:{ipv4})|(?:{ipv6}))')
        if not first_match_only:
            result = list()
        for m in ip_re.finditer(text):
            try:
                i = ipaddress.ip_address(m.group(1))
            except ValueError:  # e.g. 333.4.5.6
                continue
            if global_ips_only and (not i.is_global):  # e.g. 192.168.1.100
                continue
            if first_match_only:
                return i
            result.append(i)
        if first_match_only:
            return None
        else:
            return result
