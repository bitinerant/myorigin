#!/usr/bin/env python3
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

    def grep_ips_test():
        ip_test_strings = [
            '88.1.1.1',
            'IPs 88.1.1.2, 1.2.3.4, 9.9.9.9, etc.',
            '239.255.255.254',
            'fdsjaefwe--2.2.2.2--',
            '<123.123.123.123>, <11.11.11.11>',
            '7.8.9.10;11.12.13.14;15.16.17.19;20.21.22.23;',
            '7.8.9.10,11.12.13.14,15.16.17.19,20.21.22.23',
            'fdsjaefwe--::111,[::222]',
            '2604:ba90:111:83::2:5050',
            'abcd:a880::6:1000, ::8, 1::8, ::2:3:4:5:6:7:8, ',
            '[2:3:4:5:6:7:8:9],[10::11],[12:13:14:15::16],',
            '==9001:0db8:0000:0000:0000:ff00:0042:8329==',
            # begin invalid tests
            '888.1.1.1',
            '1234.23.53.53',
            '1.2.3.4.5',
            'aa2.2.2.2',
            '2.2..2.2',
            '127.0.0.1',
            '::1, ::',
            '<192.168.1.100>',
            '3.3.3',
            '4.4.4.4B',
            'fd18:a880:::6:1000',
            'fd18:a880::6::1000',
            'ffd18:a880::6:1000',
            'fd18:a880:1:6:100g',
            '1:2:3:4:5:6:7:8:9',
        ]
        expected_results = [
            ['88.1.1.1'],
            ['88.1.1.2', '1.2.3.4', '9.9.9.9'],
            ['239.255.255.254'],
            ['2.2.2.2'],
            ['123.123.123.123', '11.11.11.11'],
            ['7.8.9.10', '11.12.13.14', '15.16.17.19', '20.21.22.23'],
            ['7.8.9.10', '11.12.13.14', '15.16.17.19', '20.21.22.23'],
            ['::111', '::222'],
            ['2604:ba90:111:83::2:5050'],
            ['abcd:a880::6:1000', '::8', '1::8'],
            ['2:3:4:5:6:7:8:9', '10::11', '12:13:14:15::16'],
            ['9001:db8::ff00:42:8329'],
        ] + [[] for i in range(15)]
        ip_test_results = [
            [str(ip) for ip in GrepIPs.grep_ips(ips, global_ips_only=True)]
            for ips in ip_test_strings
        ]
        assert ip_test_results == expected_results, f"got {ip_test_results}"
