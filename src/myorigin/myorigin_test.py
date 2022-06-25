import random
import textwrap
import myorigin.myorigin


def test_my_ip_set1(caplog) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site91.com     site91.com/4.5.6.7           4 b
        site62.com     site62.com/xyxyxyxyxy        4 b
        site98.com     site98.com/xyxyxyxyxy        4 b
        site97.com     site97.com/xyxyxyxyxy        4 b
        site94.com     site94.com/xyxyxyxyxy        4 b
        site93.com     site93.com/xyxyxyxyxy        4 b
        site80.com     site80.com/4.5.6.7           4 b
        site29.com     site29.com/xyxyxyxyxy        4 b
        site55.com     site55.com/4.5.6.7           4 b
        site44.com     site44.com/xyxyxyxyxy        4 b
        site85.com     site85.com/ip_is_4.5.6.7_    4 b
        site43.com     site43.com/2604::89          6 b
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.log_level = 3
    args.ip_version = 4
    args.minimum_match = 4
    assert myorigin.my_ip(args) == '4.5.6.7'
    args.minimum_match = 5
    caplog.clear()
    myorigin.my_ip(args)
    assert 'not enough providers for 5 matches' in caplog.text
    args.ip_version = 6
    args.minimum_match = 2
    caplog.clear()
    myorigin.my_ip(args)
    assert 'not enough providers for 2 matches' in caplog.text
    args.minimum_match = 1
    assert myorigin.my_ip(args) == '2604::89'
    myorigin.myorigin.http_get.pytest = 2
    caplog.clear()
    myorigin.my_ip(args)
    assert (
        "https://site43.com/2604::89 → 404 pytest simulated error" in caplog.records[1].message
        or "http://site43.com/2604::89 → 404 pytest simulated error" in caplog.records[1].message
    )
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set2(caplog) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site88.com     site88.com/77                4 s
        site20.com     site20.com/1.2.3.4           6 s
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.log_level = 3
    args.ip_version = 4
    args.minimum_match = 5
    caplog.clear()
    myorigin.my_ip(args)
    assert "https://site88.com/77 → Only 2 bytes received" in caplog.records[1].message
    args.ip_version = 6  # IPv6-only, so should not recognize IPv4 address '1.2.3.4'
    caplog.clear()
    myorigin.my_ip(args)
    assert "https://site20.com/1.2.3.4 → No IP address found" in caplog.records[1].message
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set3(caplog) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site48.com     site48.com/127.0.0.1         4 p
        site51.com     site51.com/2b::29            6 s
        site52.com     site52.com/bad::18           6 s
        site53.com     site53.com/2b::29            6 s
        site54.com     site54.com/2b::29            6 s
        site55.com     site55.com/2b::29            6 s
        site56.com     site56.com/2b::29            6 s
        site57.com     site57.com/bad::18           6 s
        site58.com     site58.com/2b::29            6 s
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.log_level = 3
    args.ip_version = 4
    args.minimum_match = 5
    caplog.clear()
    myorigin.my_ip(args)
    assert (
        "http://site48.com/127.0.0.1 → Found non-global IP address 127.0.0.1"
        in caplog.records[1].message
    )
    args.log_level = 4
    args.ip_version = 6
    args.majority_ratio = 3  # 2 of 'bad::18', so need 6 to override
    caplog.clear()
    assert myorigin.my_ip(args) == '2b::29'  # rarely a test will succeed without receiving bad::18
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set4(caplog) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site60.com     site60.com/2buo29            4 b
        site61.com     site61.com/127.0.0           4 b
        site62.com     site62.com/3aaf18            4 b
        site63.com     site62.com/bbuo29            4 b
        site64.com     site64.com/r27.0.0           4 b
        site65.com     site65.com/naaf18            4 b
        site66.com     site66.com/lbuo29            4 b
        site67.com     site67.com/                  4 b
        site68.com     site68.com/%20%20%20%20      4 b
        site69.com     site69.com/tttttt            4 b
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.log_level = 3
    args.ip_version = 4
    args.max_failures = 9
    caplog.clear()
    myorigin.my_ip(args)
    assert "9 requests failed; giving up" in caplog.records[10].message
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set5(caplog) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site51.com     site51.com/2b::29            6 s
        site52.com     site52.com/bad::18           6 s
        site53.com     site53.com/2b::29            6 s
        site54.com     site54.com/2b::29            6 s
        site55.com     site55.com/2b::29            6 s
        site57.com     site57.com/bad::18           6 s
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.minimum_match = 5
    args.log_level = 3
    args.ip_version = 6
    args.majority_ratio = 3  # 2 of 'bad::18', so need 6 to override
    caplog.clear()
    myorigin.my_ip(args)
    assert (
        "multiple IPs received: ['2b::29', 'bad::18']"
        or "multiple IPs received: ['bad::18', '2b::29']"
        in "; ".join([i.message for i in caplog.records])
    )
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set6(caplog, capsys) -> None:
    myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
    test_flock_data = '''
        site62.com     site62.com/x                 4 p
        site98.com     site98.com/xy                4 s
        site97.com     site97.com/xyx               4 p
        site94.com     site94.com/xyxy              4 s
        site93.com     site93.com/xyxyx             4 p
        site29.com     site29.com/xyxyxy            4 p
        site44.com     site44.com/xyxyxyx           4 p
        site91.com     site91.com/4.5.6.7           4 s
        site80.com     site80.com/4.5.6.7           4 s
        site55.com     site55.com/4.5.6.7           4 s
        site85.com     site85.com/ip_is_4.5.6.7_    4 s
        site43.com     site43.com/2604::89          6 s
    '''
    myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
    myorigin.myorigin.http_get.pytest = 1  # mock http_get()
    args = myorigin.MyoriginArgs()
    args.dbfile = '-'
    args.log_level = 3
    args.ip_version = 4
    args.minimum_match = 5
    caplog.clear()
    myorigin.my_ip(args)
    assert 'not enough providers for 5 matches' in caplog.text
    args.ip_version = 6
    args.minimum_match = 2
    caplog.clear()
    myorigin.my_ip(args)
    assert 'not enough providers for 2 matches' in caplog.text
    args.minimum_match = 1
    assert myorigin.my_ip(args) == '2604::89'
    caplog.clear()
    myorigin.parrots.Parrot.show_parrot_db(myorigin.myorigin.init_db.engine)
    captured = capsys.readouterr()
    expected_parrot_db = '''
        ipv6.https://site43.com/2604::89:
            100% success rate (2 of 2)
            290 ms average round trip time
            score: 122 points
        ipv4.https://site91.com/4.5.6.7:
            100% success rate (1 of 1)
            290 ms average round trip time
            score: 122 points
        ipv4.https://site85.com/ip_is_4.5.6.7_:
            100% success rate (1 of 1)
            290 ms average round trip time
            score: 122 points
        ipv4.https://site80.com/4.5.6.7:
            100% success rate (1 of 1)
            290 ms average round trip time
            score: 122 points
        ipv4.https://site55.com/4.5.6.7:
            100% success rate (1 of 1)
            290 ms average round trip time
            score: 122 points
        ipv4.https://site98.com/xy:
            0% success rate (0 of 1)
            most recent error: Only 2 bytes received
            score: 10 points
        ipv4.https://site94.com/xyxy:
            0% success rate (0 of 1)
            most recent error: No IP address found
            score: 10 points
        ipv4.http://site97.com/xyx:
            0% success rate (0 of 1)
            most recent error: No IP address found
            score: 10 points
        ipv4.http://site93.com/xyxyx:
            0% success rate (0 of 1)
            most recent error: No IP address found
            score: 10 points
        ipv4.http://site62.com/x:
            0% success rate (0 of 1)
            most recent error: Only 1 bytes received
            score: 10 points
        ipv4.http://site44.com/xyxyxyx:
            0% success rate (0 of 1)
            most recent error: No IP address found
            score: 10 points
        ipv4.http://site29.com/xyxyxy:
            0% success rate (0 of 1)
            most recent error: No IP address found
            score: 10 points
    '''
    assert captured.out == textwrap.dedent(expected_parrot_db[1:])
    del myorigin.myorigin.http_get.pytest


def test_my_ip_set7(caplog, capsys) -> None:
    while True:  # loop until weighted_random() selects at least one bad IP address
        myorigin.myorigin.init_db.__dict__.pop('engine', None)  # force Parrot.startup() to re-run
        test_flock_data = '''
            site51.com     site51.com/118.4.122.98      4 p
            site52.com     site52.com/170.250.18.80     4 p
            site53.com     site53.com/118.4.122.98      4 p
            site54.com     site54.com/118.4.122.98      4 p
            site55.com     site55.com/118.4.122.98      4 p
            site56.com     site56.com/118.4.122.98      4 p
            site57.com     site57.com/170.250.18.80     4 p
            site58.com     site58.com/118.4.122.98      4 p
        '''
        myorigin.parrots.Parrot.startup.pytest = textwrap.dedent(test_flock_data)
        myorigin.myorigin.http_get.pytest = 1  # mock http_get()
        args = myorigin.MyoriginArgs()
        args.dbfile = '-'
        args.minimum_match = 5
        args.log_level = 4
        args.ip_version = 4
        args.majority_ratio = 3  # 2 of '170.250.18.80', so need 6 to override
        assert (
            myorigin.my_ip(args) == '118.4.122.98'
        )  # rarely a test will succeed without receiving bad::18
        myorigin.parrots.Parrot.show_parrot_db(myorigin.myorigin.init_db.engine)
        captured = capsys.readouterr()
        matches = ""
        expected_parrot_db = '''
            ipv4.http://site51.com/118.4.122.98:
                100% success rate (1 of 1)
                290 ms average round trip time
                score: 122 points
        '''
        t = expected_parrot_db
        matches += "A" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site51', 'site53')
        matches += "B" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site51', 'site54')
        matches += "C" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site51', 'site55')
        matches += "D" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site51', 'site56')
        matches += "E" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site51', 'site58')
        matches += "F" if textwrap.dedent(t[1:]) in captured.out else "."
        expected_parrot_db = '''
            ipv4.http://site52.com/170.250.18.80:
                0% success rate (0 of 1)
                most recent error: Incorrect IP returned: 170.250.18.80
                score: 10 points
        '''
        t = expected_parrot_db
        matches += "G" if textwrap.dedent(t[1:]) in captured.out else "."
        t = expected_parrot_db.replace('site52', 'site57')
        matches += "H" if textwrap.dedent(t[1:]) in captured.out else "."
        dots = matches.count(".")  # a dot represents unmodified site data
        assert dots == 3 or dots == 2 or dots == 0, f"matches is {matches}"
        if "G" in matches or "H" in matches:  # testing sufficient if it included an incorrect IP
            break  # testing sufficient if it included an incorrect IP
    del myorigin.myorigin.http_get.pytest


def test_weighted_random() -> None:
    random.seed('YLLMFHALDNRHISAEIFHIAE')  # predictable 'random' results
    o = {200: 5, 202: 10, 203: 11, 210: 1, 214: 10}
    n = 100  # number of iterations (10000 would make o and r values closer but take much longer)
    h = [k for k in [myorigin.myorigin.weighted_random(o) for i in range(n * sum(o.values()))]]
    r = dict(sorted({i: h.count(i) / n for i in h}.items()))
    assert r == {200: 5.06, 202: 9.85, 203: 10.76, 210: 0.85, 214: 10.48}
    random.seed()  # make unpredictable again so other tests cover a broader range
