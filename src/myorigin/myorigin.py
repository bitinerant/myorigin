import asyncio
from enum import Enum
import aiohttp
from dataclasses import dataclass
import ipaddress
import logging
import platformdirs
import random
import re
import socket
import os
from typing import Optional
import warnings
from sqlmodel import Field, Session, SQLModel, create_engine, select
from grep_ips.grep_ips import GrepIPs


def cli():
    import argparse  # https://docs.python.org/3/library/argparse.html

    formatter_class = lambda prog: argparse.HelpFormatter(prog, max_help_position=33)
    parser = argparse.ArgumentParser(
        description="Fast, fault-tolerant public IP address retrieval from Python or CLI.",
        formatter_class=formatter_class,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=12000,
        help="approximate timeout for http and https requests in milliseconds (default: 12000)",
    )
    parser.add_argument(
        "--minimum-match",
        type=int,
        default=2,
        help="an IP address is considered valid after this number of idential responses (default: 2)",
    )
    parser.add_argument(
        "--overkill",
        type=int,
        default=0,
        help="number of initial requests to make beyond minimum-match (default: 0)",
    )
    parser.add_argument(
        "--max-failures",
        type=int,
        default=10,
        help="maximum number of failed requests allowed (default: 10)",
    )
    parser.add_argument(
        "--show-api-providers",
        action='store_true',
        help="display the database of IP address API providers in a human-readable form and exit",
    )
    parser.add_argument(
        "-4",
        "--ipv4",
        action='store_true',
        help="use IPv4 only",
    )
    parser.add_argument(
        "-6",
        "--ipv6",
        action='store_true',
        help="use IPv6 only",
    )
    parser.add_argument(
        "-l",
        "--logfile",
        type=str,
        default='-',
        help="path for log file (default: write to STDERR)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action='append_const',
        const=-1,
        dest="verbose",  # mapping:  "-q"->ERROR / ""->WARNING / "-v"->INFO / "-vv"->DEBUG
        help="silence warning messages",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action='append_const',
        const=1,
        help="increase verbosity",
    )
    args = parser.parse_args()
    if args.show_api_providers:
        Parrot.show_parrot_db()
        return
    del args.show_api_providers
    if args.ipv4:
        args.ip_version = 4
    if args.ipv6:
        args.ip_version = 6
    del args.ipv4
    del args.ipv6
    args.log_level = 2 + (0 if args.verbose is None else sum(args.verbose))
    del args.verbose
    moa = MyoriginArgs(**args.__dict__)
    print(my_ip(moa))


@dataclass
class MyoriginArgs:
    timeout: int = 12000
    minimum_match: int = 2
    overkill: int = 0
    max_failures: int = 10
    ip_version: int = 0  # 0==either, 4==IPv4 only, 6==IPv6 only
    logfile: str = '-'
    log_level: int = 0  # 0==disabled, 1==errors, 2==warnings, 3==info, 4==debug


def my_ip(args: MyoriginArgs) -> str:
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
        filename=args.logfile if args.logfile != '-' else None,
        filemode='a',
    )
    logger = logging.getLogger(__name__)
    log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    try:
        logger.setLevel(log_levels[args.log_level])
    except IndexError:
        logger.setLevel(logging.WARNING)
        logger.error(f"Invalid log level")
        return ""
    return asyncio.run(main_loop(args, logger))


def http_timeout(t):
    # ClientTimeout docs: https://docs.aiohttp.org/en/stable/client_reference.html#clienttimeout
    give_up_after = float(t) / 1000
    return aiohttp.ClientTimeout(
        # total=give_up_after,  # don't use this because it includes the time in queue
        sock_connect=give_up_after,
        sock_read=give_up_after,
    )


async def timer_mark(session, context, params):
    context.trace_request_ctx.append(asyncio.get_event_loop().time())


def http_timer():  # configure signals to record beginning and end of http requests
    trace_config = aiohttp.TraceConfig()
    # on_connection_queded_end → not called if a connection is immediately available
    # on_connection_reuseconn, on_connection_create_start → exactly one of these is always called
    # on_request_headers_sent.append → always called
    # on_request_end.append → always called
    trace_config.on_connection_reuseconn.append(timer_mark)  # start timer
    trace_config.on_connection_create_start.append(timer_mark)  # start timer
    trace_config.on_request_end.append(timer_mark)  # stop timer
    return trace_config


async def http_get(url: str, session: aiohttp.ClientSession, max_size=-1, ip_version=0):
    timer_marks = list()
    # change user agent string for better site compatibility
    # via: wget -O- -q http://httpbin.org/get |grep User-Agent
    headers = {'User-Agent': 'Wget/1.20.3 (linux-gnu)'}
    # headers = {'User-Agent': 'Python/3.8 aiohttp/3.8.1'}  # default on my system
    try:
        async with session.get(
            url,
            allow_redirects=False,
            trace_request_ctx=timer_marks,
            headers=headers,
        ) as response:
            if response.status != 200:
                raise aiohttp.ClientError(f"{response.status} {response.reason}")
            html = str((await response.content.read(max_size)).decode())
            assert len(timer_marks) == 2
            # SQLite max int is 2^63 ms, or 500000 requests per second for 100 years
            ms = round((timer_marks[1] - timer_marks[0]) * 1000)
            return html, ms
    # exceptions here seem to cause infinite loop (¿bug in my code?), e.g. trying "httpss://" url
    except Exception as e:  # most will be aiohttp.ClientError
        s = str(e)
        raise ValueError(s if len(s) > 1 else "Unknown exception in http_get()")


class Parrot(SQLModel, table=True):  # data for one interface of an API provider
    # (Parrots repeats what they hear. A my-IP API provider repeats the callers IP back to them.)
    id: int = Field(primary_key=True)
    ptask: str  # one of: 'I', 'J', 'D', 'S', 'M', 'N'
    ip_version: int  # always 4 or 6
    address: str  # host+path (URL without protocol)
    milliweight: int = 1000  # 2000 means 2x more likely to be used; 0 means disabled
    attempt_count: int = 0  # number of attempted connections
    success_count: int = 0  # number of valid IP addresses returned
    total_rtt: int = 0  # total rtt (in ms) for all successful attempts
    last_errmsg: str = ""

    @staticmethod
    def startup():
        with Session(engine) as session:
            for line in parrot_data.split('\n'):
                wout_comments = re.sub(r'( +|^)#.*\n?', '', line)  # strip comments
                if len(wout_comments) == 0:
                    continue
                fields = re.sub(r' +', ' ', wout_comments).split(' ')
                assert len(fields) >= 3, f"invalid parrot_data line: {line}"
                # do not adjust the Ptask list here except to append; .id is computed from it
                for i, ptask in enumerate([Ptask.IP_HTTP, Ptask.IP_HTTPS]):
                    address = fields[1]
                    ip_version = int(fields[2])
                    for v in (4, 6):  # IPv4, IPv6
                        ip_version_offset = 0 if v == 4 else 50  # IPv4 uses 0-49, IPv6 uses 50-99
                        id = 2018260000 + int(fields[0]) * 100 + ip_version_offset + i
                        statement = select(Parrot).where(Parrot.id == id)
                        result = session.exec(statement).one_or_none()
                        ptask_active = ptask.value in fields[3:]
                        ip_version_active = ip_version == 0 or ip_version == v
                        if result is None:  # no existing row in DB
                            if not (ptask_active and ip_version_active):
                                continue  # not in DB and shouldn't be
                            result = Parrot()  # add new row to database for this Ptask
                            result.id = id
                        else:  # existing row in DB
                            if not (ptask_active and ip_version_active):
                                result.milliweight = 0  # disable in DB
                            else:
                                result.milliweight = 1000  # make sure it is enabled
                        result.ptask = ptask.value
                        result.ip_version = v
                        result.address = address
                        session.add(result)
            session.commit()

    def url(self):
        if self.ptask == Ptask.IP_HTTP.value:
            return 'http://' + self.address
        if self.ptask == Ptask.IP_HTTPS.value:
            return 'https://' + self.address
        assert ValueError, f"Ptask {Ptask(self.ptask).name} not yet implemented"

    def score(self):  # compute a score which will determine how likely it is to be chosen
        if self.attempt_count != 0:
            percent = 100.0 * self.success_count / self.attempt_count
        else:
            percent = 100.0
        score = round(percent**2 / 100.0)  # biggest portion of score is success rate
        score += 5  # every parrot gets a small chance of being selected
        if self.attempt_count < 10:
            score += 5  # prefer new parrots
        if self.success_count != 0:
            average_ms = 1.0 * self.total_rtt / self.success_count
            score += round(max((5000 - average_ms) / 400, 0.0))  # prefer faster parrots
        score *= self.milliweight  # normally 1000, but can be 0 to disable or more to promote
        return score

    @staticmethod
    def show_parrot_db():
        with Session(engine) as session:
            to_show = dict()
            results = session.exec(select(Parrot))
            for p in results:
                score = p.score()
                disp = ""
                disp += f"ipv{p.ip_version}.{p.url()}:\n"
                if p.attempt_count != 0:
                    percent = round(100.0 * p.success_count / p.attempt_count)
                    disp += f"    {percent}% success rate"
                    disp += f" ({p.success_count} of {p.attempt_count})\n"
                else:
                    disp += f"    not yet attempted\n"
                if p.success_count != 0:
                    average_ms = round(1.0 * p.total_rtt / p.success_count)
                    disp += f"    {average_ms} ms average round trip time\n"
                if len(p.last_errmsg) > 0:
                    disp += f"    most recent error: {p.last_errmsg[:70]}\n"
                disp += f"    score: {round(score/1000):,} points\n"
                to_show[score * 1000000 + p.id] = disp  # sortable, unique key
            for p in dict(sorted(to_show.items(), reverse=True)):
                print(to_show[p], end="")


@dataclass
class FetchedIP:
    parrot: Parrot
    ip: str = ''  # IP address returned by server or error message
    ip_version: int = 0  # 0==none, 4==IPv4, 6==IPv6
    rtt: int = 0  # total milliseconds needed for request or 0 for error


async def get_ip(
    p: Parrot, session: aiohttp.ClientSession, q: asyncio.Queue, ip_version: int = 0
) -> None:
    fip = FetchedIP(p)
    a = None
    try:
        html, ms = await http_get(
            p.url(),
            session,
            max_size=16384,  # don't download it all
        )
    except ValueError as e:
        a = str(e)
        if a == '':
            a = "Unknown http_get() error"
    if a is None and len(html) < 3:
        a = f"Only {len(html)} bytes received"
    if a is None:
        ip = GrepIPs.grep_ips(
            html,
            global_ips_only=True,
            first_match_only=True,
            ip_version=ip_version,
        )
        if ip is not None:
            a = str(ip)
            fip.ip_version = 4 if type(ip) == ipaddress.IPv4Address else 6
            fip.rtt = ms
    if a is None:
        # call grep_ips() again to be able to give a more specific error message
        ip = GrepIPs.grep_ips(
            html,
            global_ips_only=False,
            first_match_only=True,
            ip_version=ip_version,
        )
        if ip is None:
            a = "No IP address found"
        else:
            a = f"Found non-global IP address {ip}"
    fip.ip = a
    await q.put(fip)


class Ptask(Enum):
    IP_HTTP = 'I'  # get IP via http
    IP_HTTPS = 'J'  # get IP via https
    IP_DNS = 'D'  # get IP via DNS (not yet implemented)
    IP_STUN = 'S'  # get IP via STUN (not yet implemented)
    MD_HTTP = 'M'  # get IP metadata via http (not yet implemented)
    MD_HTTPS = 'N'  # get IP metadata via https (not yet implemented)


parrot_data = '''
# **Do not change or reuse IDs** (fields[0])

# fields[0] → parrot number (always unique so we can safely copy future changes to user's DB)
# fields[1] → parrot address (URL without 'https://' or 'http://')
# fields[2] → ip version (0==both, 4==IPv4 only, 6==IPv6 only)
# fields[3:] → Ptask list

# currently, each row can expand to 4 database rows (2 IP versions × http vs. https)

00 icanhazip.com/                            0 I J
01 ip1.dynupdate.no-ip.com/                  0 I
02 myip.dnsomatic.com/                       0 I J
03 smart-ip.net/myip                         0             # cannot connect
04 ipecho.net/plain                          0   J
05 ident.me/                                 0 I J M N     # https://api.ident.me/
06 tnedi.me/                                 0 I J M N     # https://ipa.tnedi.me/
07 ip.appspot.com/                           0 I J
08 checkip.dyndns.org/                       0 I
09 www.lawrencegoetz.com/programs/ipinfo/    0             # no API
10 shtuff.it/myip/short/                     0             # cannot connect
11 ifconfig.me/ip                            0 I J
12 www.google.com/search?q=my+ip             0             # 403 Forbidden
13 bot.whatismyipaddress.com/                0             # API discontinued "due to massive abuse"
14 ipv4.ipogre.com/                          0             # Connection timeout
15 automation.whatismyip.com/n09230945.asp   0             # API discontinued?
16 myipis.net/                               0             # API discontinued?
17 www.ipchicken.com/                        0   J
18 myip.com.tw/                              0   J
19 httpbin.org/ip                            0 I J
20 ip.nf/me.txt                              0   J   N
21 am.i.mullvad.net/ip                       0   J
22 am.i.mullvad.net/json                     0       N     # https://mullvad.net/en/check/
23 zx2c4.com/ip                              0 I J
24 ip.websupport.sk/                         0 I J
25 www.ivpn.net/                             0   J
26 www.ipaddress.com/                        0             # API discontinued?
27 www.ipaddress.my/                         0   J
28 www.showmyip.com/                         0             # no API
29 ip-api.com/line/?fields=query             0 I
30 ip-api.com/json/?fields=16966359          0     M       # https://ip-api.com/docs/
31 api.ipify.org/                            0 I J
32 ifconfig.io/ip                            0 I J
33 ipaddress.sh/                             0 I J
34 api.iplocation.net/?ip={ip}               0       N     # https://api.iplocation.net/
35 ipinfo.io/ip                              0 I J
36 ipinfo.io/{ip}/json                       0       N
37 api.ipregistry.co/?key=tryout             0 I J   N     # https://ipregistry.co/docs/
38 myexternalip.com/raw                      0 I J
39 checkip.amazonaws.com/                    0 I J
40 diagnostic.opendns.com/myip               0             # cannot connect
41 whatismyip.akamai.com/                    0             # cannot connect
42 test-ipv6.com/ip/                         0 I J         # works for IPv4 too
43 api.infoip.io/                            0 I J M N     # https://ciokan.docs.apiary.io/
44 checkip.dns.he.net/                       0 I J
45 ipapi.co/ip                               0   J
46 www.cloudflare.com/cdn-cgi/trace          0 I J
47 www.trackip.net/ip                        0 I J
48 www.trackip.net/ip?json                   0     M N
49 mypubip.com/                              0 I J
50 ip.seeip.org/                             0   J
51 ip.seeip.org/geoip                        0     M N
52 api.bigdatacloud.net/data/client-ip       0 I J
53 myip.opendns.com%20A%20@resolver1.opendns.com   0   D  
54 o-o.myaddr.l.google.com%20TXT%20@8.8.8.8        0   D  
55 whoami.akamai.net%20ANY%20@ns1-1.akamaitech.net 0   D  
'''


def weighted_random(options: dict):
    # return a randomly-chosen key with the probability represented by its value
    total = sum(options.values())
    for k, weight in options.items():
        if random.randint(0, total - 1) < weight:
            return k
        total -= weight
    assert False, f"bug in weighted_random, options {options}"
    # #test:
    # o = {200: 5, 202: 10, 203: 11, 210: 1, 214: 10}
    # n = 1000  # number of iterations
    # h = [k for k in [weighted_random(o) for i in range(n*sum(o.values()))]]
    # r = dict(sorted({i:h.count(i)/n for i in h}.items()))
    # #visually compare o and r


class DoneWithJobs(Exception):
    pass


async def main_loop(args: MyoriginArgs, logger: logging.Logger) -> str:
    result = ""
    with Session(engine) as db_session:
        scores = dict()
        if args.ip_version == 0:
            statement = select(Parrot)
        else:  # if user wants IPv4 only, ignore IPv6 DB rows; vice-versa
            statement = select(Parrot).where(Parrot.ip_version == args.ip_version)
        all_parrots = db_session.exec(statement)
        for p in all_parrots:
            score = p.score()
            if score <= 0:
                continue
            scores[p.id] = score
        q = asyncio.Queue()  # great tutorial: https://realpython.com/async-io-python/
        if args.ip_version == 0:
            ip_family = 0
        elif args.ip_version == 4:
            ip_family = socket.AF_INET
        elif args.ip_version == 6:
            ip_family = socket.AF_INET6
        else:
            assert False
        connector = aiohttp.TCPConnector(  # https://docs.aiohttp.org/en/stable/client_reference.html#tcpconnector
            limit=10,  # limit total number of simultaneous connections
            family=ip_family,
        )
        async with aiohttp.ClientSession(
            connector=connector, timeout=http_timeout(args.timeout), trace_configs=[http_timer()]
        ) as aio_session:
            try:
                logger.info(f"requests (need {args.minimum_match} matches):")
                pending_jobs_count = 0
                ip_counts = dict()
                ip_counts[4] = dict()  # number of occurrences for each received IPv4
                ip_counts[6] = dict()  # number of occurrences for each received IPv6
                fail_count = 0
                while True:  # spawn and collect jobs
                    max_ipv0_count = 0  # max of IPv4 and IPv6
                    for v in (4, 6):
                        max_ip_count = 0 if len(ip_counts[v]) == 0 else max(ip_counts[v].values())
                        # FIXME: for multiple IPs, maybe ensure most_common >= second_most_common + minimum_match more
                        if len(ip_counts[v]) > 1:
                            logger.error(f"multiple IPs received: {ip_counts[v]}")
                            raise DoneWithJobs
                        if max_ip_count >= args.minimum_match:  # we have sufficient results
                            ip = max(ip_counts[v], key=ip_counts[v].get)
                            msg = f"IP found: {ip} ({ip_counts[v][ip]} successes,"
                            logger.info(f"{msg} {fail_count} failures)")
                            result = ip
                            raise DoneWithJobs
                        max_ipv0_count = max(max_ipv0_count, max_ip_count)
                    # spawn another get_ip() job if needed
                    wanted_count = args.minimum_match + args.overkill
                    jobs_count = max_ipv0_count + pending_jobs_count
                    logger.debug(
                        f"have {max_ipv0_count} IPs plus {pending_jobs_count} pending,"
                        + f" want {wanted_count}, need {args.minimum_match}"
                    )
                    if args.overkill > 0 and wanted_count > jobs_count and len(scores) == 0:
                        msg = f"not enough parrots for {wanted_count} requests"
                        logger.warning(f"{msg}; ignoring '--overkill'")
                        args.overkill = 0
                        wanted_count = args.minimum_match + args.overkill
                    if wanted_count > jobs_count:
                        if len(scores) == 0:
                            logger.error(f"not enough parrots for {args.minimum_match} matches")
                            raise DoneWithJobs
                        p_id = weighted_random(scores)
                        statement = select(Parrot).where(Parrot.id == p_id)
                        p = db_session.exec(statement).one_or_none()
                        assert p is not None
                        del scores[p_id]  # ensure we don't choose this one again
                        # FIXME: ¿delete other scores[] for the same service?
                        logger.debug(f"launching task IPv{p.ip_version} {p.url()}")
                        asyncio.create_task(get_ip(p, aio_session, q, ip_version=args.ip_version))
                        pending_jobs_count += 1
                    await asyncio.sleep(0.0001)
                    # process completed jobs
                    try:
                        r: FetchedIP = q.get_nowait()  # may raise QueueEmpty
                        r.parrot.attempt_count += 1
                        if r.rtt != 0:  # got valid IP of some sort
                            if r.ip != '':
                                v = r.ip_version
                                ip_counts[v][r.ip] = ip_counts[v].get(r.ip, 0) + 1
                            r.parrot.success_count += 1
                            r.parrot.total_rtt += r.rtt
                            portion = f"{r.parrot.success_count} of {r.parrot.attempt_count}"
                            msg = f"    {r.parrot.url()} → {r.ip} ({r.rtt} ms;"
                            logger.info(f"{msg} {portion} succeeded)")
                        else:
                            r.parrot.last_errmsg = r.ip
                            portion = f"{r.parrot.success_count} of {r.parrot.attempt_count}"
                            msg = f"    {r.parrot.url()} → {r.ip[:40]}"
                            logger.info(f"{msg} ({portion} succeeded)")
                            fail_count += 1
                        pending_jobs_count -= 1
                        db_session.add(r.parrot)
                        db_session.commit()
                        if fail_count >= args.max_failures:
                            logger.error(f"{fail_count} requests failed; giving up")
                            raise DoneWithJobs
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.005)  # reduce looping when waiting on responses
                    await asyncio.sleep(0.0001)
            except DoneWithJobs:
                pass
        connector.close()
    return result


engine = None


def on_import():
    global engine
    appname = 'myorigin'
    GrepIPs.grep_ips_test()
    warnings.filterwarnings(  # https://github.com/tiangolo/sqlmodel/issues/189#issuecomment-1018014753
        "ignore", ".*Class SelectOfScalar will not make use of SQL compilation caching.*"
    )
    config_dir = platformdirs.user_config_dir(appname)
    try:
        os.mkdir(config_dir)
    except FileExistsError:
        pass
    # except (PermissionError, FileNotFoundError):
    #     one of these will be raised if the directory cannot be created
    db_file = os.path.join(config_dir, f'data.sqlite')
    engine = create_engine(f'sqlite:///{db_file}', echo=False)
    SQLModel.metadata.create_all(engine)
    Parrot.startup()


on_import()

if __name__ == "__main__":
    cli()
