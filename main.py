#!/usr/bin/env python3

import asyncio
from enum import Enum
from sre_constants import SUCCESS
import aiohttp
from dataclasses import dataclass
import logging
from optparse import OptionParser  # https://docs.python.org/3/library/optparse.html
import random
import re
import os
from typing import Optional
import warnings
from sqlmodel import Field, Session, SQLModel, create_engine, select
from grep_ips import GrepIPs

parser = OptionParser(usage="usage: %prog [options]")
parser.add_option(
    "-t",
    "--timeout",
    action="store",
    type="int",
    default=12000,
    help="timeout for http and https requests, in milliseconds, default is 12000",
)
parser.add_option(
    "-m",
    "--minimum-match",
    action="store",
    type="int",
    default=2,
    help="minimum number of identical responses, default is 2",
)
parser.add_option(
    "-l",
    "--logfile",
    action="store",
    type="string",
    default='-',
    help="path for log file, default is '-' (write to terminal)",
)
parser.add_option(
    "-q",
    "--quiet",
    action="store_const",
    const=0,
    dest="verbose",  # mapping:  "-q"->ERROR / ""->WARNING / "-v"->INFO / "-vv"->DEBUG
    help="silence error messages",
)
parser.add_option(
    "-v",
    "--verbose",
    action="count",
    default=1,
    help="increase verbosity",
)
(options, args) = parser.parse_args()
if len(args) != 0:
    parser.error("incorrect number of arguments")
logging.basicConfig(
    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    filename=options.logfile if options.logfile != '-' else None,
    filemode='a',
)
logger = logging.getLogger(__name__)
log_levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
logger.setLevel(log_levels[options.verbose])


def http_timeout():
    # ClientTimeout docs: https://docs.aiohttp.org/en/stable/client_reference.html#clienttimeout
    give_up_after = float(options.timeout) / 1000
    return aiohttp.ClientTimeout(sock_connect=give_up_after, sock_read=give_up_after)


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


async def http_get(url, session, max_size=-1):
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
    except aiohttp.ClientError as e:
        raise ValueError(str(e))


@dataclass
class FetchedIP:
    url: str = ''  # URL of server
    ip: str = ''  # IP address returned by server or error message
    rtt: int = 0  # total milliseconds needed for request or 0 for error


async def get_ip(url, session):
    fip = FetchedIP()
    fip.url = url
    try:
        html, ms = await http_get(url, session, max_size=16384)  # don't download it all
    except ValueError as e:
        fip.ip = str(e)
        return fip
    if len(html) < 3:
        fip.ip = f"Only {len(html)} bytes received"
        return fip
    ip = GrepIPs.grep_ips(html, global_ips_only=True, first_match_only=True)
    if ip is None:
        ip = GrepIPs.grep_ips(html, global_ips_only=False, first_match_only=True)
        if ip is None:
            fip.ip = "No IP address found"
        else:
            fip.ip = f"Found non-global IP address {ip}"
        return fip
    fip.ip = str(ip)
    fip.rtt = ms
    return fip


class Ptask(Enum):
    IP_HTTP = 'I'  # get IP via http
    IP_HTTPS = 'J'  # get IP via https
    IP_DNS = 'D'  # get IP via DNS (not yet implemented)
    IP_STUN = 'S'  # get IP via STUN (not yet implemented)
    MD_HTTP = 'M'  # get IP metadata via http (not yet implemented)
    MD_HTTPS = 'N'  # get IP metadata via https (not yet implemented)


provider_data = '''
# **Do not change or reuse IDs** (first column) because they are used to revise rows in
# existing databases.
#
# fields: ID address Ptasks

00 icanhazip.com/                              I J
01 ip1.dynupdate.no-ip.com/                    I
02 myip.dnsomatic.com/                         I J
03 smart-ip.net/myip                                       # cannot connect
04 ipecho.net/plain                              J
05 ident.me/                                   I J M N     # https://api.ident.me/
06 tnedi.me/                                   I J M N     # https://ipa.tnedi.me/
07 ip.appspot.com/                             I J
08 checkip.dyndns.org/                         I
09 www.lawrencegoetz.com/programs/ipinfo/                  # no API
10 shtuff.it/myip/short/                                   # cannot connect
11 ifconfig.me/ip                              I J
12 www.google.com/search?q=my+ip                           # 403 Forbidden
13 bot.whatismyipaddress.com/                              # API discontinued "due to massive abuse"
14 ipv4.ipogre.com/                                        # Connection timeout
15 automation.whatismyip.com/n09230945.asp                 # API discontinued?
16 myipis.net/                                             # API discontinued?
17 www.ipchicken.com/                            J
18 myip.com.tw/                                  J
19 httpbin.org/ip                              I J
20 ip.nf/me.txt                                  J   N
21 am.i.mullvad.net/ip                           J
22 am.i.mullvad.net/json                             N     # https://mullvad.net/en/check/
23 zx2c4.com/ip                                I J
24 ip.websupport.sk/                           I J
25 www.ivpn.net/                                 J
26 www.ipaddress.com/                                      # API discontinued?
27 www.ipaddress.my/                             J
28 www.showmyip.com/                                       # no API
29 ip-api.com/line/?fields=query               I
30 ip-api.com/json/?fields=16966359                M       # https://ip-api.com/docs/
31 api.ipify.org/                              I J
32 ifconfig.io/ip                              I J
33 ipaddress.sh/                               I J
34 api.iplocation.net/?ip={ip}                       N     # https://api.iplocation.net/
35 ipinfo.io/ip                                I J
36 ipinfo.io/{ip}/json                               N
37 api.ipregistry.co/?key=tryout                 J   N     # https://ipregistry.co/docs/
38 myexternalip.com/raw                        I J
39 checkip.amazonaws.com/                      I J
40 diagnostic.opendns.com/myip                             # cannot connect
41 whatismyip.akamai.com/                                  # cannot connect
42 test-ipv6.com/ip/                           I J         # works for IPv4 too
43 api.infoip.io/                              I J M N     # https://ciokan.docs.apiary.io/
44 checkip.dns.he.net/                         I J
45 ipapi.co/ip                                   J
46 www.cloudflare.com/cdn-cgi/trace            I J
47 www.trackip.net/ip                          I J
48 www.trackip.net/ip?json                         M N
49 mypubip.com/                                I J
50 ip.seeip.org/                                 J
51 ip.seeip.org/geoip                              M N
52 api.bigdatacloud.net/data/client-ip         I J
53 myip.opendns.com%20A%20@resolver1.opendns.com       D  
54 o-o.myaddr.l.google.com%20TXT%20@8.8.8.8            D  
55 whoami.akamai.net%20ANY%20@ns1-1.akamaitech.net     D  
'''


class Api_provider(SQLModel, table=True):
    id: int = Field(primary_key=True)
    ptask: str  # one of: 'I', 'J', 'D', 'S', 'M', 'N'
    address: str  # host+path (URL without protocol)
    milliweight: int = 1000  # 2000 means 2x more likely to be used; 0 means disabled
    attempt_count: int = 0  # number of attempted connections
    success_count: int = 0  # number of valid IP addresses returned
    total_rtt: int = 0  # total rtt (in ms) for all successful attempts
    last_errmsg: str = ""

    @staticmethod
    def startup():
        # with Session(engine) as session:
        #     provider_count = session.query(Api_provider).count()
        # if provider_count == 0:  # empty database
        with Session(engine) as session:
            for line in provider_data.split('\n'):
                wout_comments = re.sub(
                    r'( +|^)#.*\n?', '', line
                )  # strip comments and preceding spaces
                if len(wout_comments) == 0:
                    continue
                fields = re.sub(r' +', ' ', wout_comments).split(' ')
                assert len(fields) >= 2, f"invalid provider_data line: {line}"
                # do not adjust the Ptask list here except to append; .id is computed from it
                for i, ptask in enumerate([Ptask.IP_HTTP, Ptask.IP_HTTPS]):
                    # uniquely id each row so we can safely copy future changes
                    id = 2018264000 + int(fields[0]) * 10 + i
                    address = fields[1]
                    statement = select(Api_provider).where(Api_provider.id == id)
                    result = session.exec(statement).one_or_none()
                    if result is None:  # no existing row in DB
                        if ptask.value not in fields[2:]:  # Ptask inactive
                            continue
                        result = Api_provider()  # add new row to database for this Ptask
                        result.id = id
                    else:  # existing row in DB
                        if ptask.value not in fields[2:]:  # Ptask inactive
                            result.milliweight = 0  # disable Ptask in DB
                        else:
                            result.milliweight = 1000
                    result.ptask = ptask.value
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
        logger.debug(f"{self.url()}:")
        if self.attempt_count != 0:
            percent = round(100.0 * self.success_count / self.attempt_count)
            logger.debug(
                f"    {percent}% success rate ({self.success_count} of {self.attempt_count})"
            )
        else:
            percent = 100
            logger.debug(f"    not yet attempted")
        if self.success_count != 0:
            average_ms = round(1.0 * self.total_rtt / self.success_count)
            logger.debug(f"    {average_ms} ms average round trip time")
        else:
            average_ms = options.timeout
        if len(self.last_errmsg) > 0:
            logger.debug(f"    most recent error: {self.last_errmsg}")
        score = percent  # biggest portion of score is success rate
        score += 5  # every provider gets a small chance of being selected
        if self.attempt_count < 10:
            score += 5  # prefer new providers
        score += round((options.timeout - average_ms) / 200)  # prefer faster providers
        score *= self.milliweight  # normally 1000, but can be 0 to disable or more to promote
        logger.debug(f"    score: {score:,} points")
        return score


def weighted_random(options):
    # return the index of a randomly-chosen list item with the probability represented by the value
    total = sum(options)
    for i, weight in enumerate(options):
        if random.randint(0, total - 1) < weight:
            return i
        total -= weight
    assert False, f"bug in weighted_random, options {options}"


async def main():
    with Session(engine) as db_session:
        provider_scores = list()
        provider_ids = list()
        all_providers = db_session.exec(select(Api_provider))
        for p in all_providers:
            score = p.score()
            if score <= 0:
                continue
            provider_scores.append(score)
            provider_ids.append(p.id)
        # choose some providers at random
        jobs = list()
        thechosen = list()
        connector = aiohttp.TCPConnector(limit=10)  # limit total number of simultaneous connections
        async with aiohttp.ClientSession(
            connector=connector, timeout=http_timeout(), trace_configs=[http_timer()]
        ) as aio_session:
            logger.info(f"{options.minimum_match + 1} requests:")
            while True:
                chosen_i = weighted_random(provider_scores)
                statement = select(Api_provider).where(Api_provider.id == provider_ids[chosen_i])
                chosen_p = db_session.exec(statement).one_or_none()
                assert chosen_p is not None
                del provider_scores[chosen_i]  # ensure we don't choose this one again
                del provider_ids[chosen_i]
                thechosen.append(chosen_p)
                jobs.append(asyncio.ensure_future(get_ip(chosen_p.url(), aio_session)))
                await asyncio.sleep(0.0001)
                if len(jobs) >= options.minimum_match + 1:
                    break
                assert len(provider_scores) > 0, "not enough providers for options.minimum_match"
            responses = await asyncio.gather(*jobs)
            assert len(thechosen) == len(responses)
            assert len(thechosen) == options.minimum_match + 1
            ip_counts = dict()
            for i, r in enumerate(responses):  # update DB with response results
                assert r.url == thechosen[i].url()
                thechosen[i].attempt_count += 1
                if r.rtt != 0:  # got valid IP
                    ip_counts[r.ip] = ip_counts.get(r.ip, 0) + 1
                    thechosen[i].success_count += 1
                    thechosen[i].total_rtt += r.rtt
                    portion = f"{thechosen[i].success_count} of {thechosen[i].attempt_count}"
                    logger.info(f"    {r.url} → {r.ip} ({r.rtt} ms; {portion} succeeded)")
                else:
                    thechosen[i].last_errmsg = r.ip
                    portion = f"{thechosen[i].success_count} of {thechosen[i].attempt_count}"
                    logger.info(f"    {r.url} → {r.ip[:40]} ({portion} succeeded)")
                db_session.add(thechosen[i])
                db_session.commit()
            keys = list(ip_counts.keys())
            if len(keys) > 1:
                logger.error(f"multiple IPs received: {ip_counts}")
            elif ip_counts[keys[0]] < options.minimum_match:
                logger.warning(
                    f"{options.minimum_match} matches requested; only {ip_counts[keys[0]]} received"
                )
            else:
                logger.info(f"IP: {keys[0]} (received {ip_counts[keys[0]]} times)")
                print(keys[0])
        connector.close()


if __name__ == "__main__":
    GrepIPs.grep_ips_test()
    warnings.filterwarnings(  # https://github.com/tiangolo/sqlmodel/issues/189#issuecomment-1018014753
        "ignore", ".*Class SelectOfScalar will not make use of SQL compilation caching.*"
    )
    db_file = os.path.join(os.getenv('HOME'), '.origin-ip.sqlite')
    engine = create_engine(f'sqlite:///{db_file}', echo=False)
    SQLModel.metadata.create_all(engine)
    Api_provider.startup()
    results = asyncio.run(main())
