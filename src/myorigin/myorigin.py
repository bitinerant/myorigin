import asyncio
import aiohttp
from collections import Counter
from dataclasses import dataclass
import ipaddress
import logging
import platformdirs
import random
import re
import socket
import os
from sqlmodel import Session, SQLModel, create_engine, select
import warnings
from grep_ips.grep_ips import GrepIPs
from .parrots import Parrot


def cli(return_help_text=False):
    import argparse  # https://docs.python.org/3/library/argparse.html

    help_width = 78 if return_help_text else None  # consistent width for README.py
    formatter_class = lambda prog: argparse.HelpFormatter(
        prog,
        max_help_position=37,
        width=help_width,
    )
    parser = argparse.ArgumentParser(
        prog=app_name(),
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
        help="an IP address is considered valid after this number of idential responses"
        + " (default: 2)",
    )
    parser.add_argument(
        "--overkill",
        type=int,
        default=0,
        help="number of initial requests to make beyond minimum-match (default: 0)",
    )
    parser.add_argument(
        "--majority-ratio",
        type=int,
        default=3,
        help="minimum ratio needed to overrule a conflicting response; must be an integer;"
        + " a value of 2 means 2:1, or that 6 responses of 8.7.8.7 are needed to overrule"
        + " 3 responses of 7.8.4.4 (default: 3)",
    )
    parser.add_argument(
        "--max-failures",
        type=int,
        default=10,
        help="maximum number of failed requests allowed (default: 10)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=10,
        help="maximum number of simultaneous network connections allowed (default: 10)",
    )
    db_file_display = db_pathname().replace(os.path.expanduser('~'), '~')
    parser.add_argument(
        "--dbfile",
        type=str,
        default='',  # need to call db_pathname() again later with create_dir=True
        help=f"path for database file ('-' for memory-only; default: {db_file_display})",
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
        help="use IPv4 only; note this or --ipv6 is highly recommended if both IPv4 and IPv6"
        + " are available, in order to avoid wasteful network traffic and unpredictable results"
        + " (sometimes --minimum-match IPv4 addresses will be received first, and"
        + " sometimes IPv6 will win)",
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
    if return_help_text:  # used by README.py
        return parser.format_help()
    args = parser.parse_args()
    if args.show_api_providers:
        engine = init_db(args.dbfile)
        Parrot.show_parrot_db(engine)
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
class MyoriginArgs:  # see '--help' for descriptions
    timeout: int = 12000
    minimum_match: int = 2
    overkill: int = 0
    majority_ratio: int = 3
    max_failures: int = 10
    max_connections: int = 10
    dbfile: str = ''  # ''==db_pathname(), '-'==none, other==alternate file
    ip_version: int = 0  # 0==either, 4==IPv4 only, 6==IPv6 only
    logfile: str = '-'
    log_level: int = 0  # 0==disabled, 1==errors, 2==warnings, 3==info, 4==debug
    exception_level = 0  # 0==disabled, 1==raise exception for errors, 2==... for warnings, etc.


def app_name():
    return os.path.splitext(os.path.basename(__file__))[0]


class NetworkError(Exception):
    pass


def my_ip(args: MyoriginArgs) -> str:
    if args.log_level >= 3:  # info or debug
        log_format = '%(asctime)s.%(msecs)03d %(levelname)s %(message)s'
    else:
        log_format = '%(message)s'
    logging.basicConfig(
        format=log_format,
        datefmt='%H:%M:%S',
        filename=args.logfile if args.logfile != '-' else None,
        filemode='a',
    )
    logger = logging.getLogger('myorigin')
    log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    try:
        logger.setLevel(log_levels[args.log_level])
    except IndexError:
        logger.setLevel(logging.WARNING)
        error = "Invalid log level"
        logger.error(error)
        if args.exception_level >= 1:
            raise ValueError(error)
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


async def http_get(url: str, session: aiohttp.ClientSession, max_size=-1):
    if hasattr(http_get, 'pytest'):  # mock responses; see myorigin_test.py
        if http_get.pytest == 1:
            try:
                return re.match(r'http.*/(.*)', url).group(1), 290  # whatever follows final slash
            except:
                return f'test html response with no IP address', 180
        elif http_get.pytest == 2:
            raise ValueError("404 pytest simulated error")
    timer_marks = list()
    # change user agent string for better site compatibility and anonymity, though one site
    # ... suggests a Firefox user agent (https://www.whatismyip.com/automation-rules/);
    # Wget agent retrieved via: wget -O- -q http://httpbin.org/get |grep User-Agent
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


def weighted_random(options: dict):
    # return a randomly-chosen key with the probability represented by its value
    total = sum(options.values())
    for k, weight in options.items():
        if random.randint(0, total - 1) < weight:
            return k
        total -= weight
    assert False, f"bug in weighted_random, options {options}"


def are_we_there_yet(completed_jobs, args, logger):
    top_ip_count = 0  # max of IPv4 and IPv6
    top_ip_target = args.minimum_match
    for v in (4, 6):
        fail_count = sum(1 for r in completed_jobs if r.rtt == 0)
        if fail_count >= args.max_failures:
            raise NetworkError(f"{fail_count} requests failed; giving up")
        votes = Counter([r.ip for r in completed_jobs if (r.ip_version == v and r.rtt != 0)])
        if len(votes) == 0:
            continue
        ranked = sorted(votes.items(), key=lambda i: i[1], reverse=True)
        # ranked[0][0] is #1 candidate IP; ranked[0][1] is its vote count
        assert sum(1 for r in completed_jobs if (r.rtt != 0 and r.ip == '')) == 0
        if len(ranked) > 1 and not hasattr(are_we_there_yet, 'found_multiple_ips'):
            are_we_there_yet.found_multiple_ips = True  # only show once
            logger.info(f"multiple IPs received: {[k[0] for k in ranked]}")
        overrule = 0 if len(ranked) <= 1 else ranked[1][1] * args.majority_ratio
        target = max(args.minimum_match, overrule)  # votes necessary to win
        if ranked[0][1] >= target:  # #1 candidate has enough votes
            ip = ranked[0][0]
            msg = f"IP found: {ip} ({ranked[0][1]} successes,"
            logger.info(f"{msg} {fail_count} failures)")
            if len(ranked) > 1:  # retroactively mark other candidates as failed
                for r in completed_jobs:
                    if r.ip_version == v and r.rtt != 0 and r.ip != ip:
                        r.rtt = 0  # actually, it failed
                        r.ip = f'Incorrect IP returned: {r.ip}'
            raise DoneWithJobs(ip)
            # logger.info(f"{fail_count} fails for {len(completed_jobs)} jobs")
        top_ip_count = max(top_ip_count, ranked[0][1])
        top_ip_target = max(top_ip_target, target)
    if top_ip_count == 0:
        are_we_there_yet.__dict__.pop('found_multiple_ips', None)  # show again if needed
    return top_ip_count, top_ip_target


def log_debug_details(logger, top_ip_count, pending_jobs_count, top_ip_bonus, top_ip_target):
    if logger.isEnabledFor(logging.DEBUG):
        try:
            last_debug_msg = main_loop.last_debug_msg
        except AttributeError:
            last_debug_msg = ""
        msg = f"have {top_ip_count} IPs plus {pending_jobs_count} pending,"
        msg += f" want {top_ip_bonus}, need {top_ip_target}"
        if msg != last_debug_msg:  # avoid repeating the same message
            logger.debug(msg)
        main_loop.last_debug_msg = msg


class DoneWithJobs(Exception):
    pass


async def main_loop(args: MyoriginArgs, logger: logging.Logger) -> str:
    result = ""
    engine = init_db(args.dbfile)
    with Session(engine) as db_session:
        scores = dict()
        all_parrots = db_session.exec(select(Parrot))
        for p in all_parrots:
            if args.ip_version != 0 and args.ip_version != p.ip_version():  # only ones user wants
                continue
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
            limit=args.max_connections,
            family=ip_family,
        )
        completed_jobs = list()
        async with aiohttp.ClientSession(
            connector=connector, timeout=http_timeout(args.timeout), trace_configs=[http_timer()]
        ) as aio_session:
            try:
                logger.info(f"requests (need {args.minimum_match} matches):")
                pending_jobs_count = 0
                while True:  # spawn and collect jobs
                    # calculate what is still needed
                    top_ip_count, top_ip_target = are_we_there_yet(completed_jobs, args, logger)
                    top_ip_bonus = top_ip_target + args.overkill
                    jobs_count = top_ip_count + pending_jobs_count
                    # logging, overkill check
                    log_debug_details(
                        logger, top_ip_count, pending_jobs_count, top_ip_bonus, top_ip_target
                    )
                    if args.overkill > 0 and top_ip_bonus > jobs_count and len(scores) == 0:
                        msg = f"not enough providers for {top_ip_bonus} requests"
                        logger.warning(f"{msg}; ignoring '--overkill'")
                        args.overkill = 0
                        top_ip_bonus = top_ip_target + args.overkill
                    # spawn another get_ip() job if needed
                    if top_ip_bonus > jobs_count and pending_jobs_count < args.max_connections:
                        # TCPConnector(limit=...) does this too, but checking args.max_connections
                        # ... here delays "not enough providers" so we can collect more responses
                        if len(scores) == 0:
                            error = f"not enough providers for {args.minimum_match} matches"
                            raise NetworkError(error)
                        p_id = weighted_random(scores)
                        statement = select(Parrot).where(Parrot.id == p_id)
                        p = db_session.exec(statement).one_or_none()
                        asyncio.create_task(get_ip(p, aio_session, q, ip_version=args.ip_version))
                        pending_jobs_count += 1
                        logger.debug(f"launching task {p.id}")
                        p.del_keys_of_same_parrot(scores, logger)  # don't use this parrot again
                        main_loop.last_debug_msg = ""  # repeat debug msg after launch even if same
                    await asyncio.sleep(0.0001)
                    # process completed jobs
                    try:
                        r: FetchedIP = q.get_nowait()  # may raise QueueEmpty
                        completed_jobs.append(r)  # keep a list to write to DB later
                        if r.rtt != 0:  # got valid IP
                            # note success count will be wrong if IP is later found to be wrong
                            p = f"{r.parrot.success_count + 1} of {r.parrot.attempt_count + 1}"
                            msg = f"    {r.parrot.url()} → {r.ip} ({r.rtt} ms;"
                            logger.info(f"{msg} {p} succeeded)")
                        else:
                            p = f"{r.parrot.success_count} of {r.parrot.attempt_count + 1}"
                            msg = f"    {r.parrot.url()} → {r.ip[:40]}"
                            logger.info(f"{msg} ({p} succeeded)")
                        pending_jobs_count -= 1
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.005)  # reduce looping when waiting on responses
                    await asyncio.sleep(0.0001)
            except DoneWithJobs as e:
                result = str(e)
            except NetworkError as e:
                logger.error(e)
                if args.exception_level >= 1:
                    raise NetworkError(e)
        await connector.close()
        for r in completed_jobs:
            r.parrot.attempt_count += 1
            if r.rtt != 0:  # got valid IP of some sort
                r.parrot.success_count += 1
                r.parrot.total_rtt += r.rtt
            else:
                r.parrot.last_errmsg = r.ip
            db_session.add(r.parrot)
            db_session.commit()
    return result


def mkdir_r(path):  # like Linux `mkdir --parents`
    if path == '':
        return
    base = os.path.dirname(path)
    if not os.path.exists(base):
        mkdir_r(base)
    os.makedirs(path, exist_ok=True)
    # except (PermissionError, FileNotFoundError, NotADirectoryError):
    #     one of these will be raised if the directory cannot be created


def db_pathname(create_dir=False):
    config_dir = platformdirs.user_config_dir(app_name())
    if create_dir:
        mkdir_r(config_dir)
    return os.path.join(config_dir, f'data.sqlite')


def init_db(db_file):
    if hasattr(init_db, 'engine'):  # only need to initialize once
        return init_db.engine
    warnings.filterwarnings(  # https://github.com/tiangolo/sqlmodel/issues/189#issuecomment-1018014753
        "ignore", ".*Class SelectOfScalar will not make use of SQL compilation caching.*"
    )
    if db_file == '':  # use default location
        db_file = db_pathname(create_dir=True)
    elif db_file == '-':
        db_file = ':memory:'
    init_db.engine = create_engine(f'sqlite:///{db_file}', echo=False)
    SQLModel.metadata.create_all(init_db.engine)
    Parrot.startup(init_db.engine)
    return init_db.engine


if __name__ == "__main__":
    cli()
