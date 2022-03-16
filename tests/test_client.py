#!/usr/bin/env python3
import aiohttp
import asyncio
import random
from grep_ips import GrepIPs


urls = [
    'http://[::1]:8080/one',
    'http://[::1]:8080/slow_two',
    'http://[::1]:8080/three',
    'http://127.0.0.1:8080/four',
    'http://[::1]:8080/slowfive',
    'http://[::1]:8080/six',
    'http://[::1]:8080/seven',
    'http://127.0.0.1:8080/eight',
    'http://[::1]:8080/nine',
    'http://[::1]:8080/ten',
]
random.shuffle(urls)
http_timeout = 7.0


async def timer_mark(session, context, params):
    context.trace_request_ctx.append(asyncio.get_event_loop().time())


async def http_get(url, session, max_size=-1):
    timer_marks = list()
    try:
        async with session.get(
            url, allow_redirects=False, trace_request_ctx=timer_marks
        ) as response:
            if response.status != 200:
                raise aiohttp.ClientError(f"{response.status} {response.reason}")
            html = str((await response.content.read(max_size)).decode())
            assert len(timer_marks) == 2
            μs = round((timer_marks[1] - timer_marks[0]) * 1000000)
            return html, μs
    except aiohttp.ClientError as e:
        raise ValueError(str(e))


async def get_ip(url, session):
    try:
        html, μs = await http_get(url, session, max_size=8192)  # don't download it all
    except ValueError as e:
        return str(e)
    return f"{GrepIPs.grep_ips(html, first_match_only=True)} ({μs} μs)"


async def main():
    tasks = list()
    connector = aiohttp.TCPConnector(limit=3)  # limit the total number of simultaneous connections
    trace_config = aiohttp.TraceConfig()
    # on_connection_queded_end → not called if a connection is immediately available
    # on_connection_reuseconn, on_connection_create_start → exactly one of these is always called
    # on_request_headers_sent.append → always called
    # on_request_end.append → always called
    trace_config.on_connection_reuseconn.append(timer_mark)  # start timer
    trace_config.on_connection_create_start.append(timer_mark)  # start timer
    trace_config.on_request_end.append(timer_mark)  # stop timer
    # ClientTimeout docs: https://docs.aiohttp.org/en/stable/client_reference.html#clienttimeout
    timeout = aiohttp.ClientTimeout(sock_connect=http_timeout, sock_read=http_timeout)
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, trace_configs=[trace_config]
    ) as session:
        for url in urls:
            tasks.append(asyncio.ensure_future(get_ip(url, session)))
            await asyncio.sleep(0.0001)
        responses = await asyncio.gather(*tasks)
        assert len(urls) == len(responses)
        print(f"{len(responses)} responses:")
        for i, r in enumerate(responses):
            print(f"    {urls[i]} → {r}")


GrepIPs.grep_ips_test()
results = asyncio.run(main())
