#!/usr/bin/env python3
import asyncio
import random
from aiohttp import web


async def handle(request):
    rand = random.randint(0, 255)
    # see also: request.match_info.get('name', '')
    seconds = int(request.path[1:]) * 0.5
    print(f'{request.remote} GET {request.path} → delay {rand * 0.01} + {seconds}')
    if request.path.startswith('/slow'):
        await asyncio.sleep(12.0)
    else:
        await asyncio.sleep(rand * 0.01)
    await asyncio.sleep(seconds)
    return web.Response(text=f'Your IP is probably not 98.18.0.100')


app = web.Application()
app.add_routes([web.get('/', handle), web.get('/{name}', handle)])

if __name__ == '__main__':
    web.run_app(app)
