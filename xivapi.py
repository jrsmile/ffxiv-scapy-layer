import asyncio
import logging

import aiohttp
import pyxivapi
from pyxivapi.models import Filter, Sort


async def fetch_example_results():
    client = pyxivapi.XIVAPIClient(api_key="")

    recipe = await client.index_search(
        name="Vorsicht, Rutschgefahr!", 
        indexes=["Quest"], 
        columns=["Name_en"],
        language="de",
        string_algo="match"
    )

    await client.session.close()
    quest_name= recipe["Results"][0]["Name_en"].replace(' ','_')
    url = f"https://ffxiv.gamerescape.com/wiki/{quest_name}/NPCs"
    print(url)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_example_results())

