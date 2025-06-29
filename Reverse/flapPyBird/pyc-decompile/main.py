#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.11

import asyncio
from src.flappy import Flappy
if __name__ == '__main__':
    asyncio.run(Flappy().start())
    return None