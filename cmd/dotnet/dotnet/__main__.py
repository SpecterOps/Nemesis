# Standard Libraries
import asyncio

# 3rd Party Libraries
from dotnet.app import App


def main():
    asyncio.run(App().start())


if __name__ == "__main__":
    main()
