# 3rd Party Libraries
from passwordcracker.bootstrap import main
from passwordcracker.containers import Container

if __name__ == "__main__":
    container = Container()
    container.wire(
        modules=[
            "passwordcracker",
            "passwordcracker.bootstrap",
        ]
    )

    main(container)
