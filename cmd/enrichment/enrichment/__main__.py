# 3rd Party Libraries
from enrichment.bootstrap import main
from enrichment.containers import Container

if __name__ == "__main__":
    container = Container()
    container.wire(
        modules=[
            "enrichment",
            "enrichment.bootstrap",
        ]
    )

    main(container)
