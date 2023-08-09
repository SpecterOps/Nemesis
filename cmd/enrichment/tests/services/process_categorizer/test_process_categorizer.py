# Standard Libraries
import os

# 3rd Party Libraries
import pytest
from enrichment.tasks.process_categorizer.categorizer import CsvProcessCategorizer


@pytest.mark.asyncio
async def test_categorizer() -> None:
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    categorizer = CsvProcessCategorizer(data_dir)
    categorizer._category_files = {
        "Browser": "browsers.csv",
        "Security": "security_products.csv",
    }
    categories = await categorizer.lookup("chrome.exe")

    # assert len(categories) == 1
    # assert categories[0].category == "Browser"
    # assert categories[0].description == "Google Chrome"

    assert categories.category == "Browser"
    assert categories.description == "Google Chrome"
