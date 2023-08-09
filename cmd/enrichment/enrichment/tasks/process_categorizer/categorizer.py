# Standard Libraries
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ProcessCategory:
    category: str
    description: Optional[str]


class ProcessCategorizerInterface(ABC):
    @abstractmethod
    async def lookup(self, name: str) -> ProcessCategory:
        pass


class CsvProcessCategorizer(ProcessCategorizerInterface):
    processCategoryMap: Dict[str, ProcessCategory] = {}
    data_path: str
    _initialized: bool = False
    _category_files: Dict[str, str] = {
        "AccessTool": "access_tools.csv",
        "Browser": "browsers.csv",
        "Infrastructure": "infrastructure.csv",
        "Other": "other.csv",
        "MiscAwareness": "misc_awareness.csv",
        "Security": "security_products.csv",
    }

    def __init__(self, data_path: Optional[str] = None):
        if data_path:
            self.data_path = data_path
        else:
            self.data_path = os.path.join(os.path.dirname(__file__), "data")

    def __load_categories(self) -> None:
        for category_name, filename in self._category_files.items():
            filepath = os.path.join(self.data_path, filename)
            self.__load_csv(category_name, filepath)

    def __load_csv(self, category_name: str, filepath: str) -> None:
        csv = open(filepath, "r", encoding="utf-8")
        lines = csv.readlines()
        csv.close()

        for line in lines:
            line = line.strip()
            if line == "" or line.startswith("#"):
                continue

            parts = line.split(",", 1)

            process_name = parts[0].lower()

            if len(parts) == 1:
                description = None
            else:
                description = parts[1]

            category = ProcessCategory(category_name, description)

            # if process_name in self.processCategoryMap:
            #     raise Exception(f"Duplicate process category for the process {process_name}")
            # else:
            #     self.processCategoryMap[process_name] = category
            self.processCategoryMap[process_name] = category

    async def lookup(self, name: str) -> ProcessCategory:
        if not self._initialized:
            self.__load_categories()
            self._initialized = True

        name = name.lower()
        if name in self.processCategoryMap:
            return self.processCategoryMap[name]
        else:
            return ProcessCategory("Unknown", "Unknown")
