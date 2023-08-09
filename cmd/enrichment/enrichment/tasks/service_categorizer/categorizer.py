# Standard Libraries
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ServiceCategory:
    category: str


class ServiceCategorizerInterface(ABC):
    @abstractmethod
    async def lookup(self, name: str) -> ServiceCategory:
        pass


class TsvServiceCategorizer(ServiceCategorizerInterface):
    serviceCategoryMap: Dict[str, ServiceCategory] = {}
    data_path: str
    _initialized: bool = False
    _category_files: Dict[str, str] = {"WindowsDefault": "win10_default.tsv"}

    def __init__(self, data_path: Optional[str] = None):
        if data_path:
            self.data_path = data_path
        else:
            self.data_path = os.path.join(os.path.dirname(__file__), "data")

    def __load_categories(self) -> None:
        for category_name, filename in self._category_files.items():
            filepath = os.path.join(self.data_path, filename)
            self.__load_tsv(category_name, filepath)

    def __load_tsv(self, category_name: str, filepath: str) -> None:
        tsv = open(filepath, "r", encoding="utf-8")
        lines = tsv.readlines()
        tsv.close()

        for line in lines:
            line = line.strip()
            if line == "" or line.startswith("#"):
                continue

            parts = line.split("\t")

            # display_name = parts[0].lower()
            service_name = parts[1].lower().replace("?????", "[a-zA-Z0-9_]{5}")

            category = ServiceCategory(category_name)

            self.serviceCategoryMap[service_name] = category

    async def lookup(self, name: str) -> ServiceCategory:
        if not self._initialized:
            self.__load_categories()
            self._initialized = True

        name = name.lower()

        for key in self.serviceCategoryMap.keys():
            # have to do re.match here because some service names are per-user Service_????? style
            if re.match(key, name):
                return self.serviceCategoryMap[key]

        return ServiceCategory("Unknown")
