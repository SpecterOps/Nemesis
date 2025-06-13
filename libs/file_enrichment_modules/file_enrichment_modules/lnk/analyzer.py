# enrichment_modules/lnk/analyzer.py
import re
import tempfile
import textwrap
from datetime import datetime

import LnkParse3
import structlog
import yaml
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


def get_lnk_file_display(lnk_file, print_all=False):
    # adapated from https://github.com/Matmaus/LnkParse3/blob/39c9933acf9e47a0d43b05a92f488b2d1dc691b6/LnkParse3/lnk_file.py#L173
    res = lnk_file.get_json(print_all)

    def nice_id(identifier, uppercase=False):
        identifier = re.sub("^r_", "", identifier, 1)
        if uppercase or identifier.upper() == identifier:
            return identifier.upper().replace("_", " ")
        return identifier.capitalize().replace("_", " ")

    def make_keys_nice(input, uppercase=False):
        if isinstance(input, list):
            return [make_keys_nice(item) for item in input]
        if isinstance(input, dict):
            if "class" in input:
                key = input.pop("class")
                return {key: make_keys_nice(input)}
            result = {}
            for key, value in input.items():
                result[nice_id(key, uppercase)] = make_keys_nice(value)
            return result
        return input

    # remove r_hotkey from header and reformat flags
    res["header"].pop("r_hotkey")
    res["header"]["link_flags"] = lnk_file.format_linkFlags()
    res["header"]["file_flags"] = lnk_file.format_fileFlags()

    res_json = make_keys_nice(res, uppercase=True)

    # insert placeholders for empty lines
    res_json = {"EMPTY_LINE_PLACEHOLDER" + k: v for k, v in res_json.items()}

    # remove header key
    new_res_json = res_json["EMPTY_LINE_PLACEHOLDERHEADER"]
    res_json.pop("EMPTY_LINE_PLACEHOLDERHEADER")
    new_res_json.update(res_json)

    res_yaml = yaml.dump(new_res_json, indent=3, sort_keys=False, width=132, allow_unicode=True)

    # replace palceholders for empty lines
    res_yaml = res_yaml.replace("EMPTY_LINE_PLACEHOLDER", "\n")

    return textwrap.indent(res_yaml, "   ")


def convert_datetime(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = convert_datetime(value)
        return obj
    elif isinstance(obj, list):
        return [convert_datetime(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    return obj


class LnkParser(EnrichmentModule):
    def __init__(self):
        super().__init__("lnk_parser")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        # get the current `file_enriched` from the Dapr statestore
        file_enriched = get_file_enriched(object_id)
        should_run = "ms windows shortcut" in file_enriched.magic_type.lower()
        return should_run

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process file."""
        try:
            # get the current `file_enriched` FileEnriched object from the database backend
            file_enriched = get_file_enriched(object_id)

            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

            with self.storage.download(file_enriched.object_id) as temp_file:
                with open(temp_file.name, "rb") as f:
                    lnk = LnkParse3.lnk_file(f)

                enrichment_result.results = convert_datetime(lnk.get_json())

                logger.info(f"lnk 3: {enrichment_result.results}")

                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = get_lnk_file_display(lnk)
                    tmp_display_file.write(display)
                    tmp_display_file.flush()

                    object_id = self.storage.upload_file(tmp_display_file.name)

                    displayable_parsed = Transform(
                        type="displayable_parsed",
                        object_id=f"{object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}.txt",
                            "display_type_in_dashboard": "monaco",
                            "default_display": True,
                        },
                    )
                enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error processing file", file_object_id=object_id)


def create_enrichment_module() -> EnrichmentModule:
    return LnkParser()
