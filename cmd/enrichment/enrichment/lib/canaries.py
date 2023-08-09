# Standard Libraries
import re
import zipfile

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
import yara

logger = structlog.get_logger(module=__name__)

##################################################
#
# Canary helpers
#
##################################################

# Rules for finding canaries
#   Add any custom canary rules here
yara_rules = yara.compile(
    source="""
rule canary_domain {
    meta:
      description = "Detects the Canarytoken domain"
      license = "BSD 3-clause"
      author = "harmj0y"
      date = "2023-01-06"
    strings:
        $regex = /canarytokens\.com/
    condition:
        $regex
}
"""
)


async def get_file_canaries(path: str) -> pb.Canaries:
    """
    Runs the specified Yara canary rules against the supplied file.
    """

    canaries = pb.Canaries()

    try:
        for match in yara_rules.match(path):
            canaries.canaries_present = True

            canary = pb.Canaries.Canary()
            canary.type = match.rule
            canary_urls = []

            for strings in match.strings:
                # make sure we strip off non alpha-numeric from the beginning/end
                canary_urls.extend([re.sub(r"^\W+|\W+$", "", f"{i}") for i in strings.instances])

            # uniqify the list
            canary.data.extend(list(set(canary_urls)))
            canaries.canaries.extend([canary])

    except Exception as e:
        await logger.awarning(f"Error in get_office_document_canaries: {e}", path=path)

    return canaries


async def get_office_document_canaries(path: str) -> pb.Canaries:
    """
    Runs the specified Yara canary rules against all of the internal
    files in the supplied Office document.
    """

    canaries = pb.Canaries()
    matches = {}

    try:
        archive = zipfile.ZipFile(path)
        # get every relative path in this archive
        for path in archive.namelist():
            for match in yara_rules.match(data=archive.read(path)):
                canaries.canaries_present = True

                canary = pb.Canaries.Canary()
                canary.type = match.rule
                canary_urls = []

                for strings in match.strings:
                    # make sure we strip off non alpha-numeric from the beginning/end
                    canary_urls.extend([re.sub(r"^\W+|\W+$", "", f"{i}") for i in strings.instances])

                # uniqify the list
                unique_urls = list(set(canary_urls))

                # ensure we haven't had a match for this rule/url set already
                #   for some subfile in the document
                id = f"{match.rule}{''.join(unique_urls)}"
                if id not in matches:
                    canary.data.extend(unique_urls)
                    canaries.canaries.extend([canary])
                    matches[id] = True

    except Exception as e:
        await logger.awarning(f"Error in get_office_document_canaries: {e}", path=path)

    return canaries
