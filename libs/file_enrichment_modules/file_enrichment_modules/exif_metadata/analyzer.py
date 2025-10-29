# enrichment_modules/exif_metadata/analyzer.py
import tempfile
import textwrap

import yaml
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

logger = get_logger(__name__)

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    ".jpg",
    ".jpeg",  # JPEG
    ".tif",
    ".tiff",  # TIFF
    ".cr2",
    ".cr3",  # Canon RAW
    ".nef",  # Nikon RAW
    ".arw",  # Sony RAW
    ".dng",  # Adobe Digital Negative
}


def convert_gps_to_degrees(value):
    """Convert GPS coordinates to decimal degrees."""
    try:
        d, m, s = value
        return float(d) + float(m) / 60.0 + float(s) / 3600.0
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_gps_info(exif_data):
    """Extract and convert GPS information from EXIF data."""
    gps_info = {}

    if "GPSInfo" not in exif_data:
        return gps_info

    gps_data = exif_data["GPSInfo"]

    # Extract GPS coordinates
    gps_latitude = gps_data.get("GPSLatitude")
    gps_latitude_ref = gps_data.get("GPSLatitudeRef")
    gps_longitude = gps_data.get("GPSLongitude")
    gps_longitude_ref = gps_data.get("GPSLongitudeRef")

    if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
        lat = convert_gps_to_degrees(gps_latitude)
        lon = convert_gps_to_degrees(gps_longitude)

        if lat is not None and lon is not None:
            # Apply direction references
            if gps_latitude_ref == "S":
                lat = -lat
            if gps_longitude_ref == "W":
                lon = -lon

            gps_info["Latitude"] = lat
            gps_info["Longitude"] = lon
            gps_info["Coordinates"] = f"{lat}, {lon}"
            gps_info["Maps URL"] = f"https://www.google.com/maps?q={lat},{lon}"

    # Extract altitude
    gps_altitude = gps_data.get("GPSAltitude")
    gps_altitude_ref = gps_data.get("GPSAltitudeRef", 0)
    if gps_altitude is not None:
        altitude = float(gps_altitude)
        if gps_altitude_ref == 1:
            altitude = -altitude
        gps_info["Altitude"] = f"{altitude}m"

    # Extract timestamp
    gps_datestamp = gps_data.get("GPSDateStamp")
    gps_timestamp = gps_data.get("GPSTimeStamp")
    if gps_datestamp and gps_timestamp:
        try:
            h, m, s = gps_timestamp
            gps_info["Timestamp"] = f"{gps_datestamp} {int(h):02d}:{int(m):02d}:{int(s):02d} UTC"
        except (TypeError, ValueError):
            pass

    return gps_info


def convert_exif_value(value):
    """Convert EXIF values to JSON-serializable types."""
    # Handle PIL-specific types first
    if hasattr(value, "__class__") and "IFDRational" in value.__class__.__name__:
        # IFDRational is a fraction type - convert to float
        try:
            return float(value)
        except:
            return str(value)
    elif isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except:
            return str(value)
    elif isinstance(value, (tuple, list)):
        return [convert_exif_value(v) for v in value]
    elif isinstance(value, dict):
        return {k: convert_exif_value(v) for k, v in value.items()}
    elif isinstance(value, (int, float, str, bool, type(None))):
        return value
    elif hasattr(value, "__dict__"):
        return str(value)
    return value


def extract_exif_data(image):
    """Extract EXIF data from PIL Image object."""
    exif_dict = {}

    try:
        exif_data = image.getexif()

        if not exif_data:
            return exif_dict

        # Extract basic EXIF tags
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            exif_dict[tag_name] = convert_exif_value(value)

        # Extract GPS info if present
        if "GPSInfo" in exif_dict:
            gps_data = {}
            gps_raw = exif_data.get_ifd(0x8825)  # GPS IFD

            for tag_id, value in gps_raw.items():
                tag_name = GPSTAGS.get(tag_id, tag_id)
                gps_data[tag_name] = convert_exif_value(value)

            exif_dict["GPSInfo"] = gps_data

    except Exception as e:
        logger.warning(f"Error extracting EXIF data: {e}")

    return exif_dict


def format_exif_display(exif_data):
    """Format EXIF data for human-readable display."""
    if not exif_data:
        return "No EXIF data found in image."

    display_dict = {}

    # Camera Information
    camera_info = {}
    for key in ["Make", "Model", "Software", "LensModel", "LensMake"]:
        if key in exif_data:
            camera_info[key] = exif_data[key]
    if camera_info:
        display_dict["Camera Information"] = camera_info

    # Image Settings
    image_settings = {}
    for key in [
        "ExposureTime",
        "FNumber",
        "ISO",
        "ISOSpeedRatings",
        "FocalLength",
        "Flash",
        "WhiteBalance",
        "ExposureProgram",
        "MeteringMode",
        "ExposureBiasValue",
    ]:
        if key in exif_data:
            image_settings[key] = exif_data[key]
    if image_settings:
        display_dict["Image Settings"] = image_settings

    # Date and Time
    datetime_info = {}
    for key in [
        "DateTime",
        "DateTimeOriginal",
        "DateTimeDigitized",
        "OffsetTime",
        "OffsetTimeOriginal",
        "OffsetTimeDigitized",
    ]:
        if key in exif_data:
            datetime_info[key] = exif_data[key]
    if datetime_info:
        display_dict["Date and Time"] = datetime_info

    # GPS Information
    gps_info = extract_gps_info(exif_data)
    if gps_info:
        display_dict["GPS Information"] = gps_info

    # Image Dimensions
    image_dims = {}
    for key in [
        "ImageWidth",
        "ImageLength",
        "ExifImageWidth",
        "ExifImageHeight",
        "Orientation",
        "ResolutionUnit",
        "XResolution",
        "YResolution",
    ]:
        if key in exif_data:
            image_dims[key] = exif_data[key]
    if image_dims:
        display_dict["Image Dimensions"] = image_dims

    # Other Information
    other_info = {}
    for key in ["Artist", "Copyright", "ImageDescription", "UserComment"]:
        if key in exif_data:
            other_info[key] = exif_data[key]
    if other_info:
        display_dict["Other Information"] = other_info

    # Convert to YAML for nice formatting
    yaml_output = yaml.dump(display_dict, indent=3, sort_keys=False, width=132, allow_unicode=True)
    return textwrap.indent(yaml_output, "   ")


class ExifMetadataExtractor(EnrichmentModule):
    name: str = "exif_metadata"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = await get_file_enriched_async(object_id)

        # Check if file extension is supported
        extension = file_enriched.extension.lower() if file_enriched.extension else ""
        if extension not in SUPPORTED_EXTENSIONS:
            return False

        # Additional check via magic type for common formats
        magic_lower = file_enriched.magic_type.lower()
        return any(fmt in magic_lower for fmt in ["jpeg", "tiff", "image"])

    def _analyze_exif(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze EXIF metadata and generate enrichment result.

        Args:
            file_path: Path to the image file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            # Open image and extract EXIF
            with Image.open(file_path) as img:
                exif_data = extract_exif_data(img)

            if not exif_data:
                logger.info(f"No EXIF data found in {file_enriched.file_name}")
                return None

            # Store raw EXIF data
            enrichment_result.results = exif_data

            # Create human-readable display file
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                display = format_exif_display(exif_data)
                tmp_display_file.write(display)
                tmp_display_file.flush()

                object_id = self.storage.upload_file(tmp_display_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}.exif.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )

            enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing EXIF data for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            # get the current `file_enriched` FileEnriched object from the database backend
            file_enriched = await get_file_enriched_async(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_exif(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_exif(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing file", file_object_id=object_id)
            return None


def create_enrichment_module() -> EnrichmentModule:
    return ExifMetadataExtractor()
