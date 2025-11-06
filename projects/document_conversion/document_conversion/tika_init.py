"""Tika initialization helper."""

import os
import tempfile

import jpype
import jpype.imports  # noqa: F401
from common.logger import get_logger

logger = get_logger(__name__)


def init_tika():
    """Initialize Java Runtime and Tika."""
    if not jpype.isJVMStarted():
        logger.info("Staring JVM")
        jpype.startJVM(
            # "-Dorg.slf4j.simpleLogger.defaultLogLevel=debug",
            "-Dorg.slf4j.simpleLogger.showDateTime=true",
            "-Dorg.slf4j.simpleLogger.dateTimeFormat=yyyy-MM-dd HH:mm:ss:SSS",
            "-Dorg.slf4j.simpleLogger.showLogName=true",
            "-Dorg.slf4j.simpleLogger.logFile=System.out",  # Write to stdout instead of stderr
            classpath=["/tika-server-standard.jar"],
        )

        # Configure Java Util Logging (JUL) for PDFBox warnings
        # PDFBox may use JUL instead of SLF4J in some cases
        Logger = jpype.JClass("java.util.logging.Logger")
        Level = jpype.JClass("java.util.logging.Level")

        # Set PDFBox loggers to SEVERE (equivalent to ERROR)
        pdfbox_logger = Logger.getLogger("org.apache.pdfbox")
        pdfbox_logger.setLevel(Level.SEVERE)

    # Import Java classes
    TikaConfig = jpype.JClass("org.apache.tika.config.TikaConfig")
    Tika = jpype.JClass("org.apache.tika.Tika")
    File = jpype.JClass("java.io.File")

    # Get OCR language from environment variable
    #   Note: Use underscores for language types, not hyphens (chi_sim not chi-sim)
    ocr_languages = os.getenv("TIKA_OCR_LANGUAGES", "eng").replace("-", "_").replace(" ", "+")
    logger.info(f"Configuring Tika with OCR languages: {ocr_languages}")

    # Read the static XML config and substitute the language parameter
    with open("/tika-config.xml") as f:
        config_xml = f.read()

    # Replace the hardcoded language with the environment variable value
    config_xml = config_xml.replace(">eng<", f">{ocr_languages}<")

    # Write the modified config to a temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as temp_config:
        temp_config.write(config_xml)
        temp_config.flush()
        temp_config_path = temp_config.name

    try:
        config = TikaConfig(File(temp_config_path))
        tika_instance = Tika(config)
        logger.info(
            "Tika initialized successfully with OCR languages", config=temp_config_path, ocr_languages=ocr_languages
        )
    except Exception as e:
        logger.exception("Failed to load Tika config", ocr_languages=ocr_languages, config_xml=config_xml)
        raise e

    return tika_instance, File
