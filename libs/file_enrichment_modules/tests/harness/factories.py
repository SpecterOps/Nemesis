"""Factory methods for creating test data matching the files_enriched schema."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any


class FileEnrichedFactory:
    """Factory for creating file_enriched test data.

    Provides convenience methods for creating test data that matches
    the files_enriched database schema with sensible defaults.

    Usage:
        # Create a basic file
        data = FileEnrichedFactory.create()

        # Create a PE executable
        data = FileEnrichedFactory.create_pe_file(
            object_id="test-uuid",
            file_name="malware.exe"
        )

        # Create a plaintext file
        data = FileEnrichedFactory.create_plaintext_file(
            file_name=".git-credentials"
        )
    """

    @staticmethod
    def create(
        object_id: str | None = None,
        file_name: str = "test_file",
        extension: str | None = None,
        size: int = 1024,
        magic_type: str = "data",
        mime_type: str = "application/octet-stream",
        is_plaintext: bool = False,
        is_container: bool = False,
        hashes: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create basic file_enriched data with customizable fields.

        Args:
            object_id: UUID for the file (auto-generated if None)
            file_name: Name of the file
            extension: File extension (extracted from file_name if None)
            size: File size in bytes
            magic_type: Magic file type string
            mime_type: MIME type string
            is_plaintext: Whether file is plaintext
            is_container: Whether file is a container (zip, tar, etc.)
            hashes: Dict with md5, sha1, sha256 keys
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema
        """
        if object_id is None:
            object_id = str(uuid.uuid4())

        if extension is None and "." in file_name:
            extension = "." + file_name.rsplit(".", 1)[-1]

        if hashes is None:
            hashes = {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }

        now = datetime.now(UTC)

        data = {
            "object_id": object_id,
            "agent_id": "test-agent",
            "source": "test-source",
            "project": "test-project",
            "timestamp": now,
            "expiration": now + timedelta(days=30),
            "path": f"/test/path/{file_name}",
            "file_name": file_name,
            "extension": extension,
            "size": size,
            "magic_type": magic_type,
            "mime_type": mime_type,
            "is_plaintext": is_plaintext,
            "is_container": is_container,
            "originating_object_id": None,
            "originating_container_id": None,
            "nesting_level": None,
            "file_creation_time": None,
            "file_access_time": None,
            "file_modification_time": None,
            "security_info": None,
            "hashes": hashes,
        }

        # Apply any additional overrides
        data.update(kwargs)
        return data

    @classmethod
    def create_pe_file(
        cls,
        object_id: str | None = None,
        file_name: str = "test.exe",
        size: int = 65536,
        is_64bit: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a PE executable.

        Args:
            object_id: UUID for the file
            file_name: Name of the executable
            size: File size in bytes
            is_64bit: Whether it's a 64-bit PE
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for PE files
        """
        magic_type = "PE32+ executable (GUI) x86-64" if is_64bit else "PE32 executable (GUI) Intel 80386"

        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type=magic_type,
            mime_type="application/x-dosexec",
            **kwargs,
        )

    @classmethod
    def create_dll_file(
        cls,
        object_id: str | None = None,
        file_name: str = "test.dll",
        size: int = 32768,
        is_64bit: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a DLL.

        Args:
            object_id: UUID for the file
            file_name: Name of the DLL
            size: File size in bytes
            is_64bit: Whether it's a 64-bit DLL
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for DLL files
        """
        magic_type = "PE32+ executable (DLL) x86-64" if is_64bit else "PE32 executable (DLL) Intel 80386"

        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type=magic_type,
            mime_type="application/x-dosexec",
            **kwargs,
        )

    @classmethod
    def create_plaintext_file(
        cls,
        object_id: str | None = None,
        file_name: str = "config.txt",
        size: int = 512,
        content_hint: str = "ASCII text",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a plaintext file.

        Args:
            object_id: UUID for the file
            file_name: Name of the file
            size: File size in bytes
            content_hint: Magic type hint (e.g., "ASCII text", "UTF-8 Unicode text")
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for plaintext files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type=content_hint,
            mime_type="text/plain",
            is_plaintext=True,
            **kwargs,
        )

    @classmethod
    def create_sqlite_file(
        cls,
        object_id: str | None = None,
        file_name: str = "database.db",
        size: int = 16384,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a SQLite database.

        Args:
            object_id: UUID for the file
            file_name: Name of the database file
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for SQLite files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="SQLite 3.x database",
            mime_type="application/x-sqlite3",
            **kwargs,
        )

    @classmethod
    def create_zip_file(
        cls,
        object_id: str | None = None,
        file_name: str = "archive.zip",
        size: int = 8192,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a ZIP archive.

        Args:
            object_id: UUID for the file
            file_name: Name of the archive
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for ZIP files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="Zip archive data",
            mime_type="application/zip",
            is_container=True,
            **kwargs,
        )

    @classmethod
    def create_tar_file(
        cls,
        object_id: str | None = None,
        file_name: str = "archive.tar",
        size: int = 8192,
        compressed: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a TAR archive.

        Args:
            object_id: UUID for the file
            file_name: Name of the archive
            size: File size in bytes
            compressed: Whether it's a compressed tar (tar.gz)
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for TAR files
        """
        if compressed:
            magic_type = "gzip compressed data"
            mime_type = "application/gzip"
        else:
            magic_type = "POSIX tar archive"
            mime_type = "application/x-tar"

        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type=magic_type,
            mime_type=mime_type,
            is_container=True,
            **kwargs,
        )

    @classmethod
    def create_7z_file(
        cls,
        object_id: str | None = None,
        file_name: str = "archive.7z",
        size: int = 8192,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a 7z archive.

        Args:
            object_id: UUID for the file
            file_name: Name of the archive
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for 7z files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="7-zip archive data",
            mime_type="application/x-7z-compressed",
            is_container=True,
            **kwargs,
        )

    @classmethod
    def create_pdf_file(
        cls,
        object_id: str | None = None,
        file_name: str = "document.pdf",
        size: int = 32768,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a PDF document.

        Args:
            object_id: UUID for the file
            file_name: Name of the document
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for PDF files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="PDF document",
            mime_type="application/pdf",
            **kwargs,
        )

    @classmethod
    def create_office_file(
        cls,
        object_id: str | None = None,
        file_name: str = "document.docx",
        size: int = 16384,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for an Office document.

        Args:
            object_id: UUID for the file
            file_name: Name of the document
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for Office files
        """
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else "docx"

        mime_types = {
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "doc": "application/msword",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xls": "application/vnd.ms-excel",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "ppt": "application/vnd.ms-powerpoint",
        }

        magic_types = {
            "docx": "Microsoft Word 2007+",
            "doc": "Composite Document File V2 Document",
            "xlsx": "Microsoft Excel 2007+",
            "xls": "Composite Document File V2 Document",
            "pptx": "Microsoft PowerPoint 2007+",
            "ppt": "Composite Document File V2 Document",
        }

        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type=magic_types.get(ext, "Microsoft Office Document"),
            mime_type=mime_types.get(ext, "application/octet-stream"),
            **kwargs,
        )

    @classmethod
    def create_xml_file(
        cls,
        object_id: str | None = None,
        file_name: str = "config.xml",
        size: int = 2048,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for an XML file.

        Args:
            object_id: UUID for the file
            file_name: Name of the file
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for XML files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="XML 1.0 document",
            mime_type="application/xml",
            is_plaintext=True,
            **kwargs,
        )

    @classmethod
    def create_certificate_file(
        cls,
        object_id: str | None = None,
        file_name: str = "cert.pem",
        size: int = 2048,
        is_der: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a certificate file.

        Args:
            object_id: UUID for the file
            file_name: Name of the certificate
            size: File size in bytes
            is_der: Whether it's DER encoded (binary) vs PEM (text)
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for certificate files
        """
        if is_der:
            return cls.create(
                object_id=object_id,
                file_name=file_name,
                size=size,
                magic_type="DER Encoded Certificate",
                mime_type="application/x-x509-ca-cert",
                **kwargs,
            )
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="PEM certificate",
            mime_type="application/x-pem-file",
            is_plaintext=True,
            **kwargs,
        )

    @classmethod
    def create_keytab_file(
        cls,
        object_id: str | None = None,
        file_name: str = "krb5.keytab",
        size: int = 1024,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a Kerberos keytab file.

        Args:
            object_id: UUID for the file
            file_name: Name of the keytab
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for keytab files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="data",
            mime_type="application/octet-stream",
            **kwargs,
        )

    @classmethod
    def create_lnk_file(
        cls,
        object_id: str | None = None,
        file_name: str = "shortcut.lnk",
        size: int = 2048,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a Windows LNK shortcut file.

        Args:
            object_id: UUID for the file
            file_name: Name of the shortcut
            size: File size in bytes
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for LNK files
        """
        return cls.create(
            object_id=object_id,
            file_name=file_name,
            size=size,
            magic_type="MS Windows shortcut",
            mime_type="application/x-ms-shortcut",
            **kwargs,
        )

    @classmethod
    def create_extracted_file(
        cls,
        object_id: str | None = None,
        originating_object_id: str | None = None,
        originating_container_id: str | None = None,
        nesting_level: int = 1,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create file_enriched data for a file extracted from an archive.

        Args:
            object_id: UUID for the extracted file
            originating_object_id: UUID of the parent file
            originating_container_id: UUID of the container
            nesting_level: How deep in nested archives
            **kwargs: Additional fields to override

        Returns:
            Dict matching files_enriched schema for extracted files
        """
        if originating_object_id is None:
            originating_object_id = str(uuid.uuid4())
        if originating_container_id is None:
            originating_container_id = originating_object_id

        return cls.create(
            object_id=object_id,
            originating_object_id=originating_object_id,
            originating_container_id=originating_container_id,
            nesting_level=nesting_level,
            **kwargs,
        )
