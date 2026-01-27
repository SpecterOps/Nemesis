rule Windows_Prefetch_SCCA
{
    meta:
        description = "Detects uncompressed Windows Prefetch files (SCCA format)"
        author = "Nemesis"
        file_type = "Windows Prefetch"
        windows_versions = "Windows XP, Vista, 7, 8, 8.1"

    strings:
        $scca_header = { ?? 00 00 00 53 43 43 41 }  // Version (4 bytes) + "SCCA"

    condition:
        $scca_header at 0
}

rule Windows_Prefetch_MAM
{
    meta:
        description = "Detects MAM-compressed Windows Prefetch files"
        author = "Nemesis"
        file_type = "Windows Prefetch (Compressed)"
        windows_versions = "Windows 10, 11"
        compression = "XPRESS Huffman"

    strings:
        $mam_header = { 4D 41 4D 04 }  // "MAM" + compression type (0x04 = XPRESS Huffman)

    condition:
        $mam_header at 0
}
