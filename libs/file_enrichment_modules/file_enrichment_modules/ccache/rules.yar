rule CCache_File {
    meta:
        description = "Detects Kerberos credential cache (ccache) files"
        author = "Nemesis"
        reference = "https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html"

    strings:
        $ccache_v4 = { 05 04 }  // CCache format version 4
        $ccache_v3 = { 05 03 }  // CCache format version 3

    condition:
        ($ccache_v4 at 0) or ($ccache_v3 at 0)
}
