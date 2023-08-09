rule is_chromium_state_file
{
    strings:
        $str1 = "last_whats_new_version"
        $str2 = "shortcut_migration_version"
        $str3 = "os_crypt"
        $str4 = "encrypted_key"
    condition:
        $str1 and $str2 and $str3 and $str4
}