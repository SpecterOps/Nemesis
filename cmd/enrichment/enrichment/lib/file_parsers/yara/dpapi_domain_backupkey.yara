rule is_dpapi_domain_backupkey
{
    strings:
        $str1 = "\"domain_controller\": "
        $str2 = "\"domain_backupkey_guid\": "
        $str3 = "\"domain_backupkey_b64\": "
    condition:
        $str1 and $str2 and $str3
}
