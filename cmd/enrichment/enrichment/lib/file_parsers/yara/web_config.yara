rule is_webconfig
{
    strings:
        $str1 = "connectionStrings"
        $str2 = "connectionString="
    condition:
        $str1 and $str2
}
