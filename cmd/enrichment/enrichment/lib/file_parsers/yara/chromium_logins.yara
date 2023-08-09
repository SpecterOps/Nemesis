rule is_chromium_logins
{
    strings:
        $header = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20} // "SQLite format "
        $str1 = "username_value"
        $str2 = "password_value"
        $str3 = "stats_origin"
        $str4 = "date_password_modified"
    condition:
        $header at 0 and $str1 and $str2 and $str3 and $str4
}