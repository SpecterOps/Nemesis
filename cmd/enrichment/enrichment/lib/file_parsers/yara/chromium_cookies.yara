rule is_chromium_cookies
{
    strings:
        $header = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20} // "SQLite format "
        $str1 = "CREATE TABLE cookies"
        $str2 = "is_secure"
        $str3 = "is_httponly"
        $str4 = "last_update_utc"
    condition:
        $header at 0 and $str1 and $str2 and $str3 and $str4
}