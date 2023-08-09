rule is_chromium_history
{
    strings:
        $header = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20} // "SQLite format "
        $str1 = "CREATE TABLE downloads"
        $str2 = "original_mime_type"
        $str3 = "last_visit_time"
        $str4 = "received_bytes"
    condition:
        $header at 0 and $str1 and $str2 and $str3 and $str4
}