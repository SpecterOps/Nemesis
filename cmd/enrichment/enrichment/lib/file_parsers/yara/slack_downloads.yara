rule is_slack_downloads
{
    strings:
        $str1 = "\"appVersion\":"
        $str2 = "\"teamId\":"
        $str3 = "\"downloadState\":"
        $str4 = "\"downloadPath\":"
    condition:
        $str1 and $str2 and $str3 and $str4
}
