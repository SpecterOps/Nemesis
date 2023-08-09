rule is_slack_workspaces
{
    strings:
        $str1 = "\"domain\":"
        $str2 = "\"icon\":"
        $str3 = "\"image_original\":"
    condition:
        $str1 and $str2 and $str3
}
