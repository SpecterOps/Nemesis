rule is_group_policy_preferences
{
    strings:
        $s1 = "clsid="
        $s2 = "cpassword="
        $s3 = "neverExpires="
    condition:
        $s1 and $s2 and $s3
}
