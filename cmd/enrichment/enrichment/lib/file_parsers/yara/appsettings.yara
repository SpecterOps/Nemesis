rule is_appsettings
{
    strings:
        $str1 = "ConnectionStrings"
        $str2 = "JwtToken"
        $str3 = "Microsoft.Hosting.Lifetime"
        $str4 = "AllowedHosts"
    condition:
        ($str1 or $str2) and ($str3 or $str4)
}
