rule is_mcafee_sitelist
{
    strings:
        $s1 = "ns:SiteLists xmlns:ns"
    condition:
        $s1
}
