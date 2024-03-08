rule is_seatbelt_json
{
    strings:
        $str1 = "{\"Type\":\"Seatbelt.Commands."
        $str2 = "DTO\","
    condition:
        $str1 and $str2
}
