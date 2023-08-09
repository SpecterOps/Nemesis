rule is_seatbelt_json
{
    strings:
        $str = "{\"Type\":\"Seatbelt.Commands.HostDTO\",\""
    condition:
        $str
}
