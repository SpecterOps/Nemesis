rule is_masterkey
{
    strings:
        $hex_string = {02 00 00 00 00 00 00 00 00 00 00 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2d 00 ?? 00 ?? 00 ?? 00 ?? 00 2d 00 ?? 00 ?? 00 ?? 00 ?? 00 2d 00 ?? 00 ?? 00 ?? 00 ?? 00 2d 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00}
    condition:
        $hex_string at 0
}