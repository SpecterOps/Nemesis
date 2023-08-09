rule is_dotnet_assembly
{
    strings:
        $DOTNET = "mscorlib" ascii
    condition:
        (uint16(0) == 0x5A4D) and ($DOTNET)
}
