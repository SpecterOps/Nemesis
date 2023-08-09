import "pe"

rule is_pe
{
    condition:
        pe.is_pe
}