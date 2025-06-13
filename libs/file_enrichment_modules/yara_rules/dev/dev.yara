rule Detect_Specific_String_Password123
{
    meta:
        description = "Detects the exact string 'Password123!'"
        author = "SpecterOps"
        date = "2025-01-24"
        version = "1.0"

    strings:
        $specific_password = "Password123!"

    condition:
        $specific_password
}