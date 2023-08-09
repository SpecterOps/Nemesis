// From https://github.com/elastic/protections-artifacts/tree/main/yara
// Elastic License v2
rule Windows_EICAR_c6193e90 {
  meta:
    id = "c6193e90-edf5-41c5-a78f-9bdbd90f7450"
    fingerprint = "d94318a71723fc4f2e9f97f5dd5a0f1efc34a32f3c9eac8fa0b2da61c1d14f5d"
    creation_date = "2021-03-19"
    last_modified = "2021-07-16"
    os = "Windows"
    arch = "x86"
    category_type = "Not-a-virus"
    family = "Not-a-virus"
    threat_name = "Windows.EICAR.Not-a-virus"
    source = "Manual"
    maturity = "Diagnostic, Production"
    reference_sample = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

condition:
    all of them
}

rule Windows_Hacktool_Mimikatz_1388212a {
  meta:
    id = "1388212a-2146-4565-b93d-4555a110364f"
    fingerprint = "dbbdc492c07e3b95d677044751ee4365ec39244e300db9047ac224029dfe6ab7"
    creation_date = "2021-04-13"
    last_modified = "2021-04-14"
    os = "Windows"
    arch = "x86"
    category_type = "Hacktool"
    family = "Mimikatz"
    threat_name = "Windows.Hacktool.Mimikatz"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Password: %s" wide fullword
    // $a2 = "\n    * Session Key\n     : 0x%08x - %s" wide fullword
    $a3 = "Injecting ticket : " wide fullword
    $a4 = "/*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" wide fullword
    $a5 = "Remove mimikatz driver (mimidrv)" wide fullword
    $a6 = "mimikatz(commandline) # %s" wide fullword
    $a7 = "Password: %s" wide fullword
    $a8 = " - SCardControl(FEATURE_CCID_ESC_COMMAND)" wide fullword
    $a9 = " * to 0 will take all 'cmd' and 'mimikatz' process" wide fullword
    $a10 = "** Pass The Ticket **" wide fullword
    $a11 = "-> Ticket : %s" wide fullword
    $a12 = "Busylight Lync model (with bootloader)" wide fullword
    $a13 = "mimikatz.log" wide fullword
    $a14 = "Log mimikatz input/output to file" wide fullword
    $a15 = "ERROR kuhl_m_dpapi_masterkey ; kull_m_dpapi_unprotect_domainkey_with_key" wide fullword
    $a16 = "ERROR kuhl_m_lsadump_dcshadow ; unable to start the server: %08x" wide fullword
    $a17 = "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation (0x%08x)" wide fullword
    $a18 = "ERROR mimikatz_doLocal ; \"%s\" module not found !" wide fullword
    $a19 = "Install and/or start mimikatz driver (mimidrv)" wide fullword
    $a20 = "Target: %hhu (0x%02x - %s)" wide fullword
    $a21 = "mimikatz Ho, hey! I'm a DC :)" wide fullword
    $a22 = "mimikatz service (mimikatzsvc)" wide fullword
    $a23 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " wide fullword
    $a24 = "$http://blog.gentilkiwi.com/mimikatz 0" ascii fullword
    $a25 = " * Username : %wZ" wide fullword
condition:
    3 of ($a*)
}

rule Windows_Hacktool_Mimikatz_674fd079 {
  meta:
    id = "674fd079-f7fe-4d89-87e7-ac11aa21c9ed"
    fingerprint = "b8f71996180e5f03c10e39eb36b2084ecaff78d7af34bd3d0d75225d2cfad765"
    creation_date = "2021-04-14"
    last_modified = "2021-04-14"
    description = "Detection for default mimikatz memssp module"
    os = "Windows"
    arch = "x86"
    category_type = "Hacktool"
    family = "Mimikatz"
    threat_name = "Windows.Hacktool.Mimikatz"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
    scan_type = "File, Memory"
    severity = 99
  strings:
    $a1 = { 44 30 00 38 00 }
    $a2 = { 48 78 00 3A 00 }
    $a3 = { 4C 25 00 30 00 }
    $a4 = { 50 38 00 78 00 }
    $a5 = { 54 5D 00 20 00 }
    $a6 = { 58 25 00 77 00 }
    $a7 = { 5C 5A 00 5C 00 }
    $a8 = { 60 25 00 77 00 }
    $a9 = { 64 5A 00 09 00 }
    $a10 = { 6C 5A 00 0A 00 }
    $a11 = { 68 25 00 77 00 }
    $a12 = { 68 25 00 77 00 }
    $a13 = { 6C 5A 00 0A 00 }
    $b1 = { 6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67 }
condition:
    all of ($a*) or $b1
}

rule Windows_Hacktool_Mimikatz_355d5d3a {
  meta:
    id = "355d5d3a-e50e-4614-9a84-0da668c40852"
    fingerprint = "9a23845ec9852d2490171af111612dc257a6b21ad7fdfd8bf22d343dc301d135"
    creation_date = "2021-04-14"
    last_modified = "2021-04-14"
    description = "Detection for Invoke-Mimikatz"
    os = "Windows"
    arch = "x86"
    category_type = "Hacktool"
    family = "Mimikatz"
    threat_name = "Windows.Hacktool.Mimikatz"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "945245ca795e0a3575ee4fdc174df9d377a598476c2bf4bf0cdb0cde4286af96"
    scan_type = "File, Memory"
    severity = 90
  strings:
    $a1 = "$PEBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
    $a2 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
    $b1 = "Write-BytesToMemory -Bytes $Shellcode"
    $b2 = "-MemoryAddress $GetCommandLineWAddrTemp"
    $b3 = "-MemoryAddress $GetCommandLineAAddrTemp"
    $c1 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword
    $c2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam"
    $c3 = "at: http://blog.gentilkiwi.com"
    $c4 = "on the local computer to dump certificates."
    $c5 = "Throw \"Unable to write shellcode to remote process memory.\"" fullword
    $c6 = "-Command \"privilege::debug exit\" -ComputerName \"computer1\""
    $c7 = "dump credentials without"
    $c8 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword
    $c9 = "two remote computers to dump credentials."
    $c10 = "#If a remote process to inject in to is specified, get a handle to it" fullword
condition:
    (1 of ($a*) or 2 of ($b*)) or 5 of ($c*)
}

rule Windows_Ransomware_Bitpaymer_d74273b3 : beta {
  meta:
    name = "YARA Ransomware - BITPAYMER Variant B"
    id = "d74273b3-d109-4b5d-beff-dffee9a984b1"
    fingerprint = "4f913f06f7c7decbeb78187c566674f91ebbf929ad7057641659bb756cf2991b"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies BITPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Bitpaymer"
    threat_name = "Windows.Ransomware.Bitpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { 24 E8 00 00 00 29 F0 19 F9 89 8C 24 88 00 00 00 89 84 24 84 00 }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Bitpaymer_bca25ac6 : beta {
  meta:
    name = "YARA Ransomware - BITPAYMER Variant A"
    id = "bca25ac6-e351-4823-be75-b0661c89588a"
    fingerprint = "2ecc7884d47ca7dbba30ba171b632859914d6152601ea7b463c0f52be79ebb8c"
    creation_date = "2020-06-25"
    last_modified = "2021-03-18"
    description = "Identifies BITPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Bitpaymer"
    threat_name = "Windows.Ransomware.Bitpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "RWKGGE.PDB" fullword
    $a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
    $a3 = "04QuURX.pdb" fullword
    $a4 = "9nuhuNN.PDB" fullword
    $a5 = "mHtXGC.PDB" fullword
    $a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
    $a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
    $a8 = "k:\\softcare\\release\\h2O.pdb" fullword
condition:
    1 of ($a*)
}

rule Windows_Ransomware_Clop_6a1670aa : beta {
  meta:
    name = "YARA Ransomware - CLOP Variant B"
    id = "6a1670aa-7f78-455b-9e28-f39ed4c6476e"
    fingerprint = "7c24cc6a519922635a519dad412d1a07728317b91f90a120ccc1c7e7e2c8a002"
    creation_date = "2020-05-03"
    last_modified = "2021-02-16"
    description = "Identifies CLOP ransomware in unpacked state"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Clop"
    threat_name = "Windows.Ransomware.Clop"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = {  FF 15 04 E1 40 00 83 F8 03 74 0A 83 F8 02 }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Clop_e04959b5 : beta {
  meta:
    name = "YARA Ransomware - CLOP Variant A"
    id = "e04959b5-f3da-428d-8b56-8a9817fdebe0"
    fingerprint = "7367b90772ce6db0d639835a0a54a994ef8ed351b6dadff42517ed5fbc3d0d1a"
    creation_date = "2020-05-03"
    last_modified = "2021-03-18"
    description = "Identifies CLOP ransomware in unpacked state"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Clop"
    threat_name = "Windows.Ransomware.Clop"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "-%s\\CIopReadMe.txt" wide fullword
    $a2 = "CIopReadMe.txt" wide fullword
    $a3 = "%s-CIop^_" wide fullword
    $a4 = "%s%s.CIop" wide fullword
    $a5 = "BestChangeT0p^_-666" ascii fullword
    $a6 = ".CIop" wide fullword
    $a7 = "A%s\\ClopReadMe.txt" wide fullword
    $a8 = "%s%s.Clop" wide fullword
    $a9 = "CLOP#666" wide fullword
    $a10 = "MoneyP#666" wide fullword
condition:
    1 of ($a*)
}

rule Windows_Ransomware_Clop_9ac9ea3e : beta {
  meta:
    name = "YARA Ransomware - CLOP Variant C"
    id = "9ac9ea3e-72e1-4151-a2f8-87869f5f98e3"
    fingerprint = "1cb0adb36e94ef8f8d74862250205436ed3694ed7719d8e639cfdd0c8632fd6c"
    creation_date = "2020-05-03"
    last_modified = "2021-02-16"
    description = "Identifies CLOP ransomware in unpacked state"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Clop"
    threat_name = "Windows.Ransomware.Clop"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 8B 1D D8 E0 40 00 33 F6 8B 3D BC E0 40 00 }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Clop_606020e7 : beta {
  meta:
    name = "YARA Ransomware - CLOP Variant D"
    id = "606020e7-ce1a-4a48-b801-100fd22b3791"
    fingerprint = "5ec4e00ddf2cb1315ec7d62dd228eee0d9c15fafe4712933d42e868f83f13569"
    creation_date = "2020-05-03"
    last_modified = "2021-02-16"
    description = "Identifies CLOP ransomware in unpacked state"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Clop"
    threat_name = "Windows.Ransomware.Clop"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
    scan_type = "File, Memory"
    severity = 100
  strings:
  $d1 = { B8 E1 83 0F 3E F7 E6 8B C6 C1 EA 04 8B CA C1 E1 05 03 CA }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Darkside_d7fc4594 {
  meta:
    id = "d7fc4594-185c-4afb-986e-5718c0beabf1"
    fingerprint = "cc3adb3425b004fcc7b501932b9ac6c1531fbc35ee961680bfb06277b6c461b4"
    creation_date = "2021-05-20"
    last_modified = "2021-05-20"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Darkside"
    threat_name = "Windows.Ransomware.Darkside"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 5F 30 55 56 BD 0A 00 00 00 8B 07 8B 5F 10 8B 4F 20 8B 57 30 }
    $a2 = { 75 05 8A 16 46 12 D2 73 E6 02 D2 75 05 8A 16 46 12 D2 73 4F }
    $a3 = { 41 54 55 53 48 83 EC 28 48 8B 1F 4C 8B 66 08 48 8D 7C 24 10 4C }
condition:
    any of them
}

rule Windows_Ransomware_Dharma_aa5eefed : beta {
  meta:
    name = "YARA Ransomware - DHARMA Variant C"
    id = "aa5eefed-7212-42c9-b51d-2c58c65b53e5"
    fingerprint = "d3baf3474b450931b594322d190b243bdd813156ad80f04abcadde0db3bfe149"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies DHARMA ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Dharma"
    threat_name = "Windows.Ransomware.Dharma"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 4D F0 51 8B 55 E8 52 E8 CD 10 00 00 83 C4 08 89 45 E8 8A 45 F9 04 01 88 45 F9 0F B6 4D F9 8B 55 E4 8A 04 0A 88 45 FB 0F B6 4D FB 0F B6 55 FA 03 D1 88 55 FA 0F B6 45 FA 8B 4D E4 8A 14 01 88 55 EF 0F B6 45 F9 8B 4D E4 8A 55 EF 88 14 01 0F B6 45 FA 8B 4D E4 8A 55 FB 88 14 01 8B 45 0C 03 45 F4 0F B6 08 0F B6 55 FB 0F B6 45 EF 03 D0 0F B6 D2 8B 45 E4 0F B6 14 10 33 CA 8B 45 E8 03 45 F4 88 08 }
    $c2 = { 21 0C 7D 01 02 04 08 10 20 40 80 1B 36 6C D8 AB 4D 9A 2F 5E BC 63 C6 97 35 6A D4 B3 7D FA EF C5 91 00 00 A5 63 63 C6 84 7C 7C F8 99 77 77 EE 8D 7B 7B F6 0D F2 F2 FF BD 6B 6B D6 B1 6F 6F DE 54 C5 C5 91 50 30 30 60 03 01 01 02 A9 67 67 CE 7D 2B 2B 56 }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Dharma_b31cac3f : beta {
  meta:
    name = "YARA Ransomware - DHARMA Variant B"
    id = "b31cac3f-6e04-48b2-9d16-1a6b66fa8012"
    fingerprint = "25d23d045c57758dbb14092cff3cc190755ceb3a21c8a80505bd316a430e21fc"
    creation_date = "2020-06-25"
    last_modified = "2021-03-18"
    description = "Identifies DHARMA ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Dharma"
    threat_name = "Windows.Ransomware.Dharma"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
    scan_type = "File, Memory"
    severity = 100
    author = "Daniel Stepanic"
    rule_version = "1.0"
  strings:
    $b1 = "sssssbsss" ascii fullword
    $b2 = "sssssbs" ascii fullword
    $b3 = "RSDS%~m" ascii fullword
condition:
    3 of ($b*)
}

rule Windows_Ransomware_Dharma_e9319e4a : beta {
  meta:
    name = "YARA Ransomware - DHARMA Variant D"
    id = "e9319e4a-3850-4bad-9579-4b73199a0963"
    fingerprint = "4a4f3aebe4c9726cf62dde454f01cbf6dcb09bf3ef1b230d548fe255f01254aa"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies DHARMA ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Dharma"
    threat_name = "Windows.Ransomware.Dharma"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
    scan_type = "File, Memory"
    severity = 100
  strings:
  $d = { 08 8B 51 24 8B 45 08 8B 48 18 0F B7 14 51 85 D2 74 47 8B 45 08 8B }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Dharma_942142e3 : beta {
  meta:
    name = "YARA Ransomware - DHARMA Variant A"
    id = "942142e3-9197-41c4-86cc-66121c8a9ab5"
    fingerprint = "e8ee60d53f92dd1ade8cc956c13a5de38f9be9050131ba727f2fab41dde619a8"
    creation_date = "2020-06-25"
    last_modified = "2021-03-18"
    description = "Identifies DHARMA ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Dharma"
    threat_name = "Windows.Ransomware.Dharma"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "C:\\crysis\\Release\\PDB\\payload.pdb" ascii fullword
condition:
    1 of ($a*)
}

rule Windows_Ransomware_Doppelpaymer_6660d29f : beta {
  meta:
    name = "YARA Ransomware - DOPPELPAYMER Variant A"
    id = "6660d29f-aca9-4156-90a0-ce64fded281a"
    fingerprint = "8bf4d098b8ce9da99a2ca13fa0759a7185ade1b3ab3b281cd15749d68546d130"
    creation_date = "2020-06-28"
    last_modified = "2021-03-18"
    description = "Identifies DOPPELPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Doppelpaymer"
    threat_name = "Windows.Ransomware.Doppelpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Setup run" wide fullword
    $a2 = "RtlComputeCrc32" ascii fullword
condition:
    2 of ($a*)
}

rule Windows_Ransomware_Doppelpaymer_0b9b75b5 : beta {
  meta:
    name = "YARA Ransomware - DOPPELPAYMER Variant B"
    id = "0b9b75b5-f521-4414-8216-cde5de6b8ff7"
    fingerprint = "4fe2f648afa0031c2a4807ae882ddf19302ce6a6d26b04341950e84dbf6c1374"
    creation_date = "2020-06-28"
    last_modified = "2021-02-16"
    description = "Identifies DOPPELPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Doppelpaymer"
    threat_name = "Windows.Ransomware.Doppelpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { 8B D8 BA FF FF FF 7F 8B 4B }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Doppelpaymer_6ab188da : beta {
  meta:
    name = "YARA Ransomware - DOPPELPAYMER Variant D"
    id = "6ab188da-4e73-4669-816c-554b2f04ee65"
    fingerprint = "6c33e09e66b337064a1feae5c162f72dc5f6caecaa9829e4ad9fffb10ef3e576"
    creation_date = "2020-06-28"
    last_modified = "2021-02-16"
    description = "Identifies DOPPELPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Doppelpaymer"
    threat_name = "Windows.Ransomware.Doppelpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
    scan_type = "File, Memory"
    severity = 100
    author = "Daniel Stepanic"
    rule_version = "1.0"
  strings:
    $d1 = { 56 55 55 55 F7 EF B8 56 55 55 55 8B EA F7 E9 8B C2 8B D1 C1 FA 1F 2B C2 C1 FF 1F 2B EF 8D 14 40 B8 F3 1A CA 6B 2B CA 03 E9 F7 ED 8B CD C1 FA 05 C1 F9 1F 2B D1 6B CA B4 03 CD 74 1C 81 E1 03 00 00 80 7D 07 83 E9 01 83 C9 FC 41 8B C1 F7 D8 85 C9 8D 7C 05 04 0F 45 EF 8D 44 55 02 5D 5F C3 }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Doppelpaymer_4fb1a155 : beta {
  meta:
    name = "YARA Ransomware - DOPPELPAYMER Variant C"
    id = "4fb1a155-6448-41e9-829a-e765b7c2570e"
    fingerprint = "f7c1bb3e9d1ad02e7c4edf8accf326330331f92a0f1184bbc19c5bde7505e545"
    creation_date = "2020-06-28"
    last_modified = "2021-02-16"
    description = "Identifies DOPPELPAYMER ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Doppelpaymer"
    threat_name = "Windows.Ransomware.Doppelpaymer"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
    scan_type = "File, Memory"
    severity = 100
    author = "Daniel Stepanic"
    rule_version = "1.0"
  strings:
    $c1 = { 83 EC 64 8B E9 8B 44 24 ?? 8B 00 0F B7 10 83 FA 5C 75 }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Egregor_f24023f3 : beta {
  meta:
    name = "YARA Ransomware - EGREGOR Variant A"
    id = "f24023f3-c887-42fc-8927-cdbd04b5f84f"
    fingerprint = "3a82a548658e0823678ec9d633774018ddc6588f5e2fbce74826a46ce9c43c40"
    creation_date = "2020-10-15"
    last_modified = "2021-03-18"
    description = "Identifies EGREGOR (Sekhemt) ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Egregor"
    threat_name = "Windows.Ransomware.Egregor"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "M:\\sc\\p\\testbuild.pdb" ascii fullword
    $a2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" wide fullword
    $a3 = "nIcG`]/h3kpJ0QEAC5OJC|<eT}}\\5K|h\\\\v<=lKfHKO~01=Lo0C03icERjo0J|/+|=P0<UeN|e2F@GpTe]|wpMP`AG+IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi/G"
    $a4 = "pVrGRgJui@6ejnOu@4KgacOarSh|firCToW1LoF]7BtmQ@2j|hup2owUHQ6W}\\U3gwV6OwSPTMQVq2|G=GKrHpjOqk~`Ba<qu\\2]r0RKkf/HGngsK7LhtvtJiR}+4J"
    $a5 = "Your network was ATTACKED, your computers and servers were LOCKED," ascii wide
    $a6 = "Do not redact this special technical block, we need this to authorize you." ascii wide
condition:
    2 of ($a*)
}

rule Windows_Ransomware_Egregor_4ec2b90c : beta {
  meta:
    name = "YARA Ransomware - EGREGOR Variant B"
    id = "4ec2b90c-b2de-463d-a9c6-478c255c2352"
    fingerprint = "6ae13632f50af11626250c30f570370da23deb265ff6c1fefd2e294c8c170998"
    creation_date = "2020-10-15"
    last_modified = "2021-02-16"
    description = "Identifies EGREGOR (Sekhemt) ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Egregor"
    threat_name = "Windows.Ransomware.Egregor"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { 18 F5 46 E0 5C 94 28 B3 5C 94 28 B3 5C 94 28 B3 E8 08 D9 B3 55 94 28 B3 E8 08 DB B3 29 94 28 B3 E8 08 DA B3 44 94 28 B3 67 CA 2B B2 4D 94 28 B3 67 CA 2D B2 47 94 28 B3 67 CA 2C B2 4C 94 28 B3 81 6B E3 B3 5F 94 28 B3 5C 94 29 B3 02 94 28 B3 5C 94 28 B3 5F 94 28 B3 CE CA 28 B2 5D 94 28 B3 CE CA 2A B2 5D 94 28 B3 }
    $b2 = { 34 4F 51 46 33 5C 45 6A 75 5E 7E 4E 37 53 49 7C 49 50 4B 32 73 43 47 5E 68 43 42 4E 7C 42 30 48 62 4C 34 6D 3C 2F 36 76 3D 43 5D 6B 4F 30 32 6E 60 35 68 40 33 60 4B 47 6F 33 55 36 71 56 4A 3D 40 5C 6A 69 4B 4A 60 5C 35 2B 6B 40 33 31 5C 63 7D 4A 47 42 51 5D 70 54 68 7D 62 32 4B 72 6A 57 3C 71 }
    $b3 = { BB 05 10 D4 BB 05 10 E0 BB 05 10 EC BB 05 10 F8 BB 05 10 04 BC 05 10 10 BC 05 10 1C BC 05 10 2C BC 05 10 3C BC 05 10 50 BC 05 10 68 BC 05 10 80 BC 05 10 90 BC 05 10 A8 BC 05 10 B4 BC 05 10 C0 }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Hellokitty_8859e8e8 {
  meta:
    id = "8859e8e8-f94c-4853-b296-1fc801486c57"
    fingerprint = "f9791409d2a058dd68dc09df5e4b597c6c6a1f0da9801d7ab9e678577b621730"
    creation_date = "2021-05-03"
    last_modified = "2021-05-18"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Hellokitty"
    threat_name = "Windows.Ransomware.Hellokitty"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "HelloKittyMutex" wide fullword
    $a2 = "%s\\read_me_lkd.txt" wide fullword
    $a3 = "Win32_ShadowCopy.ID='%s'" wide fullword
    $a4 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!" wide fullword
    $a5 = "%s/secret/%S" wide fullword
    $a6 = "DECRYPT_NOTE.txt" wide fullword
    $a7 = "Some data has been stored in our servers and ready for publish." wide fullword
    $a9 = "To contact with us you have ONE week from the encryption time, after decryption keys and your personal contact link will be dele" wide
    $a10 = "In case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing." wide fullword
    $a11 = "IMPORTANT: Don't modify encrypted files or you can damage them and decryption will be impossible!" wide fullword
    $b1 = "/f /im \"%s\"" wide fullword
    $b2 = "stop \"%s\"" wide fullword
    $b3 = "/f /im %s" wide fullword
    $b4 = "stop %s" wide fullword
condition:
    (2 of ($a*) and 2 of ($b*)) or (5 of ($a*))
}

rule Windows_Ransomware_Hellokitty_4b668121 {
  meta:
    id = "4b668121-cc21-4f0b-b0fc-c2b5b4cb53e8"
    fingerprint = "834316ce0f3225b1654b3c4bccb673c9ad815e422276f61e929d5440ca51a9fa"
    creation_date = "2021-05-03"
    last_modified = "2021-05-18"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Hellokitty"
    threat_name = "Windows.Ransomware.Hellokitty"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
    $a2 = "(%d) [%d] %s: Looking for folder from cmd: %S" ascii fullword
    $a3 = "(%d) [%d] %s: ERROR: Failed to encrypt AES block" ascii fullword
    $a4 = "gHelloKittyMutex" wide fullword
    $a5 = "/C ping 127.0.0.1 & del %s" wide fullword
    $a6 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!"
    $a7 = "read_me_lkdtt.txt" wide fullword
    $a8 = "If you want to get it, you must pay us some money and we will help you." wide fullword
condition:
    5 of them
}

rule Windows_Ransomware_Hellokitty_d9391a1a {
  meta:
    id = "d9391a1a-78d3-4ae6-8e45-630ceec8bade"
    fingerprint = "4b9c96561163f925df6b2300c9e34c9572c1fe14ec3a55da4d4876ce467f6d6e"
    creation_date = "2021-05-03"
    last_modified = "2021-05-18"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Hellokitty"
    threat_name = "Windows.Ransomware.Hellokitty"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 83 6D 08 01 75 DF 89 47 FC 8B 45 F8 5F 5E 5B 8B E5 5D C3 89 }
    $a2 = { 8D 76 04 03 D0 3B D0 1B C0 03 14 BB F7 D8 3B 14 BB 89 56 FC }
    $a3 = { 83 C4 04 85 DB 75 12 0F 10 45 D4 83 C7 10 0F 11 06 83 C6 10 83 }
    $a4 = { 89 45 F8 3B 5D F4 75 25 3B C6 75 21 6A FF FF 75 14 8B D1 83 }
condition:
    any of them
}

rule Windows_Ransomware_Maze_61254061 : beta {
  meta:
    name = "YARA Ransomware - MAZE Variant C"
    id = "61254061-e8af-47ab-9cce-96debd99a80a"
    fingerprint = "670d9abbdea153ca66f24ef6806f97e9af3efb73f621167e95606da285627d1b"
    creation_date = "2020-04-18"
    last_modified = "2021-02-16"
    description = "Identifies MAZE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Maze"
    threat_name = "Windows.Ransomware.Maze"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { FC 8B 55 08 8B 44 8A 10 C1 E0 09 8B 4D FC 8B 55 08 8B 4C 8A 10 C1 }
    $c2 = { 72 F0 0C 66 0F 72 D4 14 66 0F EB C4 66 0F 70 E0 39 66 0F FE E6 66 0F 70 }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Maze_46f40c40 : beta {
  meta:
    name = "YARA Ransomware - MAZE Variant B"
    id = "46f40c40-05a4-4163-a62d-675882149781"
    fingerprint = "c5ae4051e553846e90e452b6e12182332f130e5255aabf92f12c8e86efb6755b"
    creation_date = "2020-04-18"
    last_modified = "2021-03-18"
    description = "Identifies MAZE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Maze"
    threat_name = "Windows.Ransomware.Maze"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" wide fullword
    $b2 = "Maze Ransomware" wide fullword
    $b3 = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" wide fullword
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Maze_20caee5b : beta {
  meta:
    name = "YARA Ransomware - MAZE Variant A"
    id = "20caee5b-cf7f-4db7-8c3b-67baf63bfc32"
    fingerprint = "47525839e0800f6edec6ad4580682a336e36f7d13bd9e7214eca0f16941016b8"
    creation_date = "2020-04-18"
    last_modified = "2021-03-18"
    description = "Identifies MAZE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Maze"
    threat_name = "Windows.Ransomware.Maze"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Win32_ShadowCopy.id='%s'" wide fullword
    $a2 = "\"%s\" shadowcopy delete" wide fullword
    $a3 = "%spagefile.sys" wide fullword
    $a4 = "%sswapfile.sys" wide fullword
    $a5 = "Global\\%s" wide fullword
    $a6 = "DECRYPT-FILES.txt" wide fullword
    $a7 = "process call create \"cmd /c start %s\"" wide fullword
condition:
    4 of ($a*)
}

rule Windows_Ransomware_Maze_f88f136f : beta {
  meta:
    name = "YARA Ransomware - MAZE Variant D"
    id = "f88f136f-755c-46d6-9dbe-243342ae315a"
    fingerprint = "3fa065d28d864868e49b394e895207c8be2252a9e211ac4bacce10d9ff04607e"
    creation_date = "2020-04-18"
    last_modified = "2021-02-16"
    description = "Identifies MAZE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Maze"
    threat_name = "Windows.Ransomware.Maze"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $d1 = { 00 67 00 20 00 69 00 6E 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6F 00 6E 00 73 00 20 00 69 00 6E 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2D 00 46 00 49 00 4C 00 45 00 53 00 2E }
    $d2 = { 70 C7 8B 75 6D 97 7E FC 19 2A 39 8C A4 AE AD 9C 62 05 B7 68 47 7D 02 F7 D3 0A DA 20 82 AE A8 E7 B2 26 E1 A0 5B 4E 17 09 A6 94 74 CA B6 0B 88 B0 5F 6E 11 E3 B0 EA 2F 40 D7 A2 AB 59 52 E0 F2 C2 19 24 14 95 01 7F CA }
    $d3 = { 77 B3 50 3C B1 9B 5D D4 87 F5 17 DB E1 C7 42 D8 53 24 C2 E2 6A A8 9B 1E FB E5 48 EB 10 48 44 28 64 F8 B6 A1 41 44 D0 42 FA 85 6F 17 57 09 C4 66 93 D2 21 C5 19 71 3A A1 C5 68 2E 67 B1 02 DC D1 }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Mountlocker_126a76e2 {
  meta:
    id = "126a76e2-8a97-4347-ac36-9437a512e16c"
    fingerprint = "08213f4474c7c8fd7a6e59c9ff139fb45f224109ad4e6162c12cff5ac85cb10c"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Mountlocker"
    threat_name = "Windows.Ransomware.Mountlocker"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "4a5ac3c6f8383cc33c795804ba5f7f5553c029bbb4a6d28f1e4d8fb5107902c1"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "[SKIP] locker.dir.check > black_list name=%s" wide fullword
    $a2 = "[OK] locker.dir.check > name=%s" wide fullword
    $a3 = "[ERROR] locker.worm > execute pcname=%s" wide fullword
    $a4 = "[INFO] locker.work.enum.net_drive > enum finish name=%s" wide fullword
    $a5 = "[WARN] locker.work.enum.server_shares > logon on server error=%u pcname=%s" wide fullword
condition:
    any of them
}

rule Windows_Ransomware_Phobos_a5420148 : beta {
  meta:
    name = "YARA Ransomware - PHOBOS Variant A"
    id = "a5420148-2f80-4a14-8a0d-98943fcbe784"
    fingerprint = "2b3937dbecb9a12e5e276c681eb40cb3884411a048175fcfe1bd4be3f7611aca"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies Phobos ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Phobos"
    threat_name = "Windows.Ransomware.Phobos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 61 00 63 00 75 00 74 00 65 00 00 00 61 00 63 00 74 00 69 00 6E 00 00 00 61 00 63 00 74 00 6F 00 6E 00 00 00 61 00 63 00 74 00 6F 00 72 00 00 00 61 00 63 00 75 00 66 00 66 00 00 }
    $a2 = { 0C 6D 00 73 00 66 00 74 00 65 00 73 00 71 00 6C 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 61 00 67 00 65 00 6E 00 74 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 73 00 65 00 72 00 76 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 77 00 72 00 69 00 74 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 6F 00 72 00 61 00 63 00 6C 00 65 00 2E 00 65 00 78 00 }
    $a3 = { 31 00 63 00 64 00 00 00 33 00 64 00 73 00 00 00 33 00 66 00 72 00 00 00 33 00 67 00 32 00 00 00 33 00 67 00 70 00 00 00 37 00 7A 00 00 00 61 00 63 00 63 00 64 00 61 00 00 00 61 00 63 00 63 00 64 00 62 00 00 00 61 00 63 00 63 00 64 00 63 00 00 00 61 00 63 00 63 00 64 00 65 00 00 00 61 00 63 00 63 00 64 00 74 00 00 00 61 00 63 00 63 00 64 00 77 00 00 00 61 00 64 00 62 00 00 00 61 00 64 00 70 00 00 00 61 00 69 00 00 00 61 00 69 00 33 00 00 00 61 00 69 00 34 00 00 00 61 00 69 00 35 00 00 00 61 00 69 00 36 00 00 00 61 00 69 00 37 00 00 00 61 00 69 00 38 00 00 00 61 00 6E 00 69 00 6D 00 00 00 61 00 72 00 77 00 00 00 61 00 73 00 00 00 61 00 73 00 61 00 00 00 61 00 73 00 63 00 00 00 61 00 73 00 63 00 78 00 00 00 61 00 73 00 6D 00 00 00 61 00 73 00 6D 00 78 00 00 00 61 00 73 00 70 00 00 00 61 00 73 00 70 00 78 00 00 00 61 00 73 00 72 00 00 00 61 00 73 00 78 00 00 00 61 00 76 00 69 00 00 00 61 00 76 00 73 00 00 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 00 62 00 61 00 6B 00 00 00 62 00 61 00 79 00 00 00 62 00 64 00 00 00 62 00 69 00 6E 00 00 00 62 00 6D 00 70 00 00 00 }
condition:
    2 of ($a*)
}

rule Windows_Ransomware_Phobos_ff55774d : beta {
  meta:
    name = "YARA Ransomware - PHOBOS Variant C"
    id = "ff55774d-4425-4243-8156-ce029c1d5860"
    fingerprint = "d8016c9be4a8e5b5ac32b7108542fee8426d65b4d37e2a9c5ad57284abb3781e"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies Phobos ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Phobos"
    threat_name = "Windows.Ransomware.Phobos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 24 18 83 C4 0C 8B 4F 0C 03 C6 50 8D 54 24 18 52 51 6A 00 6A 00 89 44 }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Phobos_11ea7be5 : beta {
  meta:
    name = "YARA Ransomware - PHOBOS Variant B"
    id = "11ea7be5-7aac-41d7-8d09-45131a9c656e"
    fingerprint = "a264f93e085134e5114c5d72e1bf93e70935e33756a79f1021e9c1e71d6c8697"
    creation_date = "2020-06-25"
    last_modified = "2021-02-16"
    description = "Identifies Phobos ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Phobos"
    threat_name = "Windows.Ransomware.Phobos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { C0 74 30 33 C0 40 8B CE D3 E0 85 C7 74 19 66 8B 04 73 66 89 }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Ragnarok_1cab7ea1 : beta {
  meta:
    name = "YARA Ransomware - RAGNAROK Variant C"
    id = "1cab7ea1-8d26-4478-ab41-659c193b5baa"
    fingerprint = "e2a8eabb08cb99c4999e05a06d0d0dce46d7e6375a72a6a5e69d718c3d54a3ad"
    creation_date = "2020-05-03"
    last_modified = "2021-03-18"
    description = "Identifies RAGNAROK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ragnarok"
    threat_name = "Windows.Ransomware.Ragnarok"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
    scan_type = "File, Memory"
    severity = 100
    author = "Daniel Stepanic"
    rule_version = "1.0"
  strings:
    $c1 = ".ragnarok" ascii wide fullword
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Ragnarok_7e802f95 : beta {
  meta:
    name = "YARA Ransomware - RAGNAROK Variant D"
    id = "7e802f95-964e-4dd9-a5d1-13a6cd73d750"
    fingerprint = "c62b3706a2024751f1346d0153381ac28057995cf95228e43affc3d1e4ad0fad"
    creation_date = "2020-05-03"
    last_modified = "2021-02-16"
    description = "Identifies RAGNAROK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ragnarok"
    threat_name = "Windows.Ransomware.Ragnarok"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $d1 = { 68 04 94 42 00 FF 35 A0 77 43 00 }
    $d2 = { 68 90 94 42 00 FF 35 A0 77 43 00 E8 8F D6 00 00 8B 40 10 50 }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Ragnarok_efafbe48 : beta {
  meta:
    name = "YARA Ransomware - RAGNAROK Variant A"
    id = "efafbe48-7740-4c21-b585-467f7ad76f8d"
    fingerprint = "a1535bc01756ac9e986eb564d712b739df980ddd61cfde5a7b001849a6b07b57"
    creation_date = "2020-05-03"
    last_modified = "2021-03-18"
    description = "Identifies RAGNAROK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ragnarok"
    threat_name = "Windows.Ransomware.Ragnarok"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "cmd_firewall" ascii fullword
    $a2 = "cmd_recovery" ascii fullword
    $a3 = "cmd_boot" ascii fullword
    $a4 = "cmd_shadow" ascii fullword
    $a5 = "readme_content" ascii fullword
    $a6 = "readme_name" ascii fullword
    $a8 = "rg_path" ascii fullword
    $a9 = "cometosee" ascii fullword
    $a10 = "&prv_ip=" ascii fullword
condition:
    6 of ($a*)
}

rule Windows_Ransomware_Ragnarok_5625d3f6 : beta {
  meta:
    name = "YARA Ransomware - RAGNAROK Variant B"
    id = "5625d3f6-7071-4a09-8ddf-faa2d081b539"
    fingerprint = "5c0a4e2683991929ff6307855bf895e3f13a61bbcc6b3c4b47d895f818d25343"
    creation_date = "2020-05-03"
    last_modified = "2021-03-18"
    description = "Identifies RAGNAROK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ragnarok"
    threat_name = "Windows.Ransomware.Ragnarok"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = "prv_ip" ascii fullword
    $b2 = "%i.%i.%i" ascii fullword
    $b3 = "pub_ip" ascii fullword
    $b4 = "cometosee" ascii fullword
condition:
    all of ($b*)
}

rule Windows_Ransomware_Ryuk_25d3c5ba : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant G"
    id = "25d3c5ba-8f80-4af0-8a5d-29c974fb016a"
    fingerprint = "18e70599e3a187e77697844fa358dd150e7e25ac74060e8c7cf2707fb7304efd"
    creation_date = "2020-04-30"
    last_modified = "2021-02-16"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }
condition:
    1 of ($g*)
}

rule Windows_Ransomware_Ryuk_878bae7e : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant B"
    id = "878bae7e-1e53-4648-93aa-b4075eef256d"
    fingerprint = "93a501463bb2320a9ab824d70333da2b6f635eb5958d6f8de43fde3a21de2298"
    creation_date = "2020-04-30"
    last_modified = "2021-03-18"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b2 = "RyukReadMe.html" wide fullword
    $b3 = "RyukReadMe.txt" wide fullword
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Ryuk_6c726744 : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant A"
    id = "6c726744-acdb-443a-b683-b11f8b657f7a"
    fingerprint = "d0a4608907e48d02d78ff40a59d47cad1b9258df31b7312dd1a85f8fee2a28d5"
    creation_date = "2020-04-30"
    last_modified = "2021-03-18"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "172.16." ascii fullword
    $a2 = "192.168." ascii fullword
    $a3 = "DEL /F" wide fullword
    $a4 = "lsaas.exe" wide fullword
    $a5 = "delete[]" ascii fullword
condition:
    4 of ($a*)
}

rule Windows_Ransomware_Ryuk_1a4ad952 : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant E"
    id = "1a4ad952-cc99-4653-932b-290381e7c871"
    fingerprint = "d8c5162850e758e27439e808e914df63f42756c0b8f7c2b5f9346c0731d3960c"
    creation_date = "2020-04-30"
    last_modified = "2021-02-16"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }
condition:
    1 of ($e*)
}

rule Windows_Ransomware_Ryuk_72b5fd9d : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant D"
    id = "72b5fd9d-23db-4f18-88d9-a849ec039135"
    fingerprint = "7c394aa283336013b74a8aaeb56e8363033958b4a1bd8011f3b32cfe2d37e088"
    creation_date = "2020-04-30"
    last_modified = "2021-02-16"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Ryuk_8ba51798 : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant C"
    id = "8ba51798-15d7-4f02-97fa-1844465ae9d8"
    fingerprint = "8e284bc6015502577a6ddd140b9cd110fd44d4d2cb55d0fdec5bebf3356fd7b3"
    creation_date = "2020-04-30"
    last_modified = "2021-03-18"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = "/v \"svchos\" /f" wide fullword
    $c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
    $c3 = "lsaas.exe" wide fullword
    $c4 = "FA_Scheduler" wide fullword
    $c5 = "ocautoupds" wide fullword
    $c6 = "CNTAoSMgr" wide fullword
    $c7 = "hrmlog" wide fullword
    $c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword
condition:
    3 of ($c*)
}

rule Windows_Ransomware_Ryuk_88daaf8e : beta {
  meta:
    name = "YARA Ransomware - RYUK Variant F"
    id = "88daaf8e-0bfe-46c4-9a75-2527d0e10538"
    fingerprint = "b1f218a9bc6bf5f3ec108a471de954988e7692de208e68d7d4ee205194cbbb40"
    creation_date = "2020-04-30"
    last_modified = "2021-02-16"
    description = "Identifies RYUK ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Ryuk"
    threat_name = "Windows.Ransomware.Ryuk"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }
condition:
    1 of ($f*)
}

rule Windows_Ransomware_Snake_550e0265 : beta {
  meta:
    name = "YARA Ransomware - SNAKE Variant A"
    id = "550e0265-fca9-46df-9d5a-cf3ef7efc7ff"
    fingerprint = "f2796560ddc85ad98a5ef4f0d7323948d57116813c8a26ab902fdfde849704e0"
    creation_date = "2020-06-30"
    last_modified = "2021-03-18"
    description = "Identifies SNAKE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Snake"
    threat_name = "Windows.Ransomware.Snake"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\"" ascii fullword
    $a2 = "We breached your corporate network and encrypted the data on your computers."
    $a3 = "c:\\users\\public\\desktop\\Fix-Your-Files.txt" nocase
    $a4 = "%System Root%\\Fix-Your-Files.txt" nocase
    $a5 = "%Desktop%\\Fix-Your-Files.txt" nocase
condition:
    1 of ($a*)
}

rule Windows_Ransomware_Snake_119f9c83 : beta {
  meta:
    name = "YARA Ransomware - SNAKE Variant C"
    id = "119f9c83-4b55-47ce-8c0d-3799a7b46369"
    fingerprint = "13ffd63c31df2cbaa6988abcaff3b0a3518437f1d37dcd872817b9cbdb61576f"
    creation_date = "2020-06-30"
    last_modified = "2021-02-16"
    description = "Identifies SNAKE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Snake"
    threat_name = "Windows.Ransomware.Snake"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 00 40 83 7C 00 40 9E 7C 00 60 75 7C 00 B0 6C 7C 00 B0 74 7C 00 D0 74 7C 00 B0 59 7C 00 D0 59 7C 00 F0 59 7C 00 10 5A 7C 00 30 5A 7C 00 50 5A 7C 00 70 5A 7C 00 90 5A 7C 00 B0 5A 7C 00 D0 5A 7C 00 D0 6C 7C 00 F0 5A 7C 00 30 5B 7C 00 50 5B 7C 00 70 5B 7C 00 90 5B 7C 00 D0 5E 7C 00 B0 5B 7C 00 D0 5B 7C 00 F0 5B 7C 00 50 60 7C 00 70 61 7C 00 10 5C 7C 00 30 5C 7C 00 50 5C 7C 00 10 63 7C 00 70 5C 7C 00 90 5C 7C 00 90 64 7C 00 B0 5C 7C 00 F0 5C 7C 00 10 5D 7C 00 F0 6C 7C 00 10 6D 7C 00 30 5D 7C 00 50 5D 7C 00 30 6D 7C 00 90 71 7C 00 70 5D 7C 00 90 5D 7C 00 B0 5D 7C 00 D0 5D 7C 00 70 6D 7C 00 F0 5D 7C 00 10 5E 7C 00 30 5E 7C 00 50 5E 7C 00 70 5E 7C 00 90 5E 7C 00 B0 5E 7C 00 F0 5E 7C 00 10 5F 7C 00 30 5F 7C 00 50 5F 7C 00 70 5F 7C 00 90 6D 7C 00 90 5F 7C 00 B0 6D 7C 00 D0 6D 7C 00 F0 6D 7C 00 10 6E 7C 00 B0 5F 7C 00 D0 5F 7C 00 F0 5F 7C 00 10 60 7C 00 30 60 7C 00 30 6E 7C 00 70 60 7C }
    $c2 = { 00 30 64 7C 00 50 64 7C 00 70 64 7C 00 B0 64 7C 00 D0 64 7C 00 30 73 7C 00 F0 64 7C 00 90 71 7C 00 10 65 7C 00 30 65 7C 00 50 65 7C 00 90 72 7C 00 B0 72 7C 00 70 6E 7C 00 70 65 7C 00 B0 65 7C 00 D0 65 7C 00 F0 65 7C 00 10 66 7C 00 30 66 7C 00 50 66 7C 00 70 66 7C 00 90 66 7C 00 B0 66 7C 00 D0 66 7C 00 F0 66 7C 00 30 67 7C 00 90 6E 7C 00 B0 6E 7C 00 D0 6E 7C }
condition:
    1 of ($c*)
}

rule Windows_Ransomware_Snake_0cfc8ef3 : beta {
  meta:
    name = "YARA Ransomware - SNAKE Variant D"
    id = "0cfc8ef3-d8cc-4fc0-9ca2-8e84dbcb45bd"
    fingerprint = "4dd2565c42d52f20b9787a6ede9be24837f6df19dfbbd4e58e5208894741ba26"
    creation_date = "2020-06-30"
    last_modified = "2021-02-16"
    description = "Identifies SNAKE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Snake"
    threat_name = "Windows.Ransomware.Snake"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $d1 = { 96 88 44 2C 1E 96 45 }
    $d2 = { 39 C5 7D ?? 0F B6 34 2B 39 D5 73 ?? 0F B6 3C 29 31 FE 83 FD 1A 72 }
condition:
    1 of ($d*)
}

rule Windows_Ransomware_Snake_20bc5abc : beta {
  meta:
    name = "YARA Ransomware - SNAKE Variant B"
    id = "20bc5abc-c519-47d2-a6de-5108071a9144"
    fingerprint = "e7f1be2bd7e1f39b79ac89cf58c90abdb537ff54cbf161192d997e054d3f0883"
    creation_date = "2020-06-30"
    last_modified = "2021-02-16"
    description = "Identifies SNAKE ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Snake"
    threat_name = "Windows.Ransomware.Snake"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { 57 12 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Sodinokibi_83f05fbe : beta {
  meta:
    name = "YARA Ransomware - SODINOKIBI - VTDIFF"
    id = "83f05fbe-65d1-423f-98df-21692167a1d6"
    fingerprint = "8c32ca099c9117e394379c0cc4771a15e5e4cfb1a98210c288e743a6d9cc9967"
    creation_date = "2020-06-18"
    last_modified = "2021-02-16"
    description = "Identifies SODINOKIBI/REvil ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Sodinokibi"
    threat_name = "Windows.Ransomware.Sodinokibi"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $d1 = { 03 C0 01 47 30 11 4F 34 01 57 30 8B 57 78 8B C2 11 77 34 8B 77 7C 8B CE 0F A4 C1 04 C1 E0 04 01 47 28 8B C2 11 4F 2C 8B CE 0F A4 C1 01 03 C0 01 47 28 11 4F 2C 01 57 28 8B 57 70 8B C2 11 77 2C 8B 77 74 8B CE 0F A4 C1 04 C1 E0 04 01 47 20 8B C2 11 4F 24 8B CE 0F A4 C1 01 03 C0 01 47 20 11 4F 24 01 57 20 8B 57 68 8B C2 11 77 24 8B 77 6C 8B CE 0F A4 C1 04 C1 E0 04 01 47 18 8B C2 11 4F 1C 8B CE 0F A4 C1 01 03 C0 01 47 18 11 4F 1C 01 57 18 8B 57 60 8B C2 11 77 1C 8B 77 64 }
    $d2 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
    $d3 = { F7 6F 38 03 C8 8B 43 48 13 F2 F7 6F 20 03 C8 8B 43 38 13 F2 F7 6F 30 03 C8 8B 43 40 13 F2 F7 6F 28 03 C8 8B 43 28 13 F2 F7 6F 40 03 C8 8B 45 08 13 F2 89 48 68 89 70 6C 8B 43 38 F7 6F 38 8B C8 8B F2 8B 43 28 F7 6F 48 03 C8 13 F2 8B 43 48 F7 6F 28 03 C8 8B 43 30 13 F2 F7 6F 40 0F A4 CE 01 03 C9 03 C8 8B 43 40 13 F2 F7 6F 30 03 C8 8B 45 08 13 F2 89 48 70 89 70 74 8B 43 38 F7 6F 40 8B C8 }
    $d4 = { 33 C0 8B 5A 68 8B 52 6C 0F A4 FE 08 C1 E9 18 0B C6 C1 E7 08 8B 75 08 0B CF 89 4E 68 8B CA 89 46 6C 33 C0 8B 7E 60 8B 76 64 0F A4 DA 19 C1 E9 07 0B C2 C1 E3 19 8B 55 08 0B CB 89 4A 60 8B CF 89 42 64 33 C0 8B 5A 10 8B 52 14 0F AC F7 15 C1 E1 0B C1 EE 15 0B C7 0B CE 8B 75 }
    $d5 = { C1 01 C1 EE 1F 0B D1 03 C0 0B F0 8B C2 33 43 24 8B CE 33 4B 20 33 4D E4 33 45 E0 89 4B 20 8B CB 8B 5D E0 89 41 24 8B CE 33 4D E4 8B C2 31 4F 48 33 C3 8B CF 31 41 4C 8B C7 8B CE 33 48 70 8B C2 33 47 74 33 4D E4 33 C3 89 4F 70 8B CF 89 41 74 8B }
    $d6 = { 8B 43 40 F7 6F 08 03 C8 8B 03 13 F2 F7 6F 48 03 C8 8B 43 48 13 F2 F7 2F 03 C8 8B 43 08 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 18 03 C8 8B 43 18 13 F2 F7 6F 30 03 C8 8B 43 38 13 F2 F7 6F 10 03 C8 8B 43 10 13 F2 F7 6F 38 03 C8 8B 43 28 13 F2 }
    $d7 = { 8B CE 33 4D F8 8B C2 33 C3 31 4F 18 8B CF 31 41 1C 8B C7 8B CE 33 48 40 8B C2 33 4D F8 33 47 44 89 4F 40 33 C3 8B CF 89 41 44 8B C7 8B CE 33 48 68 8B C2 33 47 6C 33 4D F8 33 C3 89 4F 68 8B CF 89 41 6C 8B CE 8B }
    $d8 = { 36 7D 49 30 85 35 C2 C3 68 60 4B 4B 7A BE 83 53 AB E6 8E 42 F9 C6 62 A5 D0 6A AD C6 F1 7D F6 1D 79 CD 20 FC E7 3E E1 B8 1A 43 38 12 C1 56 28 1A 04 C9 22 55 E0 D7 08 BB 9F 0B 1F 1C B9 13 06 35 }
    $d9 = { C2 C1 EE 03 8B 55 08 0B CE 89 4A 4C 8B CF 89 42 48 33 C0 8B 72 30 8B 52 34 C1 E9 0C 0F A4 DF 14 0B C7 C1 E3 14 8B 7D 08 0B CB 89 4F 30 8B CE 89 47 34 33 C0 C1 E1 0C 0F AC D6 14 0B C6 C1 EA 14 89 47 08 0B CA }
    $d10 = { 8B F2 8B 43 38 F7 6F 28 03 C8 8B 43 18 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 38 03 C8 8B 43 40 13 F2 F7 6F 20 0F A4 CE 01 03 C9 03 C8 8B 43 20 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 30 03 C8 }
    $d11 = { 33 45 FC 31 4B 28 8B CB 31 41 2C 8B CE 8B C3 33 48 50 8B C2 33 43 54 33 CF 33 45 FC 89 4B 50 8B CB 89 41 54 8B CE 8B C3 33 48 78 8B C2 33 43 7C 33 CF 33 45 FC 89 4B 78 8B CB 89 41 7C 33 B1 A0 }
    $d12 = { 52 24 0F A4 FE 0E C1 E9 12 0B C6 C1 E7 0E 8B 75 08 0B CF 89 4E 20 8B CA 89 46 24 33 C0 8B 7E 78 8B 76 7C 0F A4 DA 1B C1 E9 05 0B C2 C1 E3 1B 8B 55 08 0B CB 89 4A 78 8B CF 89 42 7C 33 C0 8B 9A }
    $d13 = { F2 8B 43 38 F7 6F 20 03 C8 8B 43 40 13 F2 F7 6F 18 03 C8 8B 43 10 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 30 03 C8 8B 43 20 13 F2 F7 6F 38 03 C8 8B 43 30 13 F2 F7 6F 28 03 C8 8B 43 48 13 F2 }
    $d14 = { 8B 47 30 13 F2 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 74 03 C9 89 4B 70 8B 47 30 F7 6F 48 8B C8 8B F2 8B 47 38 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 7C 03 C9 89 4B 78 8B 47 38 F7 6F 48 8B C8 }
condition:
    all of them
}

rule Windows_Ransomware_Sodinokibi_182b2cea : beta {
  meta:
    name = "YARA Ransomware - SODINOKIBI - YARP"
    id = "182b2cea-5aae-443a-9a2e-b3121a0ac8c7"
    fingerprint = "ab0eded4a21d0735132ea7fc7231cab16ad7c222fadeaa648de6e8dc4494ff44"
    creation_date = "2020-06-18"
    last_modified = "2021-03-18"
    description = "Identifies SODINOKIBI/REvil ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Sodinokibi"
    threat_name = "Windows.Ransomware.Sodinokibi"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "expand 32-byte kexpand 16-byte k" ascii fullword
    $b1 = "ServicesActive" wide fullword
    $b2 = "CreateThread" ascii fullword
    $b3 = "GetExitCodeProcess" ascii fullword
    $b4 = "CloseHandle" ascii fullword
    $b5 = "SetErrorMode" ascii fullword
    $b6 = ":!:(:/:6:C:\\:m:" ascii fullword
    $b7 = "tnFhC9mCc4Q6dehM6ho7Xc7oGS8PLAV6Sp" ascii fullword
condition:
    ($a1 and 5 of ($b*))
}

rule Windows_Ransomware_Sodinokibi_a282ba44 : beta {
  meta:
    name = "YARA Ransomware - SODINOKIBI - BESKAR"
    id = "a282ba44-b8bf-4fcc-a1c4-795675a928de"
    fingerprint = "07f1feb22f8b9de0ebd5c4649545eb4823a274b49b2c61a44d3eed4739ecd572"
    creation_date = "2020-06-18"
    last_modified = "2021-02-16"
    description = "Identifies SODINOKIBI/REvil ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Sodinokibi"
    threat_name = "Windows.Ransomware.Sodinokibi"
    source = "Automated"
    maturity = "Diagnostic"
    reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 59 59 85 F6 74 25 8B 55 08 83 66 04 00 89 3E 8B 0A 0B 4A 04 }
    $c2 = { 8D 45 F8 89 75 FC 50 8D 45 FC 89 75 F8 50 56 56 6A 01 6A 30 }
    $c3 = { 75 0C 72 D3 33 C0 40 5F 5E 5B 8B E5 5D C3 33 C0 EB F5 55 8B EC 83 }
    $c4 = { 0C 8B 04 B0 83 78 04 05 75 1C FF 70 08 FF 70 0C FF 75 0C FF }
    $c5 = { FB 8B 45 FC 50 8B 08 FF 51 08 5E 8B C7 5F 5B 8B E5 5D C3 55 }
    $c6 = { BC 00 00 00 33 D2 8B 4D F4 8B F1 8B 45 F0 0F A4 C1 01 C1 EE 1F }
    $c7 = { 54 8B CE F7 D1 8B C2 23 4D DC F7 D0 33 4D F4 23 C7 33 45 E8 89 }
    $c8 = { 0C 89 46 0C 85 C0 75 2A 33 C0 EB 6C 8B 46 08 85 C0 74 62 6B }
condition:
    (6 of ($c*))
}

rule Windows_Ransomware_Stop_1e8d48ff {
  meta:
    id = "1e8d48ff-e0ab-478d-8268-a11f2e87ab79"
    fingerprint = "715888e3e13aaa33f2fd73beef2c260af13e9726cb4b43d349333e3259bf64eb"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Stop"
    threat_name = "Windows.Ransomware.Stop"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "821b27488f296e15542b13ac162db4a354cbf4386b6cd40a550c4a71f4d628f3"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
    $b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF }
condition:
    any of them
}

rule Windows_Ransomware_Thanos_c3522fd0 : beta {
  meta:
    name = "YARA Ransomware - THANOS Variant C"
    id = "c3522fd0-90e2-4dd9-82f1-4502689270dd"
    fingerprint = "6d9d6131fd0e3a8585900f4966cb2d1b32e7f5d71b9a65b7a47d80e94bd9f89a"
    creation_date = "2020-11-03"
    last_modified = "2021-02-16"
    description = "Identifies THANOS (Hakbit) ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Thanos"
    threat_name = "Windows.Ransomware.Thanos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $c1 = { 0C 89 45 F0 83 65 EC 00 EB 07 8B 45 EC 40 89 45 EC 83 7D EC 18 }
    $c2 = { E8 C1 E0 04 8B 4D FC C6 44 01 09 00 8B 45 E8 C1 E0 04 8B 4D FC 83 64 01 }
    $c3 = { 00 2F 00 18 46 00 54 00 50 00 20 00 55 00 73 00 65 00 72 00 4E 00 }
condition:
    2 of ($c*)
}

rule Windows_Ransomware_Thanos_a6c09942 : beta {
  meta:
    name = "YARA Ransomware - THANOS Variant B"
    id = "a6c09942-0733-40d7-87b7-eb44dd472a35"
    fingerprint = "4abcf47243bebc281566ba4929b20950e3f1bfac8976ae5bc6b8ffda85468ec0"
    creation_date = "2020-11-03"
    last_modified = "2021-02-16"
    description = "Identifies THANOS (Hakbit) ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Thanos"
    threat_name = "Windows.Ransomware.Thanos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $b1 = { 00 57 00 78 00 73 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 6D 00 6C 00 73 00 5A 00 58 00 4D 00 67 00 64 00 32 00 56 00 79 00 5A 00 53 00 42 00 6C 00 62 00 6D 00 4E 00 79 00 65 00 58 00 42 00 30 00 5A 00 57 00 51 00 73 00 49 00 47 00 6C 00 6D 00 49 00 48 00 6C 00 76 00 64 00 53 00 42 00 33 00 59 00 57 00 35 00 30 00 49 00 48 00 52 00 76 00 49 00 47 00 64 00 6C 00 64 00 43 00 42 00 30 00 61 00 47 00 56 00 74 00 49 00 47 00 46 00 73 00 62 00 43 00 42 00 69 00 59 00 57 00 4E 00 72 00 4C 00 43 00 42 00 77 00 62 00 47 00 56 00 68 00 63 00 32 00 55 00 67 00 59 00 32 00 46 00 79 00 5A 00 57 00 5A 00 31 00 62 00 47 00 78 00 35 00 49 00 48 00 4A 00 6C 00 59 00 57 00 51 00 67 00 64 00 47 00 68 00 6C 00 49 00 48 00 52 00 6C 00 65 00 48 00 51 00 67 00 62 00 6D 00 39 00 30 00 5A 00 53 00 42 00 73 00 62 00 32 00 4E 00 68 00 64 00 47 00 56 00 6B 00 49 00 47 00 6C 00 75 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 47 00 56 00 7A 00 61 00 33 00 52 00 76 00 63 00 43 00 34 00 75 00 4C 00 67 00 3D 00 3D }
    $b2 = { 01 0E 0E 05 00 02 0E 0E 0E 04 00 01 01 0E 04 00 01 0E 0E 06 00 03 01 0E 0E 0E 80 90 55 00 30 00 39 00 47 00 56 00 46 00 64 00 42 00 55 00 6B 00 56 00 63 00 54 00 57 00 6C 00 6A 00 63 00 6D 00 39 00 7A 00 62 00 32 00 5A 00 30 00 58 00 46 00 64 00 70 00 62 00 6D 00 52 00 76 00 64 00 33 00 4D 00 67 00 54 00 6C 00 52 00 63 00 51 00 33 00 56 00 79 00 63 00 6D 00 56 00 75 00 64 00 46 00 5A 00 6C 00 63 00 6E 00 4E 00 70 00 62 00 32 00 35 00 63 00 56 00 32 00 6C 00 }
condition:
    1 of ($b*)
}

rule Windows_Ransomware_Thanos_e19feca1 : beta {
  meta:
    name = "YARA Ransomware - THANOS Variant A"
    id = "e19feca1-b131-4045-be0c-d69d55f9a83e"
    fingerprint = "d6654d0b3155d9c64fd4e599ba34d51f110d9dfda6fa1520b686602d9f608f92"
    creation_date = "2020-11-03"
    last_modified = "2021-03-18"
    description = "Identifies THANOS (Hakbit) ransomware"
    os = "Windows"
    arch = "x86"
    category_type = "Ransomware"
    family = "Thanos"
    threat_name = "Windows.Ransomware.Thanos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "<GetIPInfo>b__"
    $a2 = "<Killproc>b__"
    $a3 = "<Crypt>b__"
    $a4 = "<Encrypt2>b__"
    $b1 = "Your files are encrypted."
    $b2 = "I will treat you good if you treat me good too."
    $b3 = "I don't want to loose your files too"
    $b4 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide fullword
    $b5 = "\\HOW_TO_DECYPHER_FILES.txt" wide fullword
    $b6 = "c3RvcCBTUUxURUxFTUVUUlkkRUNXREIyIC95" wide fullword
    $b7 = "c3RvcCBNQkFNU2VydmljZSAveQ==" wide fullword
    $b8 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsIA==" wide fullword
    $b9 = "c3RvcCBjY0V2dE1nciAveQ==" wide fullword
condition:
    (4 of ($a*)) or (3 of ($b*))
}

rule Windows_Trojan_AgentTesla_d3ac2b2f {
  meta:
    id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
    fingerprint = "60c031526f8c3099f324b9dccaad3e8e7fb60c85ef79237aa9917e128b072c14"
    creation_date = "2021-03-22"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "AgentTesla"
    threat_name = "Windows.Trojan.AgentTesla"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "GetMozillaFromLogins" ascii fullword
    $a2 = "AccountConfiguration+username" wide fullword
    $a3 = "MailAccountConfiguration" ascii fullword
    $a4 = "KillTorProcess" ascii fullword
    $a5 = "SmtpAccountConfiguration" ascii fullword
    $a6 = "GetMozillaFromSQLite" ascii fullword
    $a7 = "Proxy-Agent: HToS5x" wide fullword
    $a8 = "set_BindingAccountConfiguration" ascii fullword
    $a9 = "doUsernamePasswordAuth" ascii fullword
    $a10 = "SafariDecryptor" ascii fullword
    $a11 = "get_securityProfile" ascii fullword
    $a12 = "get_useSeparateFolderTree" ascii fullword
    $a13 = "get_DnsResolver" ascii fullword
    $a14 = "get_archivingScope" ascii fullword
    $a15 = "get_providerName" ascii fullword
    $a16 = "get_ClipboardHook" ascii fullword
    $a17 = "get_priority" ascii fullword
    $a18 = "get_advancedParameters" ascii fullword
    $a19 = "get_disabledByRestriction" ascii fullword
    $a20 = "get_LastAccessed" ascii fullword
    $a21 = "get_avatarType" ascii fullword
    $a22 = "get_signaturePresets" ascii fullword
    $a23 = "get_enableLog" ascii fullword
    $a24 = "TelegramLog" ascii fullword
    $a25 = "generateKeyV75" ascii fullword
    $a26 = "set_accountName" ascii fullword
    $a27 = "set_InternalServerPort" ascii fullword
    $a28 = "set_bindingConfigurationUID" ascii fullword
    $a29 = "set_IdnAddress" ascii fullword
    $a30 = "set_GuidMasterKey" ascii fullword
    $a31 = "m_MyWebServicesObjectProvider" ascii fullword
    $a32 = "m_UserObjectProvider" ascii fullword
    $a33 = "m_ComputerObjectProvider" ascii fullword
    $a34 = "m_ThreadStaticValue" ascii fullword
    $a35 = "set_username" ascii fullword
    $a36 = "set_version" ascii fullword
condition:
    8 of ($a*)
}

rule Windows_Trojan_Amadey_7abb059b {
  meta:
    id = "7abb059b-4001-4eec-8185-1e0497e15062"
    fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Amadey"
    threat_name = "Windows.Trojan.Amadey"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
condition:
    all of them
}

rule Windows_Trojan_Amadey_c4df8d4a {
  meta:
    id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
    fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Amadey"
    threat_name = "Windows.Trojan.Amadey"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword
condition:
    all of them
}

rule Windows_Trojan_AveMaria_31d2bce9 {
  meta:
    id = "31d2bce9-3266-447b-9a2d-57cf11a0ff1f"
    fingerprint = "8f75e2d8308227a42743168deb021de18ad485763fd257991c5e627c025c30c0"
    creation_date = "2021-05-30"
    last_modified = "2021-05-30"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "AveMaria"
    threat_name = "Windows.Trojan.AveMaria"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "5767bca39fa46d32a6cb69ef7bd1feaac949874768dac192dbf1cf43336b3d7b"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
    $a2 = "SMTP Password" wide fullword
    $a3 = "select signon_realm, origin_url, username_value, password_value from logins" ascii fullword
    $a4 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide fullword
    $a5 = "for /F \"usebackq tokens=*\" %%A in (\"" wide fullword
    $a6 = "\\Torch\\User Data\\Default\\Login Data" wide fullword
    $a7 = "/n:%temp%\\ellocnak.xml" wide fullword
    $a8 = "\"os_crypt\":{\"encrypted_key\":\"" wide fullword
    $a9 = "Hey I'm Admin" wide fullword
    $a10 = "\\logins.json" wide fullword
    $a11 = "Accounts\\Account.rec0" ascii fullword
    $a12 = "warzone160" ascii fullword
    $a13 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide fullword
condition:
    8 of ($a*)
}

rule Windows_Trojan_Bazar_711d59f6 {
  meta:
    id = "711d59f6-6e8a-485d-b362-4c1bf1bda66e"
    fingerprint = "a9e78b4e39f4acaba86c2595db67fcdcd40d1af611d41a023bd5d8ca9804efa4"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Bazar"
    threat_name = "Windows.Trojan.Bazar"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "f29253139dab900b763ef436931213387dc92e860b9d3abb7dcd46040ac28a0e"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }
condition:
    all of them
}

rule Windows_Trojan_Bazar_9dddea36 {
  meta:
    id = "9dddea36-1345-434b-8ce6-54d2eab39616"
    fingerprint = "e322e36006cc017d5d5d9887c89b180c5070dbe5a9efd9fb7ae15cda5b726d6c"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Bazar"
    threat_name = "Windows.Trojan.Bazar"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "63df43daa61f9a0fbea2e5409b8f0063f7af3363b6bc8d6984ce7e90c264727d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { C4 10 5B 5F 5E C3 41 56 56 57 55 53 48 83 EC 18 48 89 C8 48 }
condition:
    all of them
}

rule Windows_Trojan_Bazar_3a2cc53b {
  meta:
    id = "3a2cc53b-4f73-41f9-aabd-08b8755ba44c"
    fingerprint = "f146d4fff29011acf595f2cba10ed7c3ce6ba07fbda0864d746f8e6355f91add"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Bazar"
    threat_name = "Windows.Trojan.Bazar"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "b057eb94e711995fd5fd6c57aa38a243575521b11b98734359658a7a9829b417"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 48 63 41 3C 45 33 ED 44 8B FA 48 8B F9 8B 9C 08 88 00 00 00 44 8B A4 08 8C 00 }
condition:
    all of them
}

rule Windows_Trojan_Bitrat_34bd6c83 {
  meta:
    id = "34bd6c83-9a71-43d5-b0b1-1646a8fb66e8"
    fingerprint = "bc4a5fad1810ad971277a455030eed3377901a33068bb994e235346cfe5a524f"
    creation_date = "2021-06-13"
    last_modified = "2021-06-27"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Bitrat"
    threat_name = "Windows.Trojan.Bitrat"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "37f70ae0e4e671c739d402c00f708761e98b155a1eefbedff1236637c4b7690a"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "crd_logins_report" ascii fullword
    $a2 = "drives_get" ascii fullword
    $a3 = "files_get" ascii fullword
    $a4 = "shell_stop" ascii fullword
    $a5 = "hvnc_start_ie" ascii fullword
condition:
    all of them
}

rule Windows_Trojan_Carberp_d6de82ae {
  meta:
    id = "d6de82ae-9846-40cb-925d-e0a371e1c44c"
    fingerprint = "7ce34f1000749a938b78508c93371d3339cd49f73eeec36b25da13c9d129b85c"
    creation_date = "2021-02-07"
    last_modified = "2021-07-16"
    description = "Identifies VNC module from the leaked Carberp source code. This could exist in other malware families."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Carberp"
    threat_name = "Windows.Trojan.Carberp"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://github.com/m0n0ph1/malware-1/blob/master/Carberp%20Botnet/source%20-%20absource/pro/all%20source/hvnc_dll/HVNC%20Lib/vnc/xvnc.h#L342"
    reference_sample = "f98fadb6feab71930bd5c08e85153898d686cc96c84fe349c00bf6d482de9b53"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = ".NET CLR Networking_Perf_Library_Lock_PID_0" ascii wide fullword
    $a2 = "FakeVNCWnd" ascii wide fullword
condition:
    all of them
}

rule Windows_Trojan_CobaltStrike_c851687a {
  meta:
    id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
    fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies UAC Bypass module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "bypassuac.dll" ascii fullword
    $a2 = "bypassuac.x64.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
    $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
    $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
    $b3 = "[*] Cleanup successful" ascii fullword
    $b4 = "\\System32\\cliconfg.exe" wide fullword
    $b5 = "\\System32\\eventvwr.exe" wide fullword
    $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
    $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
    $b8 = "\\System32\\sysprep\\" wide fullword
    $b9 = "[-] COM initialization failed." ascii fullword
    $b10 = "[-] Privileged file copy failed: %S" ascii fullword
    $b11 = "[-] Failed to start %S: %d" ascii fullword
    $b12 = "ReflectiveLoader"
    $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
    $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
    $b15 = "[+] %S ran and exited." ascii fullword
    $b16 = "[+] Privileged file copy success! %S" ascii fullword
condition:
    2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e {
  meta:
    id = "0b58325e-2538-434d-9a2c-26e2c32db039"
    fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Keylogger module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "keylogger.dll" ascii fullword
    $a2 = "keylogger.x64.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\keylogger" ascii fullword
    $a4 = "%cE=======%c" ascii fullword
    $a5 = "[unknown: %02X]" ascii fullword
    $b1 = "ReflectiveLoader"
    $b2 = "%c2%s%c" ascii fullword
    $b3 = "[numlock]" ascii fullword
    $b4 = "%cC%s" ascii fullword
    $b5 = "[backspace]" ascii fullword
    $b6 = "[scroll lock]" ascii fullword
    $b7 = "[control]" ascii fullword
    $b8 = "[left]" ascii fullword
    $b9 = "[page up]" ascii fullword
    $b10 = "[page down]" ascii fullword
    $b11 = "[prtscr]" ascii fullword
    $b12 = "ZRich9" ascii fullword
    $b13 = "[ctrl]" ascii fullword
    $b14 = "[home]" ascii fullword
    $b15 = "[pause]" ascii fullword
    $b16 = "[clear]" ascii fullword
condition:
    1 of ($a*) and 14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 {
  meta:
    id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
    fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies dll load module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
    $b1 = "__imp_BeaconErrorDD" ascii fullword
    $b2 = "__imp_BeaconErrorNA" ascii fullword
    $b3 = "__imp_BeaconErrorD" ascii fullword
    $b4 = "__imp_BeaconDataInt" ascii fullword
    $b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
    $b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
    $b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
    $b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
    $c1 = "__imp__BeaconErrorDD" ascii fullword
    $c2 = "__imp__BeaconErrorNA" ascii fullword
    $c3 = "__imp__BeaconErrorD" ascii fullword
    $c4 = "__imp__BeaconDataInt" ascii fullword
    $c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
    $c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
    $c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
    $c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword
condition:
    1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767 {
  meta:
    id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
    fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies getsystem module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
    $b1 = "getsystem failed." ascii fullword
    $b2 = "_isSystemSID" ascii fullword
    $b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
    $c1 = "getsystem failed." ascii fullword
    $c2 = "$pdata$isSystemSID" ascii fullword
    $c3 = "$unwind$isSystemSID" ascii fullword
    $c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
condition:
    1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f {
  meta:
    id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
    fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Hashdump module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 70
  strings:
    $a1 = "hashdump.dll" ascii fullword
    $a2 = "hashdump.x64.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\hashdump" ascii fullword
    $a4 = "ReflectiveLoader"
    $a5 = "Global\\SAM" ascii fullword
    $a6 = "Global\\FREE" ascii fullword
    $a7 = "[-] no results." ascii fullword
condition:
    4 of ($a*)
}

/*
Triggering on the nslookup BOF, too difficult to currently get around...

rule Windows_Trojan_CobaltStrike_6e971281 {
  meta:
    id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
    fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Interfaces module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
    $b1 = "__imp_BeaconFormatAlloc" ascii fullword
    $b2 = "__imp_BeaconFormatPrintf" ascii fullword
    $b3 = "__imp_BeaconOutput" ascii fullword
    $b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
    $b5 = "__imp_KERNEL32$LocalFree" ascii fullword
    $b6 = "__imp_LoadLibraryA" ascii fullword
    $c1 = "__imp__BeaconFormatAlloc" ascii fullword
    $c2 = "__imp__BeaconFormatPrintf" ascii fullword
    $c3 = "__imp__BeaconOutput" ascii fullword
    $c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
    $c5 = "__imp__KERNEL32$LocalFree" ascii fullword
    $c6 = "__imp__LoadLibraryA" ascii fullword
condition:
    1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}
*/

rule Windows_Trojan_CobaltStrike_09b79efa {
  meta:
    id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
    fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Invoke Assembly module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "invokeassembly.x64.dll" ascii fullword
    $a2 = "invokeassembly.dll" ascii fullword
    $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
    $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
    $b3 = "[-] Failed to create the runtime host" ascii fullword
    $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
    $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
    $b6 = "ReflectiveLoader"
    $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
    $b8 = "[-] No .NET runtime found. :(" ascii fullword
    $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
    $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
condition:
    1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e {
  meta:
    id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
    fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Kerberos module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
    $a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
    $a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
    $a4 = "command_kerberos_ticket_use" ascii fullword
    $a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
    $a6 = "command_kerberos_ticket_purge" ascii fullword
    $a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
    $a8 = "$unwind$kerberos_init" ascii fullword
    $a9 = "$unwind$KerberosTicketUse" ascii fullword
    $a10 = "KerberosTicketUse" ascii fullword
    $a11 = "$unwind$KerberosTicketPurge" ascii fullword
    $b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
    $b2 = "_command_kerberos_ticket_use" ascii fullword
    $b3 = "_command_kerberos_ticket_purge" ascii fullword
    $b4 = "_kerberos_init" ascii fullword
    $b5 = "_KerberosTicketUse" ascii fullword
    $b6 = "_KerberosTicketPurge" ascii fullword
    $b7 = "_LsaCallKerberosPackage" ascii fullword
condition:
    5 of ($a*) or 3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a {
  meta:
    id = "de42495a-0002-466e-98b9-19c9ebb9240e"
    fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Mimikatz module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
    $b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
    $b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
    $b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
    $b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
    $b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
    $b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
    $b7 = "mimikatz(powershell) # %s" wide fullword
    $b8 = "powershell_reflective_mimikatz" ascii fullword
    $b9 = "mimikatz_dpapi_cache.ndr" wide fullword
    $b10 = "mimikatz.log" wide fullword
    $b11 = "ERROR mimikatz_doLocal" wide
    $b12 = "mimikatz_x64.compressed" wide
condition:
    1 of ($a*) and 7 of ($b*)
}

/*
Triggering on several BOFs, too difficult to currently get around...

rule Windows_Trojan_CobaltStrike_72f68375 {
  meta:
    id = "72f68375-35ab-49cc-905d-15302389a236"
    fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Netdomain module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
    $b1 = "__imp_BeaconPrintf" ascii fullword
    $b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
    $b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
    $c1 = "__imp__BeaconPrintf" ascii fullword
    $c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
    $c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
condition:
    1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}
*/

rule Windows_Trojan_CobaltStrike_15f680fb {
  meta:
    id = "15f680fb-a04f-472d-a182-0b9bee111351"
    fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Netview module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "netview.x64.dll" ascii fullword
    $a2 = "netview.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\netview" ascii fullword
    $b1 = "Sessions for \\\\%s:" ascii fullword
    $b2 = "Account information for %s on \\\\%s:" ascii fullword
    $b3 = "Users for \\\\%s:" ascii fullword
    $b4 = "Shares at \\\\%s:" ascii fullword
    $b5 = "ReflectiveLoader" ascii fullword
    $b6 = "Password changeable" ascii fullword
    $b7 = "User's Comment" wide fullword
    $b8 = "List of hosts for domain '%s':" ascii fullword
    $b9 = "Password changeable" ascii fullword
    $b10 = "Logged on users at \\\\%s:" ascii fullword
condition:
    2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
  meta:
    id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
    fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Portscan module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "portscan.x64.dll" ascii fullword
    $a2 = "portscan.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\portscan" ascii fullword
    $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
    $b2 = "(ARP) Target '%s' is alive. " ascii fullword
    $b3 = "TARGETS!12345" ascii fullword
    $b4 = "ReflectiveLoader" ascii fullword
    $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
    $b6 = "Scanner module is complete" ascii fullword
    $b7 = "pingpong" ascii fullword
    $b8 = "PORTS!12345" ascii fullword
    $b9 = "%s:%d (%s)" ascii fullword
    $b10 = "PREFERENCES!12345" ascii fullword
condition:
    2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
  meta:
    id = "91e08059-46a8-47d0-91c9-e86874951a4a"
    fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Post Ex module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "postex.x64.dll" ascii fullword
    $a2 = "postex.dll" ascii fullword
    $a3 = "RunAsAdminCMSTP" ascii fullword
    $a4 = "KerberosTicketPurge" ascii fullword
    $b1 = "GetSystem" ascii fullword
    $b2 = "HelloWorld" ascii fullword
    $b3 = "KerberosTicketUse" ascii fullword
    $b4 = "SpawnAsAdmin" ascii fullword
    $b5 = "RunAsAdmin" ascii fullword
    $b6 = "NetDomain" ascii fullword
condition:
    2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
  meta:
    id = "ee756db7-e177-41f0-af99-c44646d334f7"
    fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
    creation_date = "2021-03-23"
    last_modified = "2021-04-20"
    description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
    $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
    $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
    $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
    $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
    $a11 = "Could not open service control manager on %s: %d" ascii fullword
    $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
    $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
    $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
    $a15 = "could not create remote thread in %d: %d" ascii fullword
    $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a17 = "could not write to process memory: %d" ascii fullword
    $a18 = "Could not create service %s on %s: %d" ascii fullword
    $a19 = "Could not delete service %s on %s: %d" ascii fullword
    $a20 = "Could not open process token: %d (%u)" ascii fullword
    $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a22 = "Could not start service %s on %s: %d" ascii fullword
    $a23 = "Could not query service %s on %s: %d" ascii fullword
    $a24 = "Could not connect to pipe (%s): %d" ascii fullword
    $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a26 = "could not spawn %s (token): %d" ascii fullword
    $a27 = "could not open process %d: %d" ascii fullword
    $a28 = "could not run %s as %s\\%s: %d" ascii fullword
    $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
    $a30 = "kerberos ticket use failed:" ascii fullword
    $a31 = "Started service %s on %s" ascii fullword
    $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
    $a33 = "I'm already in SMB mode" ascii fullword
    $a34 = "could not spawn %s: %d" ascii fullword
    $a35 = "could not open %s: %d" ascii fullword
    $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
    $a37 = "Could not open '%s'" ascii fullword
    $a38 = "%s.1%08x.%x%x.%s" ascii fullword
    $a39 = "%s as %s\\%s: %d" ascii fullword
    $a40 = "%s.1%x.%x%x.%s" ascii fullword
    $a41 = "beacon.x64.dll" ascii fullword
    $a42 = "%s on %s: %d" ascii fullword
    $a43 = "www6.%x%x.%s" ascii fullword
    $a44 = "cdn.%x%x.%s" ascii fullword
    $a45 = "api.%x%x.%s" ascii fullword
    $a46 = "%s (admin)" ascii fullword
    $a47 = "beacon.dll" ascii fullword
    $a48 = "%s%s: %s" ascii fullword
    $a49 = "@%d.%s" ascii fullword
    $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
    $a51 = "Content-Length: %d" ascii fullword
condition:
    6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561 {
  meta:
    id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
    fingerprint = "1adc3d2d6af9fee9ded94fbecac441fc63bfb2dfa08dbf68ad7da877f3ba9dc2"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies PowerShell Runner module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "PowerShellRunner.dll" wide fullword
    $a2 = "powershell.x64.dll" ascii fullword
    $a3 = "powershell.dll" ascii fullword
    $a4 = "\\\\.\\pipe\\powershell" ascii fullword
    $a5 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
    $b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
    $b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
    $b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
    $b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
    $b5 = "CustomPSHostUserInterface" ascii fullword
    $b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
    $b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
    $c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
condition:
    (3 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124 {
  meta:
    id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
    fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies PsExec module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
    $b1 = "__imp_BeaconDataExtract" ascii fullword
    $b2 = "__imp_BeaconDataParse" ascii fullword
    $b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
    $b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
    $b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
    $b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
    $c1 = "__imp__BeaconDataExtract" ascii fullword
    $c2 = "__imp__BeaconDataParse" ascii fullword
    $c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
    $c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
    $c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
    $c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
condition:
    1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7 {
  meta:
    id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
    fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Registry module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
    $b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
    $b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
    $b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
    $b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
    $b5 = "__imp_BeaconFormatAlloc" ascii fullword
    $b6 = "__imp_BeaconOutput" ascii fullword
    $b7 = "__imp_BeaconFormatFree" ascii fullword
    $b8 = "__imp_BeaconDataPtr" ascii fullword
    $c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
    $c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
    $c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
    $c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
    $c5 = "__imp__BeaconFormatAlloc" ascii fullword
    $c6 = "__imp__BeaconOutput" ascii fullword
    $c7 = "__imp__BeaconFormatFree" ascii fullword
    $c8 = "__imp__BeaconDataPtr" ascii fullword
condition:
    1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
  meta:
    id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
    fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Screenshot module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "screenshot.x64.dll" ascii fullword
    $a2 = "screenshot.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
    $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
    $b2 = "GetDesktopWindow" ascii fullword
    $b3 = "CreateCompatibleBitmap" ascii fullword
    $b4 = "GDI32.dll" ascii fullword
    $b5 = "ReflectiveLoader"
    $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
condition:
    2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c {
  meta:
    id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
    fingerprint = "1ecbc35201f65024976cb7419561b988df328c3b0a5cac2c2eea2211d986ddd0"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies SSH Agent module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "sshagent.x64.dll" ascii fullword
    $a2 = "sshagent.dll" ascii fullword
    $a3 = "\\\\.\\pipe\\sshagent" ascii fullword
    $a4 = "got %02x %s" ascii fullword
    $a5 = "connect to %s:%d: %s" ascii fullword
    $b1 = "forwarded-tcpip" ascii fullword
    $b2 = "127.0.0.1" ascii fullword
    $b3 = "cd %s ; cd %s ; pwd"
    $b4 = "SUCCESS %s@%s:%d %s" ascii fullword
    $b5 = "%d bytes at %p"
    $b6 = "connect to %s:%d: time out" ascii fullword
condition:
    2 of ($a*) or 3 of ($b*)
}

// rule Windows_Trojan_CobaltStrike_a56b820f {
//   meta:
//     id = "a56b820f-0a20-4054-9c2d-008862646a78"
//     fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
//     creation_date = "2021-03-23"
//     last_modified = "2021-04-12"
//     description = "Identifies Timestomp module from Cobalt Strike"
//     os = "Windows"
//     arch = "x86"
//     category_type = "Trojan"
//     family = "CobaltStrike"
//     threat_name = "Windows.Trojan.CobaltStrike"
//     source = "Manual"
//     maturity = "Diagnostic"
//     scan_type = "File, Memory"
//     severity = 100
//   strings:
//     $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
//     $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
//     $b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
//     $b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
//     $b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
//     $b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
//     $b5 = "__imp_BeaconDataExtract" ascii fullword
//     $b6 = "__imp_BeaconPrintf" ascii fullword
//     $b7 = "__imp_BeaconDataParse" ascii fullword
//     $c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
//     $c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
//     $c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
//     $c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
//     $c5 = "__imp__BeaconDataExtract" ascii fullword
//     $c6 = "__imp__BeaconPrintf" ascii fullword
//     $c7 = "__imp__BeaconDataParse" ascii fullword
// condition:
//     1 of ($a*) or 5 of ($b*) or 5 of ($c*)
// }

rule Windows_Trojan_CobaltStrike_92f05172 {
  meta:
    id = "92f05172-f15c-4077-a958-b8490378bf08"
    fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies UAC cmstp module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
    $b1 = "elevate_cmstp" ascii fullword
    $b2 = "$pdata$elevate_cmstp" ascii fullword
    $b3 = "$unwind$elevate_cmstp" ascii fullword
    $c1 = "_elevate_cmstp" ascii fullword
    $c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
    $c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
    $c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
    $c5 = "OLDNAMES"
    $c6 = "__imp__BeaconDataParse" ascii fullword
    $c7 = "_willAutoElevate" ascii fullword
condition:
    1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5 {
  meta:
    id = "417239b5-cf2d-4c85-a022-7a8459c26793"
    fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies UAC token module from Cobalt Strike"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
    $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
    $a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
    $a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
    $b1 = "$pdata$is_admin_already" ascii fullword
    $b2 = "$unwind$is_admin" ascii fullword
    $b3 = "$pdata$is_admin" ascii fullword
    $b4 = "$unwind$is_admin_already" ascii fullword
    $b5 = "$pdata$RunAsAdmin" ascii fullword
    $b6 = "$unwind$RunAsAdmin" ascii fullword
    $b7 = "is_admin_already" ascii fullword
    $b8 = "is_admin" ascii fullword
    $b9 = "process_walk" ascii fullword
    $b10 = "get_current_sess" ascii fullword
    $b11 = "elevate_try" ascii fullword
    $b12 = "RunAsAdmin" ascii fullword
    $b13 = "is_ctfmon" ascii fullword
    $c1 = "_is_admin_already" ascii fullword
    $c2 = "_is_admin" ascii fullword
    $c3 = "_process_walk" ascii fullword
    $c4 = "_get_current_sess" ascii fullword
    $c5 = "_elevate_try" ascii fullword
    $c6 = "_RunAsAdmin" ascii fullword
    $c7 = "_is_ctfmon" ascii fullword
    $c8 = "_reg_query_dword" ascii fullword
    $c9 = ".drectve" ascii fullword
    $c10 = "_is_candidate" ascii fullword
    $c11 = "_SpawnAsAdmin" ascii fullword
    $c12 = "_SpawnAsAdminX64" ascii fullword
condition:
    1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
  meta:
    id = "29374056-03ce-484b-8b2d-fbf75be86e27"
    fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
    creation_date = "2021-03-23"
    last_modified = "2021-04-12"
    description = "Identifies Cobalt Strike MZ Reflective Loader."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
    $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
condition:
    1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3 {
  meta:
    id = "949f10e3-68c9-4600-a620-ed3119e09257"
    fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
    creation_date = "2021-03-25"
    last_modified = "2021-03-25"
    description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
    $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
condition:
    all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 {
  meta:
    id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
    fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
    creation_date = "2021-03-25"
    last_modified = "2021-03-25"
    description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "CobaltStrike"
    threat_name = "Windows.Trojan.CobaltStrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 99
  strings:
    $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
    $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
condition:
    all of them
}

// rule Windows_Trojan_CobaltStrike_8519072e {
//   meta:
//     id = "8519072e-3e43-470b-a3cf-18f92b3f31a2"
//     fingerprint = "90c0c1ec6cfc065ba1d92bb5f24568b31827f05e3f932ce3128cb6d278ff7757"
//     creation_date = "2021-03-25"
//     last_modified = "2021-04-12"
//     description = "Identifies Cobalt Strike trial/default versions"
//     os = "Windows"
//     arch = "x86"
//     category_type = "Trojan"
//     family = "CobaltStrike"
//     threat_name = "Windows.Trojan.CobaltStrike"
//     source = "Manual"
//     maturity = "Diagnostic"
//     scan_type = "File, Memory"
//     severity = 90
//   strings:
//     $a1 = "User-Agent:"
//     $a2 = "wini"
//     $a3 = "5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
//     $a4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/
// condition:
//     all of them
// }

rule Windows_Trojan_Cobaltstrike_663fc95d {
  meta:
    id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
    fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
    creation_date = "2021-04-01"
    last_modified = "2021-04-01"
    description = "Identifies CobaltStrike via unidentified function code"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Cobaltstrike"
    threat_name = "Windows.Trojan.Cobaltstrike"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
condition:
    all of them
}

rule Windows_Trojan_Diceloader_b32c6b99 {
  meta:
    id = "b32c6b99-f634-4c6f-98f4-39954ef15afa"
    fingerprint = "15d4bc57c03a560608ae69551aa46d1786072b3d78d747512f8ac3e6822a7b93"
    creation_date = "2021-04-23"
    last_modified = "2021-05-18"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Diceloader"
    threat_name = "Windows.Trojan.Diceloader"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "a3b3f56a61c6dc8ba2aa25bdd9bd7dc2c5a4602c2670431c5cbc59a76e2b4c54"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "D$0GET " ascii fullword
    $a2 = "D$THostf" ascii fullword
    $a3 = "D$,POST" ascii fullword
    $a4 = "namef" ascii fullword
    $a5 = "send" ascii fullword
    $a6 = "log.ini" wide
    $a7 = { 70 61 73 73 00 00 65 6D 61 69 6C 00 00 6C 6F 67 69 6E 00 00 73 69 67 6E 69 6E 00 00 61 63 63 6F 75 6E 74 00 00 70 65 72 73 69 73 74 65 6E 74 00 00 48 6F 73 74 3A 20 }
condition:
    all of them
}

rule Windows_Trojan_Diceloader_15eeb7b9 {
  meta:
    id = "15eeb7b9-311f-477b-8ae1-b8f689a154b7"
    fingerprint = "4cc70bec5d241c6f84010fbfe2eafbc6ec6d753df2bb3f52d9498b54b11fc8cb"
    creation_date = "2021-04-23"
    last_modified = "2021-05-18"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Diceloader"
    threat_name = "Windows.Trojan.Diceloader"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "a1202df600d11ad2c61050e7ba33701c22c2771b676f54edd1846ef418bea746"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { E9 92 9D FF FF C3 E8 }
    $a2 = { E9 E8 61 FF FF C3 E8 }
condition:
    any of them
}

rule Windows_Trojan_Formbook_1112e116 {
  meta:
    id = "1112e116-dee0-4818-a41f-ca5c1c41b4b8"
    fingerprint = "b8b88451ad8c66b54e21455d835a5d435e52173c86e9b813ffab09451aff7134"
    creation_date = "2021-06-14"
    last_modified = "2021-06-14"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Formbook"
    threat_name = "Windows.Trojan.Formbook"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 3C 30 50 4F 53 54 74 09 40 }
    $a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
    $a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
    $a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
condition:
    any of them
}

rule Windows_Trojan_Generic_a681f24a {
  meta:
    id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
    fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Generic"
    threat_name = "Windows.Trojan.Generic"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
    scan_type = "File, Memory"
    severity = 25
  strings:
    $a = "_kasssperskdy" wide fullword
    $b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
    $c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword
condition:
    2 of them
}

rule Windows_Trojan_Gh0st_ee6de6bc {
  meta:
    id = "ee6de6bc-1648-4a77-9607-e2a211c7bda4"
    fingerprint = "3c529043f34ad8a8692b051ad7c03206ce1aafc3a0eb8fcf7f5bcfdcb8c1b455"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    description = "Identifies a variant of Gh0st Rat"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Gh0st"
    threat_name = "Windows.Trojan.Gh0st"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "ea1dc816dfc87c2340a8b8a77a4f97618bccf19ad3b006dce4994be02e13245d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = ":]%d-%d-%d\n%d:%d:%d" ascii fullword
    $a2 = "[Pause Break]" ascii fullword
    $a3 = "f-secure.exe" ascii fullword
    $a4 = "Accept-Language: zh-cn" ascii fullword
condition:
    all of them
}

rule Windows_Trojan_Gozi_fd494041 {
  meta:
    id = "fd494041-3fe8-4ffa-9ab8-6798032f1d66"
    fingerprint = "faabcdfb3402a5951ff1fde4f994dcb00ec9a71fb815b80dc1da9b577bf92ec2"
    creation_date = "2021-03-22"
    last_modified = "2021-07-16"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Gozi"
    threat_name = "Windows.Trojan.Gozi"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "0a1c1557bdb8c1b99e2b764fc6b21a07e33dc777b492a25a55cbd8737031e237"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "/C ping localhost -n %u && del \"%s\"" wide fullword
    $a2 = "/C \"copy \"%s\" \"%s\" /y && \"%s\" \"%s\"" wide fullword
    $a3 = "/C \"copy \"%s\" \"%s\" /y && rundll32 \"%s\",%S\"" wide fullword
    $a4 = "ASCII.GetString(( gp \"%S:\\%S\").%s))',0,0)" wide
    $a5 = "filename=\"%.4u.%lu\""
    $a6 = "Urundll32 \"%s\",%S" wide fullword
    $a7 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii fullword
    $a8 = "%08X-%04X-%04X-%04X-%08X%04X" ascii fullword
    $a9 = "&whoami=%s" ascii fullword
    $a10 = "%u.%u_%u_%u_x%u" ascii fullword
    $a11 = "size=%u&hash=0x%08x" ascii fullword
    $a12 = "&uptime=%u" ascii fullword
    $a13 = "%systemroot%\\system32\\c_1252.nls" ascii fullword
    $a14 = "IE10RunOnceLastShown_TIMESTAMP" ascii fullword
condition:
    8 of ($a*)
}

rule Windows_Trojan_Gozi_261f5ac5 {
  meta:
    id = "261f5ac5-7800-4580-ac37-80b71c47c270"
    fingerprint = "cbc8fec8fbaa809cfc7da7db72aeda43d4270f907e675016cbbc2e28e7b8553c"
    creation_date = "2019-08-02"
    last_modified = "2021-07-16"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Gozi"
    threat_name = "Windows.Trojan.Gozi"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "31835c6350177eff88265e81335a50fcbe0dc46771bf031c836947851dcebb4f"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
    $a2 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
    $a3 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\""
    $a4 = "&tor=1"
    $a5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)"
    $a6 = "http://constitution.org/usdeclar.txt"
    $a7 = "grabs="
    $a8 = "CHROME.DLL"
    $a9 = "Software\\AppDataLow\\Software\\Microsoft\\"
condition:
    4 of ($a*)
}

rule Windows_Trojan_Hancitor_6738d84a {
  meta:
    id = "6738d84a-7393-4db2-97cc-66f471b5699a"
    fingerprint = "44a4dd7c35e0b4f3f161b82463d8f0ee113eaedbfabb7d914ce9486b6bd3a912"
    creation_date = "2021-06-17"
    last_modified = "2021-06-21"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Hancitor"
    threat_name = "Windows.Trojan.Hancitor"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "a674898f39377e538f9ec54197689c6fa15f00f51aa0b5cc75c2bafd86384a40"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d"
    $b1 = "Rundll32.exe %s, start" ascii fullword
    $b2 = "MASSLoader.dll" ascii fullword
condition:
    $a1 or all of ($b*)
}

rule Windows_Trojan_IcedID_1cd868a6 {
  meta:
    id = "1cd868a6-d2ec-4c48-a69a-aaa6c7af876c"
    fingerprint = "3e76b3ac03c5268923cfd5d0938745d66cda273d436b83bee860250fdcca6327"
    creation_date = "2021-02-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "IcedID"
    threat_name = "Windows.Trojan.IcedID"
    source = "Automated"
    maturity = "Diagnostic"
    reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
    reference_sample = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }
condition:
    all of them
}

rule Windows_Trojan_IcedID_237e9fb6 {
  meta:
    id = "237e9fb6-b5fa-4747-af1f-533c76a5a639"
    fingerprint = "e2ea6d1477ce4132f123b6c00101a063f7bba7acf38be97ee8dca22cc90ed511"
    creation_date = "2021-02-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "IcedID"
    threat_name = "Windows.Trojan.IcedID"
    source = "Automated"
    maturity = "Diagnostic"
    reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
    reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }
condition:
    all of them
}

rule Windows_Trojan_IcedID_f1ce2f0a {
  meta:
    id = "f1ce2f0a-0d34-46a4-8e42-0906adf4dc1b"
    fingerprint = "1940c4bf5d8011dc7edb8dde718286554ed65f9e96fe61bfa90f6182a4b8ca9e"
    creation_date = "2021-02-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "IcedID"
    threat_name = "Windows.Trojan.IcedID"
    source = "Automated"
    maturity = "Diagnostic"
    reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
    reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }
condition:
    all of them
}

rule Windows_Trojan_IcedID_08530e24 {
  meta:
    id = "08530e24-5b84-40a4-bc5c-ead74762faf8"
    fingerprint = "f2b5768b87eec7c1c9730cc99364cc90e87fd9201bf374418ad008fd70d321af"
    creation_date = "2021-03-21"
    last_modified = "2021-07-16"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "IcedID"
    threat_name = "Windows.Trojan.IcedID"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "c:\\ProgramData\\" ascii fullword
    $a2 = "loader_dll_64.dll" ascii fullword
    $a3 = "aws.amazon.com" wide fullword
    $a4 = "Cookie: __gads=" wide fullword
    $b1 = "LookupAccountNameW" ascii fullword
    $b2 = "GetUserNameA" ascii fullword
    $b3 = "; _gat=" wide fullword
    $b4 = "; _ga=" wide fullword
    $b5 = "; _u=" wide fullword
    $b6 = "; __io=" wide fullword
    $b7 = "; _gid=" wide fullword
    $b8 = "%s%u" wide fullword
    $b9 = "i\\|9*" ascii fullword
    $b10 = "WinHttpSetStatusCallback" ascii fullword
condition:
    all of ($a*) and 5 of ($b*)
}

rule Win_Trojan_Kronos_cdd2e2c5 {
  meta:
    id = "cdd2e2c5-17fc-4cec-aece-0b19c54faccf"
    fingerprint = "0e124d42a6741a095b66928303731e7060788bc1035b98b729ca91e4f7b6bc44"
    creation_date = "2021-02-07"
    last_modified = "2021-07-16"
    description = "Strings used by the Kronos banking trojan and variants."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Kronos"
    threat_name = "Windows.Trojan.Kronos"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
    reference_sample = "baa9cedbbe0f5689be8f8028a6537c39e9ea8b0815ad76cb98f365ca5a41653f"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "data_inject" ascii wide fullword
    $a2 = "set_filter" ascii wide fullword
    $a3 = "set_url" ascii wide fullword
    $a4 = "%ws\\%ws.cfg" ascii wide fullword
    $a5 = "D7T1H5F0F5A4C6S3" ascii wide fullword
    $a6 = "[DELETE]" ascii wide fullword
    $a7 = "Kronos" ascii wide fullword
condition:
    4 of them
}

rule Windows_Trojan_Lokibot_1f885282 {
  meta:
    id = "1f885282-b60e-491e-ae1b-d26825e5aadb"
    fingerprint = "a7519bb0751a6c928af7548eaed2459e0ed26128350262d1278f74f2ad91331b"
    creation_date = "2021-06-22"
    last_modified = "2021-06-22"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Lokibot"
    threat_name = "Windows.Trojan.Lokibot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "916eded682d11cbdf4bc872a8c1bcaae4d4e038ac0f869f59cc0a83867076409"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" fullword
condition:
    all of them
}

rule Windows_Trojan_Lokibot_0f421617 {
  meta:
    id = "0f421617-df2b-4cb5-9d10-d984f6553012"
    fingerprint = "9ff5d594428e4a5de84f0142dfa9f54cb75489192461deb978c70f1bdc88acda"
    creation_date = "2021-07-20"
    last_modified = "2021-07-20"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Lokibot"
    threat_name = "Windows.Trojan.Lokibot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "de6200b184832e7d3bfe00c193034192774e3cfca96120dc97ad6fed1e472080"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 08 8B CE 0F B6 14 38 D3 E2 83 C1 08 03 F2 48 79 F2 5F 8B C6 }
condition:
    all of them
}

rule Windows_Trojan_Metasploit_a6e956c9 {
  meta:
    id = "a6e956c9-799e-49f9-b5c5-ac68aaa2dc21"
    fingerprint = "21855599bc51ec2f71d694d4e0f866f815efe54a42842dfe5f8857811530a686"
    creation_date = "2021-03-23"
    last_modified = "2021-03-23"
    description = "Identifies the API address lookup function leverage by metasploit shellcode"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C 61 7C 02 2C 20 }
condition:
    $a1
}

rule Windows_Trojan_Metasploit_38b8ceec {
  meta:
    id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
    fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
    creation_date = "2021-03-23"
    last_modified = "2021-03-23"
    description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 85
  strings:
    $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
condition:
    $a1
}

rule Windows_Trojan_Metasploit_7bc0f998 {
  meta:
    id = "7bc0f998-7014-4883-8a56-d5ee00c15aed"
    fingerprint = "fdb5c665503f07b2fc1ed7e4e688295e1222a500bfb68418661db60c8e75e835"
    creation_date = "2021-03-23"
    last_modified = "2021-03-23"
    description = "Identifies the API address lookup function leverage by metasploit shellcode"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 84
  strings:
    $a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }
condition:
    $a1
}

rule Windows_Trojan_Metasploit_f7f826b4 {
  meta:
    id = "f7f826b4-6456-4819-bc0c-993aeeb7e325"
    fingerprint = "9b07dc54d5015d0f0d84064c5a989f94238609c8167cae7caca8665930a20f81"
    creation_date = "2021-03-23"
    last_modified = "2021-03-23"
    description = "Identifies metasploit kernel->user shellcode. Likely used in ETERNALBLUE and BlueKeep exploits."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = { 48 92 31 C9 51 51 49 89 C9 4C 8D 05 0? 00 00 00 89 CA 48 83 EC 20 FF D0 48 83 C4 30 C3 }
condition:
    $a1
}

rule Windows_Trojan_Metasploit_24338919 {
  meta:
    id = "24338919-8efe-4cf2-a23a-a3f22095b42d"
    fingerprint = "ac76190a84c4bdbb6927c5ad84a40e2145ca9e76369a25ac2ffd727eefef4804"
    creation_date = "2021-03-23"
    last_modified = "2021-03-23"
    description = "Identifies metasploit wininet reverse shellcode. Also used by other tools (like beacon)."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 80
  strings:
    $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
condition:
    $a1
}

rule Windows_Trojan_Metasploit_0f5a852d {
  meta:
    id = "0f5a852d-cacd-43d7-8754-204b09afba2f"
    fingerprint = "97daac4249e85a73d4e6a4450248e59e0d286d5e7c230cf32a38608f8333f00d"
    creation_date = "2021-04-07"
    last_modified = "2021-04-07"
    description = "Identifies 64 bit metasploit wininet reverse shellcode. May also be used by other malware families."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 80
  strings:
    $a = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 }
condition:
    all of them
}

rule Windows_Trojan_Metasploit_c9773203 {
  meta:
    id = "c9773203-6d1e-4246-a1e0-314217e0207a"
    fingerprint = "afde93eeb14b4d0c182f475a22430f101394938868741ffa06445e478b6ece36"
    creation_date = "2021-04-07"
    last_modified = "2021-04-12"
    description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
    scan_type = "File, Memory"
    severity = 10
  strings:
    $a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }
condition:
    all of them
}

rule Windows_Trojan_Metasploit_dd5ce989 {
  meta:
    id = "dd5ce989-3925-4e27-97c1-3b8927c557e9"
    fingerprint = "4fc7c309dca197f4626d6dba8afcd576e520dbe2a2dd6f7d38d7ba33ee371d55"
    creation_date = "2021-04-14"
    last_modified = "2021-04-14"
    description = "Identifies Meterpreter DLL used by Metasploit"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
    reference_sample = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
    scan_type = "File, Memory"
    severity = 90
  strings:
    $a1 = "metsrv.x64.dll" fullword
    $a2 = "metsrv.dll" fullword
    $b1 = "ReflectiveLoader"
condition:
    1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Metasploit_96233b6b {
  meta:
    id = "96233b6b-d95a-4e0e-8f83-f2282a342087"
    fingerprint = "40032849674714bc9eb020971dd9f27a07b53b8ff953b793cb3aad136256fd70"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    description = "Identifies another 64 bit API hashing function used by Metasploit."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "e7a2d966deea3a2df6ce1aeafa8c2caa753824215a8368e0a96b394fb46b753b"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 31 FF 0F B7 4A 26 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D }
condition:
    all of them
}

rule Windows_Trojan_Metasploit_4a1c4da8 {
  meta:
    id = "4a1c4da8-837d-4ad1-a672-ddb8ba074936"
    fingerprint = "7a31ce858215f0a8732ce6314bfdbc3975f1321e3f87d7f4dc5a525f15766987"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    description = "Identifies Metasploit 64 bit reverse tcp shellcode."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Metasploit"
    threat_name = "Windows.Trojan.Metasploit"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "9582d37ed9de522472abe615dedef69282a40cfd58185813c1215249c24bbf22"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 6A 10 56 57 68 99 A5 74 61 FF D5 85 C0 74 0A FF 4E 08 }
condition:
    all of them
}

rule Windows_Trojan_Nanocore_d8c4e3c5 {
  meta:
    id = "d8c4e3c5-8bcc-43d2-9104-fa3774282da5"
    fingerprint = "e5c284f14c1c650ef8ddd7caf314f5318e46a811addc2af5e70890390c7307d4"
    creation_date = "2021-06-13"
    last_modified = "2021-06-13"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Nanocore"
    threat_name = "Windows.Trojan.Nanocore"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "b2262126a955e306dc68487333394dc08c4fbd708a19afeb531f58916ddb1cfd"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "NanoCore.ClientPluginHost" ascii fullword
    $a2 = "NanoCore.ClientPlugin" ascii fullword
    $b1 = "get_BuilderSettings" ascii fullword
    $b2 = "ClientLoaderForm.resources" ascii fullword
    $b3 = "PluginCommand" ascii fullword
    $b4 = "IClientAppHost" ascii fullword
    $b5 = "GetBlockHash" ascii fullword
    $b6 = "AddHostEntry" ascii fullword
    $b7 = "LogClientException" ascii fullword
    $b8 = "PipeExists" ascii fullword
    $b9 = "IClientLoggingHost" ascii fullword
condition:
    1 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_Netwire_6a7df287 {
  meta:
    id = "6a7df287-1656-4779-9a96-c0ab536ae86a"
    fingerprint = "85051a0b94da4388eaead4c4f4b2d16d4a5eb50c3c938b3daf5c299c9c12f1e6"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Netwire"
    threat_name = "Windows.Trojan.Netwire"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }
condition:
    all of them
}

rule Windows_Trojan_Netwire_1b43df38 {
  meta:
    id = "1b43df38-886e-4f58-954a-a09f30f19907"
    fingerprint = "4142ea14157939dc23b8d1f5d83182aef3a5877d2506722f7a2706b7cb475b76"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Netwire"
    threat_name = "Windows.Trojan.Netwire"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
    $a2 = "\\Login Data"
    $a3 = "SOFTWARE\\NetWire" fullword
condition:
    2 of them
}

rule Windows_Trojan_Njrat_30f3c220 {
  meta:
    id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
    fingerprint = "2abd38871cb87838b94f359caa2f888ac350a2a753db55f4c919a426af0fb5fd"
    creation_date = "2021-06-13"
    last_modified = "2021-07-22"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Njrat"
    threat_name = "Windows.Trojan.Njrat"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "get_Registry" ascii fullword
    $a2 = "netsh firewall delete allowedprogram \"" wide fullword
    $a3 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
    $a4 = "SEE_MASK_NOZONECHECKS" wide fullword
    $a5 = "Download ERROR" wide fullword
condition:
    all of them
}

rule Windows_Trojan_Qbot_92c67a6d {
  meta:
    id = "92c67a6d-9290-4cd9-8123-7dace2cf333d"
    fingerprint = "4719993107243a22552b65e6ec8dc850842124b0b9919a6ecaeb26377a1a5ebd"
    creation_date = "2021-02-16"
    last_modified = "2021-03-18"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Qbot"
    threat_name = "Windows.Trojan.Qbot"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 33 C0 59 85 F6 74 2D 83 66 0C 00 40 89 06 6A 20 89 46 04 C7 46 08 08 00 }
condition:
    all of them
}

rule Windows_Trojan_Qbot_d91c1384 {
  meta:
    id = "d91c1384-839f-4062-8a8d-5cda931029ae"
    fingerprint = "1b47ede902b6abfd356236e91ed3e741cf1744c68b6bb566f0d346ea07fee49a"
    creation_date = "2021-07-08"
    last_modified = "2021-07-08"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Qbot"
    threat_name = "Windows.Trojan.Qbot"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }
condition:
    all of them
}

rule Windows_Trojan_Quasarrat_e52df647 {
  meta:
    id = "e52df647-c197-4790-b051-8951fba80c3b"
    fingerprint = "c888f0856c6568b83ab60193f8144a61e758e6ff53f6ead8565282ae8b3a9815"
    creation_date = "2021-06-27"
    last_modified = "2021-07-16"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Quasarrat"
    threat_name = "Windows.Trojan.Quasarrat"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "a58efd253a25cc764d63476931da2ddb305a0328253a810515f6735a6690de1d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "GetKeyloggerLogsResponse" ascii fullword
    $a2 = "DoDownloadAndExecute" ascii fullword
    $a3 = "http://api.ipify.org/" wide fullword
    $a4 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide fullword
    $a5 = "\" /sc ONLOGON /tr \"" wide fullword
condition:
    4 of them
}

rule Windows_Trojan_Raccoon_af6decc6 {
  meta:
    id = "af6decc6-f917-4a80-b96d-1e69b8f8ebe0"
    fingerprint = "f9314a583040e4238aab7712ac16d7638a3b7c9194cbcf2ea9b4516c228c546b"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Raccoon"
    threat_name = "Windows.Trojan.Raccoon"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" wide fullword
    $a2 = "\\stealler\\json.hpp" wide fullword
condition:
    any of them
}

rule Windows_Trojan_Raccoon_58091f64 {
  meta:
    id = "58091f64-2118-47f8-bcb2-407a3c62fa33"
    fingerprint = "ea819b46ec08ba6b33aa19dcd6b5ad27d107a8e37f3f9eb9ff751fe8e1612f88"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Raccoon"
    threat_name = "Windows.Trojan.Raccoon"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 74 FF FF FF 10 8D 4D AC 53 6A 01 8D 85 60 FF FF FF 0F 43 85 60 FF }
condition:
    all of them
}

rule Windows_Trojan_RedLineStealer_17ee6a17 {
  meta:
    id = "17ee6a17-161e-454a-baf1-2734995c82cd"
    fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
    creation_date = "2021-06-12"
    last_modified = "2021-06-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "RedLineStealer"
    threat_name = "Windows.Trojan.RedLineStealer"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "RedLine.Logic.SQLite" ascii fullword
    $a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
    $a3 = "RedLine.Client.Models.Gecko" ascii fullword
    $b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
    $b2 = "get_encryptedUsername" ascii fullword
    $b3 = "https://icanhazip.com" wide fullword
    $b4 = "GetPrivate3Key" ascii fullword
    $b5 = "get_GrabTelegram" ascii fullword
    $b6 = "<GrabUserAgent>k__BackingField" ascii fullword
condition:
    1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_RedLineStealer_f54632eb {
  meta:
    id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
    fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
    creation_date = "2021-06-12"
    last_modified = "2021-06-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "RedLineStealer"
    threat_name = "Windows.Trojan.RedLineStealer"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
    $a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
    $a3 = "Software\\Valve\\SteamLogin Data" wide fullword
    $a4 = "get_ScannedWallets" ascii fullword
    $a5 = "get_ScanTelegram" ascii fullword
    $a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
    $a7 = "<Processes>k__BackingField" ascii fullword
    $a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
    $a9 = "<ScanFTP>k__BackingField" ascii fullword
    $a10 = "DataManager.Data.Credentials" ascii fullword
condition:
    6 of ($a*)
}

rule Windows_Trojan_Remcos_b296e965 {
  meta:
    id = "b296e965-a99e-4446-b969-ba233a2a8af4"
    fingerprint = "a5267bc2dee28a3ef58beeb7e4a151699e3e561c16ce0ab9eb27de33c122664d"
    creation_date = "2021-06-10"
    last_modified = "2021-06-10"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Remcos"
    threat_name = "Windows.Trojan.Remcos"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Remcos restarted by watchdog!" ascii fullword
    $a2 = "Mutex_RemWatchdog" ascii fullword
    $a3 = "%02i:%02i:%02i:%03i"
    $a4 = "* Remcos v" ascii fullword
condition:
    2 of them
}

rule Windows_Trojan_SnakeKeylogger_af3faa65 {
  meta:
    id = "af3faa65-b19d-4267-ac02-1a3b50cdc700"
    fingerprint = "15f4ef2a03c6f5c6284ea6a9013007e4ea7dc90a1ba9c81a53a1c7407d85890d"
    creation_date = "2021-04-06"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "SnakeKeylogger"
    threat_name = "Windows.Trojan.SnakeKeylogger"
    source = "Manual"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "get_encryptedPassword" ascii fullword
    $a2 = "get_encryptedUsername" ascii fullword
    $a3 = "get_timePasswordChanged" ascii fullword
    $a4 = "get_passwordField" ascii fullword
    $a5 = "set_encryptedPassword" ascii fullword
    $a6 = "get_passwords" ascii fullword
    $a7 = "get_logins" ascii fullword
    $a8 = "GetOutlookPasswords" ascii fullword
    $a9 = "StartKeylogger" ascii fullword
    $a10 = "KeyLoggerEventArgs" ascii fullword
    $a11 = "KeyLoggerEventArgsEventHandler" ascii fullword
    $a12 = "GetDataPassword" ascii fullword
    $a13 = "_encryptedPassword" ascii fullword
    $b1 = "----------------S--------N--------A--------K--------E----------------"
    $c1 = "SNAKE-KEYLOGGER" ascii fullword
condition:
    8 of ($a*) or #b1 > 5 or #c1 > 5
}

rule Windows_Trojan_Trickbot_01365e46 {
  meta:
    id = "01365e46-c769-4c6e-913a-4d1e42948af2"
    fingerprint = "98505c3418945c10bf4f50a183aa49bdbc7c1c306e98132ae3d0fc36e216f191"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_06fd4ac4 {
  meta:
    id = "06fd4ac4-1155-4068-ae63-4d83db2bd942"
    fingerprint = "ece49004ed1d27ef92b3b1ec040d06e90687d4ac5a89451e2ae487d92cb24ddd"
    creation_date = "2021-03-28"
    last_modified = "2021-03-30"
    description = "Identifies Trickbot unpacker"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_ce4305d1 {
  meta:
    id = "ce4305d1-8a6f-4797-afaf-57e88f3d38e6"
    fingerprint = "ae606e758b02ccf2a9a313aebb10773961121f79a94c447e745289ee045cf4ee"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_1e56fad7 {
  meta:
    id = "1e56fad7-383f-4ee0-9f8f-a0b3dcceb691"
    fingerprint = "a0916134f47df384bbdacff994970f60d3613baa03c0a581b7d1dd476af3121b"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_93c9a2a4 {
  meta:
    id = "93c9a2a4-a07a-4ed4-a899-b160d235bf50"
    fingerprint = "0ff82bf9e70304868ff033f0d96e2a140af6e40c09045d12499447ffb94ab838"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_5340afa3 {
  meta:
    id = "5340afa3-ff90-4f61-a1ac-aba1f32dd375"
    fingerprint = "7da4726ccda6a76d2da773d41f012763802d586f64a313c1c37733905ae9da81"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_e7932501 {
  meta:
    id = "e7932501-66bf-4713-b10e-bcda29f4b901"
    fingerprint = "ae31b49266386a6cf42289a08da4a20fc1330096be1dae793de7b7230225bfc7"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_cd0868d5 {
  meta:
    id = "cd0868d5-42d8-437f-8c1a-303526c08442"
    fingerprint = "2f777285a90fce20cd4eab203f3ec7ed1c62e09fc2dfdce09b57e0802f49628f"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_515504e2 {
  meta:
    id = "515504e2-6b7f-4398-b89b-3af2b46c78a7"
    fingerprint = "8eb741e1b3bd760e2cf511ad6609ac6f1f510958a05fb093eae26462f16ee1d0"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_a0fc8f35 {
  meta:
    id = "a0fc8f35-cbeb-43a8-b00d-7a0f981e84e4"
    fingerprint = "033ff4f47fece45dfa7e3ba185df84a767691e56f0081f4ed96f9e2455a563cb"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_cb95dc06 {
  meta:
    id = "cb95dc06-6383-4487-bf10-7fd68d61e37a"
    fingerprint = "0d28f570db007a1b91fe48aba18be7541531cceb7f11a6a4471e92abd55b3b90"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_9d4d3fa4 {
  meta:
    id = "9d4d3fa4-4e37-40d7-8399-a49130b7ef49"
    fingerprint = "b06c3c7ba1f5823ce381971ed29554e5ddbe327b197de312738165ee8bf6e194"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_34f00046 {
  meta:
    id = "34f00046-8938-4103-91ec-4a745a627d4a"
    fingerprint = "5c6f11e2a040ae32336f4b4c4717e0f10c73359899302b77e1803f3a609309c0"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_f2a18b09 {
  meta:
    id = "f2a18b09-f7b3-4d1a-87ab-3018f520b69c"
    fingerprint = "3e4474205efe22ea0185c49052e259bc08de8da7c924372f6eb984ae36b91a1c"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_d916ae65 {
  meta:
    id = "d916ae65-c97b-495c-89c2-4f1ec90081d2"
    fingerprint = "2e109ed59a1e759ef089e04c21016482bf70228da30d8b350fc370b4e4d120e0"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_52722678 {
  meta:
    id = "52722678-afbe-43ec-a39b-6848b7d49488"
    fingerprint = "e67dda5227be74424656957843777ea533b6800576fd85f978fd8fb50504209c"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_28a60148 {
  meta:
    id = "28a60148-2efb-4cd2-ada1-dd2ae2699adf"
    fingerprint = "c857aa792ef247bfcf81e75fb696498b1ba25c09fc04049223a6dfc09cc064b1"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_997b25a0 {
  meta:
    id = "997b25a0-aeac-4f74-aa87-232c4f8329b6"
    fingerprint = "0bba1c5284ed0548f51fdfd6fb96e24f92f7f4132caefbf0704efb0b1a64b7c4"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_b17b33a1 {
  meta:
    id = "b17b33a1-1021-4980-8ffd-2e7aa4ca2ae4"
    fingerprint = "753d15c1ff0cc4cf75250761360bb35280ff0a1a4d34320df354e0329dd35211"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }
condition:
    all of them
}

rule Windows_Trojan_Trickbot_23d77ae5 {
  meta:
    id = "23d77ae5-80de-4bb0-8701-ddcaff443dcc"
    fingerprint = "d382a99e5eed87cf2eab5e238e445ca0bf7852e40b0dd06a392057e76144699f"
    creation_date = "2021-03-28"
    last_modified = "2021-04-12"
    description = "Targets importDll64 containing Browser data stealer module"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "844974A2D3266E1F9BA275520C0E8A5D176DF69A0CCD5135B99FACF798A5D209"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "/system32/cmd.exe /c \"start microsoft-edge:{URL}\"" ascii fullword
    $a2 = "SELECT name, value, host_key, path, expires_utc, creation_utc, encrypted_value FROM cookies" ascii fullword
    $a3 = "attempt %d. Cookies not found" ascii fullword
    $a4 = "attempt %d. History not found" ascii fullword
    $a5 = "Cookies version is %d (%d)" ascii fullword
    $a6 = "attempt %d. Local Storage not found" ascii fullword
    $a7 = "str+='xie.com.'+p+'.guid='+'{'+components[i]+'}\\n';" ascii fullword
    $a8 = "Browser exec is: %s" ascii fullword
    $a9 = "found mozilla key: %s" ascii fullword
    $a10 = "Version %d is not supported" ascii fullword
    $a11 = "id %d - %s" ascii fullword
    $a12 = "prot: %s, scope: %s, port: %d" ascii fullword
    $a13 = "***** Send %d bytes to callback from %s *****" ascii fullword
    $a14 = "/chrome.exe {URL}" ascii fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_5574be7d {
  meta:
    id = "5574be7d-7502-4357-8110-2fb4a661b2bd"
    fingerprint = "23d9b89917a0fc5aad903595b89b650f6dbb0f82ce28ce8bcc891904f62ccf1b"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets injectDll64 containing injection functionality to steal banking credentials"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "8c5c0d27153f60ef8aec57def2f88e3d5f9a7385b5e8b8177bab55fa7fac7b18"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "webinject64.dll" ascii fullword
    $a2 = "Mozilla Firefox version: %s" ascii fullword
    $a3 = "socks=127.0.0.1:" ascii fullword
    $a4 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii fullword
    $a5 = "<moduleconfig>" ascii fullword
    $a6 = "https://%.*s%.*s" ascii fullword
    $a7 = "http://%.*s%.*s" ascii fullword
    $a8 = "Chrome version: %s" ascii fullword
    $a9 = "IE version real: %s" ascii fullword
    $a10 = "IE version old: %s" ascii fullword
    $a11 = "Build date: %s %s" ascii fullword
    $a12 = "EnumDpostServer" ascii fullword
    $a13 = "ESTR_PASS_" ascii fullword
    $a14 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii fullword
    $a15 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii fullword
    $a16 = "<autoconf>" ascii fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_1473f0b4 {
  meta:
    id = "1473f0b4-a6b5-4b19-a07e-83d32a7e44a0"
    fingerprint = "15438ae141a2ac886b1ba406ba45119da1a616c3b2b88da3f432253421aa8e8b"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets mailsearcher64.dll module"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "9cfb441eb5c60ab1c90b58d4878543ee554ada2cceee98d6b867e73490d30fec"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "mailsearcher.dll" ascii fullword
    $a2 = "%s/%s/%s/send/" wide fullword
    $a3 = "Content-Disposition: form-data; name=\"list\"" ascii fullword
    $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autostart>no</autostart><autoconf><conf ctl=\"SetConf\" file=\"mail"
    $a5 = "eriod=\"60\"/></autoconf></moduleconfig>" ascii fullword
    $a6 = "=Waitu H" ascii fullword
    $a7 = "Content-Length: %d" ascii fullword
condition:
    2 of ($a*)
}

rule Windows_Trojan_Trickbot_dcf25dde {
  meta:
    id = "dcf25dde-36c4-4a24-aa2b-0b3f42324918"
    fingerprint = "4088ae29cb3b665ccedf69e9d02c1ff58620d4b589343cd4077983b25c5b479f"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets networkDll64.dll module containing functionality to gather network and system information"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "BA2A255671D33677CAB8D93531EB25C0B1F1AC3E3085B95365A017463662D787"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "Host Name - %s" wide fullword
    $a2 = "Last Boot Up Time - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
    $a3 = "Install Date - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
    $a4 = "System Directory - %s" wide fullword
    $a5 = "OS Version - %s" wide fullword
    $a6 = "***PROCESS LIST***" wide fullword
    $a7 = "Product Type - Domain Controller" wide fullword
    $a8 = "Registered Organization - %s" wide fullword
    $a9 = "Product Type - Domain Controller" wide fullword
    $a10 = "Build Type - %s" wide fullword
    $a11 = "Boot Device - %s" wide fullword
    $a12 = "Serial Number - %s" wide fullword
    $a13 = "OS Architecture - %s" wide fullword
    $a14 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"1440\"/></au"
    $a15 = "oduleconfig>" ascii fullword
    $a16 = "Computer name: %s" wide fullword
    $a17 = "/c net view /all /domain" ascii fullword
    $a18 = "/c nltest /domain_trusts" ascii fullword
    $a19 = "***SYSTEMINFO***" wide fullword
    $a20 = "***LOCAL MACHINE DATA***" wide fullword
    $a21 = "Admin Name: %s" wide fullword
    $a22 = "Domain controller: %s" wide fullword
    $a23 = "Admin E-mail: %s" wide fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_46dc12dd {
  meta:
    id = "46dc12dd-d81a-43a6-b7c3-f59afa1c863e"
    fingerprint = "997fe1c5a06bfffb754051436c48a0538ff2dcbfddf0d865c3a3797252247946"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets newBCtestDll64 module containing reverse shell functionality"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "BF38A787AEE5AFDCAB00B95CCDF036BC7F91F07151B4444B54165BB70D649CE5"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "setconf" ascii fullword
    $a2 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
    $a3 = "nf\" file = \"bcconfig\" period = \"90\"/></autoconf></moduleconfig>" ascii fullword
    $a4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
    $a5 = "<addr>" ascii fullword
    $a6 = "</addr>" ascii fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_78a26074 {
  meta:
    id = "78a26074-dc4b-436d-8188-2a3cfdabf6db"
    fingerprint = "f0446c7e1a497b93720824f4a5b72f23f00d0ee9a1607bc0c1b097109ec132a8"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets psfin64.dll module containing point-of-sale recon functionality"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "8CD75FA8650EBCF0A6200283E474A081CC0BE57307E54909EE15F4D04621DDE0"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"14400\"/></a"
    $a2 = "Dpost servers unavailable" ascii fullword
    $a3 = "moduleconfig>" ascii fullword
    $a4 = "ALOHA found: %d" wide fullword
    $a5 = "BOH found: %d" wide fullword
    $a6 = "MICROS found: %d" wide fullword
    $a7 = "LANE found: %d" wide fullword
    $a8 = "RETAIL found: %d" wide fullword
    $a9 = "REG found: %d" wide fullword
    $a10 = "STORE found: %d" wide fullword
    $a11 = "POS found: %d" wide fullword
    $a12 = "DOMAIN %s" wide fullword
    $a13 = "/%s/%s/90" wide fullword
    $a14 = "CASH found: %d" wide fullword
    $a15 = "COMPUTERS:" wide fullword
    $a16 = "TERM found: %d" wide fullword
condition:
    3 of ($a*)
}

rule Windows_Trojan_Trickbot_217b9c97 {
  meta:
    id = "217b9c97-a637-49b8-a652-5a42ea19ee8e"
    fingerprint = "7d5dcb60526a80926bbaa7e3cd9958719e326a160455095ff9f0315e85b8adf6"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets pwgrab64.dll module containing functionality use to retrieve local passwords"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "1E90A73793017720C9A020069ED1C87879174C19C3B619E5B78DB8220A63E9B7"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "pwgrab.dll" ascii fullword
    $a2 = "\\\\.\\pipe\\pidplacesomepipe" ascii fullword
    $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii fullword
    $a4 = "select origin_url, username_value, password_value, length(password_value) from logins where blacklisted_by_user = 0" ascii fullword
    $a5 = "<moduleconfig><autostart>yes</autostart><all>yes</all><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
    $a6 = "Grab_Passwords_Chrome(0)" ascii fullword
    $a7 = "Grab_Passwords_Chrome(1)" ascii fullword
    $a8 = "=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" ascii fullword
    $a9 = "Grab_Passwords_Chrome(): Can't open database" ascii fullword
    $a10 = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_"
    $a11 = "Chrome login db copied" ascii fullword
    $a12 = "Skip Chrome login db copy" ascii fullword
    $a13 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
    $a14 = "Grab_Passwords_Chrome() success" ascii fullword
    $a15 = "No password provided by user" ascii fullword
    $a16 = "Chrome login db should be copied (copy absent)" ascii fullword
    $a17 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_d2110921 {
  meta:
    id = "d2110921-b957-49b7-8a26-4c0b7d1d58ad"
    fingerprint = "55dbbcbc77ec51a378ad2ba8d56cb0811d23b121cacd037503fd75d08529c5b5"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets shareDll64.dll module containing functionality use to spread Trickbot across local networks"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "05EF40F7745DB836DE735AC73D6101406E1D9E58C6B5F5322254EB75B98D236A"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "module64.dll" ascii fullword
    $a2 = "Size - %d kB" ascii fullword
    $a3 = "%s - FAIL" wide fullword
    $a4 = "%s - SUCCESS" wide fullword
    $a5 = "ControlSystemInfoService" ascii fullword
    $a6 = "<moduleconfig><autostart>yes</autostart></moduleconfig>" ascii fullword
    $a7 = "Copy: %d" wide fullword
    $a8 = "Start sc 0x%x" wide fullword
    $a9 = "Create sc 0x%x" wide fullword
    $a10 = "Open sc %d" wide fullword
    $a11 = "ServiceInfoControl" ascii fullword
condition:
    3 of ($a*)
}

rule Windows_Trojan_Trickbot_0114d469 {
  meta:
    id = "0114d469-8731-4f4f-8657-49cded5efadb"
    fingerprint = "4f1fa072f4ba577d590bb8946ea9b9774aa291cb2406f13be5932e97e8e760c6"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets systeminfo64.dll module containing functionality use to retrieve system information"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "083CB35A7064AA5589EFC544AC1ED1B04EC0F89F0E60383FCB1B02B63F4117E9"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "<user>%s</user>" wide fullword
    $a2 = "<service>%s</service>" wide fullword
    $a3 = "<users>" wide fullword
    $a4 = "</users>" wide fullword
    $a5 = "%s%s%s</general>" wide fullword
    $a6 = "<program>%s</program>" wide fullword
    $a7 = "<moduleconfig><autostart>no</autostart><limit>2</limit></moduleconfig>" ascii fullword
    $a8 = "<cpu>%s</cpu>" wide fullword
    $a9 = "<ram>%s</ram>" wide fullword
    $a10 = "</installed>" wide fullword
    $a11 = "<installed>" wide fullword
    $a12 = "<general>" wide fullword
    $a13 = "SELECT * FROM Win32_Processor" wide fullword
    $a14 = "SELECT * FROM Win32_OperatingSystem" wide fullword
    $a15 = "SELECT * FROM Win32_ComputerSystem" wide fullword
condition:
    6 of ($a*)
}

rule Windows_Trojan_Trickbot_07239dad {
  meta:
    id = "07239dad-7f9e-4b20-a691-d9538405b931"
    fingerprint = "32d63b8db4307fd67e2c9068e22f843f920f19279c4a40e17cd14943577e7c81"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets vncDll64.dll module containing remote control VNC functionality"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "DBD534F2B5739F89E99782563062169289F23AA335639A9552173BEDC98BB834"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "C:\\Users\\MaxMikhaylov\\Documents\\Visual Studio 2010\\MMVNC.PROXY\\VNCSRV\\x64\\Release\\VNCSRV.pdb" ascii fullword
    $a2 = "vncsrv.dll" ascii fullword
    $a3 = "-new -noframemerging http://www.google.com" ascii fullword
    $a4 = "IE.HTTP\\shell\\open\\command" ascii fullword
    $a5 = "EDGE\\shell\\open\\command" ascii fullword
    $a6 = "/K schtasks.exe |more" ascii fullword
    $a7 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig> " ascii fullword
    $a8 = "\\Microsoft Office\\Office16\\outlook.exe" ascii fullword
    $a9 = "\\Microsoft Office\\Office11\\outlook.exe" ascii fullword
    $a10 = "\\Microsoft Office\\Office15\\outlook.exe" ascii fullword
    $a11 = "\\Microsoft Office\\Office12\\outlook.exe" ascii fullword
    $a12 = "\\Microsoft Office\\Office14\\outlook.exe" ascii fullword
    $a13 = "TEST.TEMP:" ascii fullword
    $a14 = "Chrome_WidgetWin" wide fullword
    $a15 = "o --disable-gpu --disable-d3d11 --disable-accelerated-2d-canvas" ascii fullword
    $a16 = "NetServerStart" ascii fullword
condition:
    6 of ($a*)
}

rule Windows_Trojan_Trickbot_fd7a39af {
  meta:
    id = "fd7a39af-c6ea-4682-a00a-01f775c3bb8d"
    fingerprint = "3f2e654f2ffdd940c27caec3faeb4bda24c797a17d0987378e36c1e16fadc772"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets wormDll64.dll module containing spreading functionality"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "D5BB8D94B71D475B5EB9BB4235A428563F4104EA49F11EF02C8A08D2E859FD68"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "module64.dll" ascii fullword
    $a2 = "worming.png" wide
    $a3 = "Size - %d kB" ascii fullword
    $a4 = "[+] %s -" wide fullword
    $a5 = "%s\\system32" ascii fullword
    $a6 = "[-] %s" wide fullword
    $a7 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii fullword
    $a8 = "*****MACHINE IN WORKGROUP*****" wide fullword
    $a9 = "*****MACHINE IN DOMAIN*****" wide fullword
    $a10 = "\\\\%s\\IPC$" ascii fullword
    $a11 = "Windows 5" ascii fullword
    $a12 = "InfMach" ascii fullword
    $a13 = "%s x64" wide fullword
    $a14 = "%s x86" wide fullword
    $a15 = "s(&(objectCategory=computer)(userAccountControl:" wide fullword
    $a16 = "------MACHINE IN D-N------" wide fullword
condition:
    5 of ($a*)
}

rule Windows_Trojan_Trickbot_2d89e9cd {
  meta:
    id = "2d89e9cd-2941-4b20-ab4e-a487d329ff76"
    fingerprint = "e6eea38858cfbbe5441b1f69c5029ff9279e7affa51615f6c91981fe656294fc"
    creation_date = "2021-03-29"
    last_modified = "2021-04-12"
    description = "Targets tabDll64.dll module containing functionality using SMB for lateral movement"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "3963649ebfabe8f6277190be4300ecdb68d4b497ac5f81f38231d3e6c862a0a8"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" ascii fullword
    $a2 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" ascii fullword
    $a3 = "%SystemRoot%\\system32\\stsvc.exe" ascii fullword
    $a4 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" ascii fullword
    $a5 = "DLL and target process must be same architecture" ascii fullword
    $a6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" ascii fullword
    $a7 = "%SystemDrive%\\stsvc.exe" ascii fullword
    $a8 = "Wrote shellcode to 0x%x" ascii fullword
    $a9 = "ERROR: %d, line - %d" wide fullword
    $a10 = "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p" ascii fullword
    $a11 = "GetProcessPEB:EXCEPT" wide fullword
    $a12 = "Checked count - %i, connected count %i" wide fullword
    $a13 = "C:\\%s\\%s C:\\%s\\%s" ascii fullword
    $a14 = "C:\\%s\\%s" ascii fullword
    $a15 = "%s\\ADMIN$\\stsvc.exe" wide fullword
    $a16 = "%s\\C$\\stsvc.exe" wide fullword
    $a17 = "Size - %d kB" ascii fullword
    $a18 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
    $a19 = "%s - FAIL" wide fullword
    $a20 = "%s - SUCCESS" wide fullword
    $a21 = "CmainSpreader::init() CreateEvent, error code %i" wide fullword
    $a22 = "Incorrect ModuleHandle %i, expect %i" wide fullword
    $a23 = "My interface is \"%i.%i.%i.%i\", mask \"%i.%i.%i.%i\"" wide fullword
    $a24 = "WormShare" ascii fullword
    $a25 = "ModuleHandle 0x%08X, call Control: error create thread %i" wide fullword
    $a26 = "Enter to Control: moduleHandle 0x%08X, unknown Ctl = \"%S\"" wide fullword
condition:
    3 of ($a*)
}

rule Windows_Trojan_Trickbot_32930807 {
  meta:
    id = "32930807-30bb-4c57-8e17-0da99a816405"
    fingerprint = "e216357e6444334d5dd26e57b1233d1601b175826da2d486113bb1bdb322ec9f"
    creation_date = "2021-03-30"
    last_modified = "2021-04-12"
    description = "Targets cookiesdll.dll module containing functionality used to retrieve browser cookie data"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "e999b83629355ec7ff3b6fda465ef53ce6992c9327344fbf124f7eb37808389d"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
    $a2 = "Cookies.dll" ascii fullword
    $a3 = "Usage: .system COMMAND" ascii fullword
    $a4 = "Usage: .log FILENAME" ascii fullword
    $a5 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
    $a6 = "Usage: .dump ?--preserve-rowids? ?--newlines? ?LIKE-PATTERN?" ascii fullword
    $a7 = "Usage %s sub-command ?switches...?" ascii fullword
    $a8 = "\\AppData\\Roaming\\Microsoft\\Windows\\Cookies" ascii fullword
    $a9 = "%s:%d: expected %d columns but found %d - extras ignored" ascii fullword
    $a10 = "%s:%d: expected %d columns but found %d - filling the rest with NULL" ascii fullword
    $a11 = "Unknown option \"%s\" on \".dump\"" ascii fullword
    $a12 = "error in %s %s%s: %s" ascii fullword
    $a13 = "UPDATE temp.%s SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view')" ascii fullword
    $a14 = ");CREATE TEMP TABLE [_shell$self](op,cmd,ans);" ascii fullword
    $a15 = "\\AppData\\Local\\Microsoft\\Windows\\INetCookies" ascii fullword
    $a16 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
    $a17 = "INSERT INTO selftest(tno,op,cmd,ans)\nSELECT rowid*10,op,cmd,ans FROM [_shell$self];" ascii fullword
    $a18 = "RELEASE dump;" ascii fullword
    $a19 = "SELECT %s FROM temp.t592690916721053953805701627921227776 x ORDER BY %s" ascii fullword
    $a20 = "temp%llx" ascii fullword
    $a21 = "File \"%s\" already exists." ascii fullword
    $a22 = "Error: ambiguous test-control: \"%s\"" ascii fullword
    $a23 = "Cookies send failure: servers unavailable" ascii fullword
    $a24 = "\\cookies.sqlite" ascii fullword
    $a25 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii fullword
condition:
    5 of ($a*)
}

rule Windows_Trojan_Trickbot_618b27d2 {
  meta:
    id = "618b27d2-22ad-4542-86ed-7148f17971da"
    fingerprint = "df4336e5cbca495dac4fe110bd7a727e91bb3d465f76d3f3796078332c13633c"
    creation_date = "2021-03-30"
    last_modified = "2021-04-12"
    description = "Targets Outlook.dll module containing functionality used to retrieve Outlook data"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "d3ec8f4a46b21fb189fc3d58f3d87bf9897653ecdf90b7952dcc71f3b4023b4e"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "OutlookX32.dll" ascii fullword
    $a2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" wide fullword
    $a3 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" wide fullword
    $a4 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" wide fullword
    $a5 = "OutlookX32" ascii fullword
    $a6 = " Port:" wide fullword
    $a7 = " User:" wide fullword
    $a8 = " Pass:" wide fullword
    $a9 = "String$" ascii fullword
    $a10 = "outlookDecrU" ascii fullword
    $a11 = "Cannot Decrypt" ascii fullword
    $a12 = " Mail:" wide fullword
    $a13 = " Serv:" wide fullword
    $a14 = ",outlookDecr" ascii fullword
    $a15 = "CryptApi" ascii fullword
condition:
    5 of ($a*)
}

rule Windows_Trojan_Trickbot_6eb31e7b {
  meta:
    id = "6eb31e7b-9dc3-48ff-91fe-8c584729c415"
    fingerprint = "660286a167d1b8b89cbbafee974c3aa39e9280f15dffe4e9c0114d3a1f09f6e2"
    creation_date = "2021-03-30"
    last_modified = "2021-04-12"
    description = "Targets DomainDll module containing functionality using LDAP to retrieve credentials and configuration information"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "3e3d82ea4764b117b71119e7c2eecf46b7c2126617eafccdfc6e96e13da973b1"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "module32.dll" ascii fullword
    $a2 = "Size - %d kB" ascii fullword
    $a3 = "services.xml" wide fullword
    $a4 = "datasources.xml" wide fullword
    $a5 = "groups.xml" wide fullword
    $a6 = "printers.xml" wide fullword
    $a7 = "drives.xml" wide fullword
    $a8 = "scheduledtasks.xml" wide fullword
    $a9 = "</moduleconfig> " ascii fullword
    $a10 = "<moduleconfig>" ascii fullword
    $a11 = "\\\\%ls\\SYSVOL\\%ls" wide fullword
    $a12 = "DomainGrabber14" ascii fullword
    $a13 = "<autostart>yes</autostart>" ascii fullword
    $a14 = "<needinfo name=\"id\"/>" ascii fullword
    $a15 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_91516cf4 {
  meta:
    id = "91516cf4-c826-4d5d-908f-e1c0b3bccec5"
    fingerprint = "69338d2e74d82d1a587a9b078d13b8a457758412ca420ca53f88923a3f8d336b"
    creation_date = "2021-03-30"
    last_modified = "2021-03-30"
    description = "Generic signature used to identify Trickbot module usage"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "6cd0d4666553fd7184895502d48c960294307d57be722ebb2188b004fc1a8066"
    scan_type = "File, Memory"
    severity = 80
  strings:
    $a1 = "<moduleconfig>" ascii wide
    $a2 = "<autostart>" ascii wide
    $a3 = "</autostart>" ascii wide
    $a4 = "</moduleconfig>" ascii wide
condition:
    2 of ($a*)
}

rule Windows_Trojan_Trickbot_be718af9 {
  meta:
    id = "be718af9-5995-4ae2-ba55-504e88693c96"
    fingerprint = "047b1c64b8be17d4a6030ab2944ad715380f53a8a6dd9c8887f198693825a81d"
    creation_date = "2021-03-30"
    last_modified = "2021-04-12"
    description = "Targets permadll module used to fingerprint BIOS/firmaware data"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "user_platform_check.dll" ascii fullword
    $a2 = "<moduleconfig><nohead>yes</nohead></moduleconfig>" ascii fullword
    $a3 = "DDEADFDEEEEE"
    $a4 = "\\`Ruuuuu_Exs|_" ascii fullword
    $a5 = "\"%pueuu%" ascii fullword
condition:
    3 of ($a*)
}

rule Windows_Trojan_Trickbot_f8dac4bc {
  meta:
    id = "f8dac4bc-2ea1-4733-a260-59f3cae2eba8"
    fingerprint = "256daf823f6296ae02103336817dec565129a11f37445b791b2f8e3163f0c17f"
    creation_date = "2021-03-30"
    last_modified = "2021-04-12"
    description = "Targets rdpscan module used to bruteforce RDP"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "13d102d546b9384f944f2a520ba32fb5606182bed45a8bba681e4374d7e5e322"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "rdpscan.dll" ascii fullword
    $a2 = "F:\\rdpscan\\Bin\\Release_nologs\\"
    $a3 = "Cookie: %s %s" wide fullword
    $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
    $a5 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
    $a6 = "X^Failed to create a list of contr" ascii fullword
    $a7 = "rdp/domains" wide fullword
    $a8 = "Your product name" wide fullword
    $a9 = "rdp/over" wide fullword
    $a10 = "rdp/freq" wide fullword
    $a11 = "rdp/names" wide fullword
    $a12 = "rdp/dict" wide fullword
    $a13 = "rdp/mode" wide fullword
condition:
    4 of ($a*)
}

rule Windows_Trojan_Trickbot_9c0fa8fe {
  meta:
    id = "9c0fa8fe-8d5f-4581-87a0-92a4ed1b32b3"
    fingerprint = "bd49ed2ee65ff0cfa95efc9887ed24de3882c5b5740d0efc6b9690454ca3f5dc"
    creation_date = "2021-07-13"
    last_modified = "2021-07-13"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Trickbot"
    threat_name = "Windows.Trojan.Trickbot"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }
condition:
    all of them
}

rule Windows_Trojan_Vidar_9007feb2 {
  meta:
    id = "9007feb2-6ad1-47b6-bae2-3379d114e4f1"
    fingerprint = "8416b14346f833264e32c63253ea0b0fe28e5244302b2e1b266749c543980fe2"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Vidar"
    threat_name = "Windows.Trojan.Vidar"
    source = "Automated"
    maturity = "Diagnostic"
    reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a = { E8 53 FF D6 50 FF D7 8B 45 F0 8D 48 01 8A 10 40 3A D3 75 F9 }
condition:
    all of them
}

rule Windows_Trojan_Vidar_114258d5 {
  meta:
    id = "114258d5-f05e-46ac-914b-1a7f338ccf58"
    fingerprint = "9b4f7619e15398fcafc622af821907e4cf52964c55f6a447327738af26769934"
    creation_date = "2021-06-28"
    last_modified = "2021-06-28"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Vidar"
    threat_name = "Windows.Trojan.Vidar"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "BinanceChainWallet" fullword
    $a2 = "*wallet*.dat" fullword
    $a3 = "SOFTWARE\\monero-project\\monero-core" fullword
    $b1 = "CC\\%s_%s.txt" fullword
    $b2 = "History\\%s_%s.txt" fullword
    $b3 = "Autofill\\%s_%s.txt" fullword
condition:
    1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Zeus_e51c60d7 {
  meta:
    id = "e51c60d7-3afa-4cf5-91d8-7782e5026e46"
    fingerprint = "f654d45152fd0e6a494b563e46e900a8afc4831dbdb832fda141146802af4a9d"
    creation_date = "2021-02-07"
    last_modified = "2021-07-16"
    description = "Detects strings used in Zeus web injects. Many other malware families are built on Zeus and may hit on this signature."
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Zeus"
    threat_name = "Windows.Trojan.Zeus"
    source = "Manual"
    maturity = "Diagnostic"
    reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
    reference_sample = "d7e9cb60674e0a05ad17eb96f8796d9f23844a33f83aba5e207b81979d0f2bf3"
    scan_type = "File, Memory"
    severity = 100
  strings:
    $a1 = "set_url" ascii wide fullword
    $a2 = "data_before" ascii wide fullword
    $a3 = "data_after" ascii wide fullword
    $a4 = "data_end" ascii wide fullword
    $a5 = "data_inject" ascii wide fullword
condition:
    4 of them
}
