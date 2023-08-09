rule is_new_office_document
{
	strings:
		$header = { 50 4B 03 04 }
		$word_str = "word/document.xml"
        $excel_str = "xl/workbook.xml"
        $ppt_str = "ppt/presentation.xml"
		$enc_header = { D0 CF 11 E0 A1 B1 1A E1 }
		$enc_str = "EncryptionInfo" nocase wide ascii
	condition:
	   ($header at 0 and ($word_str or $excel_str or $ppt_str or $enc_str)) or ($enc_header and $enc_str)
}