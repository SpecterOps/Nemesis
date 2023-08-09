rule is_ole_office_document
{
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str = "SummaryInformation" nocase wide ascii
	condition:
	   $header at 0 and $str
}