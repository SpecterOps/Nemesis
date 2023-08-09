rule is_passwd
{
    strings:
        $re = /root:.+:[0-9]{,10}:[0-9]{,10}:[a-zA-Z0-9 ]{,50}:[\/a-zA-Z0-9 ]{,50}:[\/a-zA-Z0-9 ]{,50}/
    condition:
        $re
}
