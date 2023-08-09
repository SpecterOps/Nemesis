rule is_shadow
{
    strings:
        $re = /root:.*:[0-9]{,10}:[0-9]{,10}:[0-9]{,10}:[0-9]{,10}:::/
    condition:
        $re
}
