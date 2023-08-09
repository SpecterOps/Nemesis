rule is_tomcat_users
{
    strings:
        $str1 = "<tomcat-users>"
        $str2 = "<user username="
    condition:
        $str1 and $str2
}
