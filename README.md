# WAF Bypass Tool

WAF Bypass by Nemesida WAF team ([nemesida-waf.com](https://nemesida-waf.com)) is an open source tool (Python3) to check any WAF for the number of False Positives/False Negative using predefined payloads (if desired, the set of payloads can be changed). Turn off ban mode before use.

A script developed for internal needs, including for testing Nemesis WAF and Nemesida WAF Free, but you can use it to test any WAF.

### When using, do not violate the law. We are not responsible for the use of the program.

![WAF Bypass Script](https://camo.githubusercontent.com/9ccddb9274eefa8bbe31cc1b0df79782ea6a92d5985b8eeab093a2cd83ad834a/68747470733a2f2f686162726173746f726167652e6f72672f776562742f73642f756a2f39312f7364756a39317333752d5f356a653970666b6e64306577696c6a732e706e67)

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free bypass the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:
<pre>
%2f???%2f??t%20%2f???%2fp??s??
cat+/e't'c/pa'ss'wd
e'c'ho 'swd test pentest' | awk '{print "cat /etc/pas"$1}' | bash
ec'h'o 'cat /etc/examplewd' | sed 's/example/pass/g' | bash
</pre>

## How to run

### Run from Docker
The latest waf-bypass always available via the [Docker Hub](https://hub.docker.com/r/nemesida/waf-bypass). It can be easily pulled via the following command:

<pre>
# docker pull nemesida/waf-bypass
</pre>

Run with the command:

<pre>
# docker run nemesida/waf-bypass --host='example.com'
or
# docker run nemesida/waf-bypass --host='example.com' --proxy='http://proxy.example.com:3128'
</pre>

### Run source code from GitHub
<pre>
# git clone https://github.com/nemesida-waf/waf_bypass.git /opt/waf-bypass/
# python3 -m pip install -r /opt/waf-bypass/requirements.txt

# python3 /opt/waf-bypass/main.py --host='example.com'
or
# python3 /opt/waf-bypass/main.py --host='example.com' --proxy='http://proxy.example.com:3128'
</pre>

### Options
The --proxy option specifies where to connect to instead of the host.
 
The --block option specifies an HTTP status code expected when the WAF blocks.  Default if none specified is 403.  May be repeated.

The --header option specifies an HTTP header to send with all requests (e.g. for authentication).  May be repeated.
