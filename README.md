# WAF Bypass Tool

WAF bypass is an open source tool to analyze the security of any WAF for False Positives and False Negatives using predefined and customizable payloads. Check your WAF before an attacker does. WAF Bypass Tool is developed by Nemesida WAF team ([nemesida-waf.com](https://nemesida-waf.com)) with the participation of community.

### When using, do not violate the law. We are not responsible for the use of the program.

<img align="left" src="https://user-images.githubusercontent.com/99513957/211177749-44f0b3b3-2ecc-486e-a4d3-87b1df5ed1a2.png">

There are attacks for which it is impossible to create a signature, while not increasing the number of false positives. Therefore, it is absolutely normal that Nemesida WAF Free bypass the attack, and the commercial version of Nemesida WAF Free blocks. For example, we can execute the <code>cat /etc/passwd</code> command in the following ways:

<pre>
%2f???%2f??t%20%2f???%2fp??s??
cat+/e't'c/pa'ss'wd
e'c'ho 'swd test pentest' | awk '{print "cat /etc/pas"$1}' | bash
ec'h'o 'cat /etc/examplewd' | sed 's/example/pass/g' | bash
</pre>

### Payloads type and description
- CM (Custom HTTP Method)
- FP (False Positive)
- LDAP (LDAP Injection etc.)
- LFI (Local File Include)
- MFD (multipart/form-data)
- NoSQLi (NoSQL injection)
- OR (Open Redirect)
- RCE (Remote Code Execution)
- RFI (Remote File Inclusion)
- SQLi (SQL injection)
- SSI (Server-Side Includes)
- SSTI (Server-Side Template Injection)
- UWA (Unwanted Access)
- XSS (Cross-Site Scripting)

## How to run

### Run from Docker
The latest waf-bypass always available via the [Docker Hub](https://hub.docker.com/r/nemesida/waf-bypass). It can be easily pulled via the following command:

<pre>
# docker pull nemesida/waf-bypass
</pre>

Run with the command:

<pre>
# docker run nemesida/waf-bypass --host='example.com'
</pre>

### Run source code from GitHub
<pre>
# git clone https://github.com/nemesida-waf/waf_bypass.git /opt/waf-bypass/
# python3 -m pip install -r /opt/waf-bypass/requirements.txt
# python3 /opt/waf-bypass/main.py --host='example.com'  
</pre>

### Options

- <code>'--proxy'</code> (<code>--proxy='http://proxy.example.com:3128'</code>) - option allows to specify where to connect to instead of the host.

- <code>'--header'</code> (<code>--header 'Authorization: Basic YWRtaW46YWRtaW4='</code>) - option allows to specify the HTTP header to send with all requests (e.g. for authentication). Multiple use is allowed.

- <code>'--block-code'</code> (<code>--block-code='222'</code>) - option allows you to specify the HTTP status code to expect when the WAF is blocked. (default is <code>403</code>). Multiple use is allowed.

- <code>'--threads'</code> (<code>--threads=10</code>) - option allows to specify the number of parallel scan threads (default is <code>10</code>).

- <code>'--timeout'</code> (<code>--timeout=10</code>) - option allows to specify a request processing timeout in sec. (default is <code>30</code>).
