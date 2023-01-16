# WAF Bypass Tool

WAF bypass is an open source tool to analyze the security of any WAF for False Positives and False Negatives using predefined and customizable payloads. Check your WAF before an attacker does. WAF Bypass Tool is developed by Nemesida WAF team ([nemesida-waf.com](https://nemesida-waf.com)) with the participation of community.

![WAF Bypass](https://user-images.githubusercontent.com/99513957/211177749-44f0b3b3-2ecc-486e-a4d3-87b1df5ed1a2.png)

## How to run

> It is forbidden to use for illegal and illegal purposes. Don't break the law. We are not responsible for possible risks associated with the use of this software.

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

#### Options

- <code>'--proxy'</code> (<code>--proxy='http://proxy.example.com:3128'</code>) - option allows to specify where to connect to instead of the host.

- <code>'--header'</code> (<code>--header 'Authorization: Basic YWRtaW46YWRtaW4='</code> or <code>--header 'Authorization: Basic YWRtaW46YWRtaW4=' --header 'X-TOKEN: ABCDEF'</code>) - option allows to specify the HTTP header to send with all requests (e.g. for authentication). Multiple use is allowed.

- <code>'--block-code'</code> (<code>--block-code='222'</code> or <code>--block-code='403' --block-code='222'</code>) - option allows you to specify the HTTP status code to expect when the WAF is blocked. (default is <code>403</code>). Multiple use is allowed.

- <code>'--threads'</code> (<code>--threads=15</code>) - option allows to specify the number of parallel scan threads (default is <code>10</code>).

- <code>'--timeout'</code> (<code>--timeout=10</code>) - option allows to specify a request processing timeout in sec. (default is <code>30</code>).

- <code>'--json-format'</code> - an option that allows you to display the result of the work in JSON format (useful for integrating the tool with security platforms).


## Payloads

Depending on the purpose, payloads are located in the appropriate folders:

- FP (False Positive payloads)

- API (API testing payloads)
- CM (Custom HTTP Method payloads)
- LDAP (LDAP Injection etc. payloads)
- LFI (Local File Include payloads)
- MFD (multipart/form-data payloads)
- NoSQLi (NoSQL injection payloads)
- OR (Open Redirect payloads)
- RCE (Remote Code Execution payloads)
- RFI (Remote File Inclusion payloads)
- SQLi (SQL injection payloads)
- SSI (Server-Side Includes payloads)
- SSRF (Server-side request forgery payloads)
- SSTI (Server-Side Template Injection payloads)
- UWA (Unwanted Access payloads)
- XSS (Cross-Site Scripting payloads)


### Write your own payloads

When compiling a payload, the following zones, method and options are used:

- URL        - request's path (e.g.: <code>/my_payload</code>)
- ARGS       - request's query (e.g.: <code>my_payload</code> or <code>param1=my_payload1&param2=my_payload2</code>)
- BODY       - request's body (e.g.: <code>my_payload</code> or <code>param1=my_payload1&param2=my_payload2</code>)
- COOKIE     - request's cookie (e.g.: <code>my_payload</code>)
- USER-AGENT - request's user-agent (e.g.: <code>my_payload</code>)
- REFERER    - request's referer (e.g.: <code>my_payload</code> or <code>http://example.com/my_payload</code>)
- HEADER     - request's header (e.g.: <code>my_payload</code>)
- METHOD     - request's method (e.g. GET, POST, HEAD etc.)

- JSON - specifies that the request's body should be in JSON format
- BLOCKED - specifies that the request should be blocked (FN testing) or not (FP)

Except for some cases described below, the zones are independent of each other and are tested separately (those if 2 zones are specified - the script will send 2 requests - alternately checking one and the second zone).

For the zones you can use <code>%RND%</code> suffix, which allows you to generate an arbitrary string of 6 letters and numbers. (e.g.: <code>param%RND=my_payload</code> or <code>param=%RND%</code> OR <code>A%RND%B</code>)

You can create your own payloads, to do this, create your own folder on the '/payload/' folder, or place the payload in an existing one (e.g.: '/payload/XSS'). Allowed data format is JSON.


#### API directory
API testing payloads located in this directory are automatically appended with a header <code>'Content-Type: application/json'</code>.


#### MFD directory
For MFD (multipart/form-data) payloads located in this directory, you must specify the <code>BODY</code> (required) and <code>BOUNDARY</code> (optional). If <code>BOUNDARY</code> is not set, it will be generated automatically (in this case, only the payload must be specified for the </code>BODY</code>, without additional data (<code>'... Content-Disposition: form-data; ...'</code>).

If a <code>BOUNDARY</code> is specified, then the content of the <code>BODY</code> must be formatted in accordance with the RFC, but this allows for multiple payloads in <code>BODY</code> a separated by <code>BOUNDARY</code>.

Other zones are allowed in this directory (e.g.: <code>URL</code>, <code>ARGS</code> etc.). Regardless of the zone, header <code>'Content-Type: multipart/form-data; boundary=...'</code> will be added to all requests.
