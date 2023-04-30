# InfoSec OpenAI Examples
Currently a script which takes a list of Languages e.g:

```python
languages = [
    "Java",
    "Python",
    "Csharp",
    "Swift",
    "Kotlin",
    "PHP",
    "Rust",
    "Go",
    "JavaScript",
]
```
And for each language describe the following list of CWEs:

* Describe the vulnerability
* Show an example of vulnerable code in that language
* Show an example of remediation
* Create a Semgrep rule to detect the vulnerability
* Create a CodeQL rule to detect the vulnerability

The Goal is to show how you can write the structure of a long set of technical best practices, requirments and OpenAI can write the initial DRAFT of those best practices and techincal information quickly for people to then review and edit.

These are the following CWEs:


```python
cwe_list = [
    'CWE-079: Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    'CWE-020: Improper Input Validation',
    'CWE-078: Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    'CWE-089: Improper Neutralization of Special Elements used in an SQL Command (\'SQL Injection\')',
    'CWE-022: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
    'CWE-352: Cross-Site Request Forgery (CSRF)',
    'CWE-434: Unrestricted Upload of File with Dangerous Type',
    'CWE-306: Missing Authentication for Critical Function',
    'CWE-502: Deserialization of Untrusted Data',
    'CWE-287: Improper Authentication',
    'CWE-798: Use of Hard-coded Credentials',
    'CWE-276: Incorrect Default Permissions',
    'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
    'CWE-522: Insufficiently Protected Credentials',
    'CWE-611: Improper Restriction of XML External Entity Reference',
    'CWE-918: Server-Side Request Forgery (SSRF)',
    'CWE-077: Improper Neutralization of Special Elements used in a Command (\'Command Injection\')',
    'CWE-295: Improper Certificate Validation',
    'CWE-094: Improper Control of Generation of Code (\'Code Injection\')',
    'CWE-269: Improper Privilege Management',
    'CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement (\'Expression Language Injection\')',
    'CWE-059: Improper Link Resolution Before File Access (\'Link Following\')',
    'CWE-319: Cleartext Transmission of Sensitive Information',
    'CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')',
    'CWE-532: Insertion of Sensitive Information into Log File'
]
```
