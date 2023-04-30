# InfoSec OpenAI Examples

# Overview

There are a set of ongoing uses cases and best practices for Generative AI for infosec use cases.



# Use Case 01 - Generating Long Technical Documents

Currently a script which takes a list of Languages e.g (Python, Java, JS, C# etc..), and for each language describe the following list of CWEs:

* Describe the vulnerability type
* Show an example of vulnerable code in that language
* Show an example of remediation
* Create a Semgrep rule to detect the type of vulnerability
* Create a CodeQL rule to detect the type of vulnerability

The goal is to show how you can write the structure of a long set of technical best practices, requirments and OpenAI can write the initial DRAFT of those best practices and techincal information quickly for people to then review and edit.

# Use Case 02 - InfoSec Knowledge Specific ChatBot

This is a weba application trained on the OWASP OpenCRE Infosec References and returns responces with the correct citations