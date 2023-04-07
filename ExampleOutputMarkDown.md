# Java

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of vulnerability that occurs when an attacker is able to inject malicious scripts into a web page, allowing them to gain access to confidential information or to take control of the page. These scripts can be injected into a web page through user input, such as by entering malicious code into a text box or URL. When a user visits the page, the malicious script is executed and can access user data or perform other malicious activities. XSS vulnerabilities can lead to serious security breaches and should always be taken seriously.

### Vulnerable Code

```java
String userInput = request.getParameter("userInput");
String output = "<h1>Welcome, " + userInput + "</h1>";
response.getWriter().write(output);

// This code is vulnerable to cross-site scripting (XSS) attacks because it does not properly sanitize the user input before it is included in the generated output. An attacker could inject malicious JavaScript code which would be executed in the user's browser when the output is rendered.
```

### Remediation

```java
The following code example is a remediation for Cross-site Scripting (CWE-079):

// Before
String input = request.getParameter("input");
response.getWriter().println("<p>" + input + "</p>");

// After
String input = request.getParameter("input");
input = input.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
response.getWriter().println("<p>" + input + "</p>");
```

### Semgrep Rule

```yaml
rule = dot.cwe_079:
    patterns:
    - pattern: |
        "<\s*[^>]*[^/]\s*(on\w+\s*=\s*("[^"]*"|'[^']*'))
      message: "Potential cross-site scripting issue detected."
      severity: WARNING
      languages: [java]
```

### CodeQL Rule

```ql
import cwe089

class CrossSiteScriptingVulnerability implements Rule {
   
    // Query to detect the vulnerability
    Query<Node> vulnerableNodes =
        // Find any HTML ‘<’ tags
        (HtmlElement h) =>
            h.getTextContent()

        // Which contain any untrusted input
        // i.e. input which is not properly sanitized
        & exists(Variable v, MethodInvocation m |
            h.getTextContent().contains(m)
            & m.getTarget().matches(v)
            & not cwe089.sanitizationFunction(m)
        )

    // Issue a finding for each vulnerable node
    @Override
    test() {
        for (Node n : vulnerableNodes) {
            report(n);
        }
    }

}
```

## CWE-020: Improper Input Validation

### Description

CWE-020 is an Improper Input Validation vulnerability that occurs when an application fails to validate user input, allowing malicious or malformed data to be entered into the system. This can lead to security issues such as buffer overflows, SQL injection, and other attacks. In Java, this can be caused by not validating user input when using methods such as getParameter, readLine, and readBytes. This can allow an attacker to enter malicious data and manipulate the system.

### Vulnerable Code

```java
public void processInput(String input) {
  // do something with the input
  // ...
  System.out.println("Input is: " + input);
}

In this code, the input is not being properly validated, which can lead to potential security vulnerabilities. An attacker could pass malicious input that would be executed by the system, potentially leading to malicious code execution.
```

### Remediation

```java
The following is an example of a method for performing proper input validation in Java:

public boolean validateInput(String input) {
    if (input == null || input.trim().length() == 0) {
        return false;
    }
    // Perform other validation checks as necessary
    return true;
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detect improper input validation"
    author = "Author"
    date = "2020-08-05"
  source:
    lang = "java"
  detection:
    input_validation:
      patterns:
       - pattern: '.*receive.*input.*'
         message: 'Improper input validation may lead to vulnerabilities'
         confidence: high
}
```

### CodeQL Rule

```ql
import cwe020

class ImproperInputValidationVulnerability implements Vulnerability {
  // Check if the vulnerable code is present
  Boolean isVulnerable(Cwe020 cwe020) {
    return exists(Method m,
      m.getName().matches("(?i).*validat.*") and
      cwe020.getInputValidation(m)
    );
  }
}
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of security vulnerability that occurs when a user is able to inject malicious code into an OS command. This can be done by inputting special characters, such as semicolons or quotation marks, which can be interpreted as part of a command and then executed by the system. This can be dangerous, as it can allow for malicious code to be executed on the system. In Java, this vulnerability can occur if user input is passed directly to an OS command without being properly sanitized.

### Vulnerable Code

```java
String command = "ping -c 1 " + ipAddr;
Runtime.getRuntime().exec(command);

In the above example, the code creates a command string that includes an IP address specified by the user. This could allow an attacker to inject malicious code into the command string, which would then execute on the system when the Runtime.getRuntime().exec() method is called.
```

### Remediation

```java
Original vulnerable code:

String command = "ping -t " + userInput;
Runtime.getRuntime().exec(command);

Remediated code:

String[] command = {"ping", "-t", userInput};
Process proc = new ProcessBuilder(command).start();
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detect CWE-078: Improper Neutralization of Special Elements used in an OS Command"
    severity = "High"
  strings:
    $input = "*"
  condition:
    all of them
}

---

rule = {
  meta:
    description = "Detect CWE-078: Improper Neutralization of Special Elements used in an OS Command"
    severity = "High"
  strings:
    $input = "/*"
  condition:
    all of them
}
```

### CodeQL Rule

```ql
import cwe
import java

class CommandInjectionVulnerability extends SecurityCodeQL {
  // Create a query to detect the vulnerable code
  query vulnerableCode() {
    // Find any Java method which takes a string as an argument
    Method m = method("java.lang.String", _, _)
    // Find any command execution in the method
    Process p = Process.create(m)
    // Find any string concatenation in the method
    StringConcatenation sc = StringConcatenation.inMethod(m)
    // Find any string concatenation used as an argument for a command execution
    select sc, p 
    such that sc.isArgumentTo(p)
  }

  // Create a query to generate an alert for vulnerable code
  query alertVulnerableCode() {
    // Find any vulnerable code
    vulnerableCode()
    //
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089 is a type of vulnerability where an attacker is able to inject malicious SQL code into an application. This can be done by sending malicious user input to the application that is not properly sanitized and then used in an SQL query. The attacker can then use this query to gain access to the application's data or even execute code on the server. This vulnerability can cause data leakage, information disclosure, and even system compromise.

### Vulnerable Code

```java
String query = "SELECT user_name FROM users WHERE user_id=" + request.getParameter("user_id");
Statement stmt = connection.createStatement();
ResultSet result = stmt.executeQuery(query);

In this example, the application is building an SQL query using a parameter from an HTTP request without properly validating or escaping it. This could allow an attacker to inject malicious SQL code into the query and potentially gain access to sensitive data or execute malicious commands on the database.
```

### Remediation

```java
// Before
String query = "SELECT * FROM users WHERE username = '" + username + "'";

// After
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, username);
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects SQL Injection vulnerability"
    severity = "CRITICAL"
  source:
    language = "Java"
  patterns:
    - pattern: 'String query = .*?;'
      name: "sql_query"
    - pattern: 'query.+?(".*?|'.*?')'
      name: "sql_injection"
      within: sql_query
  filters:
    - sql_injection
}
```

### CodeQL Rule

```ql
import cwe089

class Cwe089Rule extends Rule {
    Cwe089Rule() {
        super("Cwe089")
    }

    @Override
    query {
        // Find all SQL queries
        QSqlQuery qQuery | 
        // Find all uses of user-controlled data
        QSqlQuery.prepare(string userInput)
        // Find any instances of the user-controlled data being used without proper sanitization
        qQuery.exec(string userInput)
    }
}
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

This vulnerability occurs when an application fails to properly restrict the paths a user can access, allowing a user to traverse directories outside the intended path. This vulnerability can be exploited by malicious users to access sensitive data and files, as well as to gain unauthorized access to system resources. This vulnerability is especially dangerous when user-supplied input is used as part of the path, as attackers can manipulate the input to traverse directories outside of the intended path.

### Vulnerable Code

```java
public void copyFile(String sourceFile, String destinationFile) { 
   Path sourcePath = Paths.get(sourceFile);
   Path destinationPath = Paths.get("/home/user/destination/" + destinationFile);
   try {
    Files.copy(sourcePath, destinationPath);
   } catch (IOException e) {
    e.printStackTrace();
   }
}

The above code is vulnerable to Path Traversal because it fails to properly validate the source path, allowing a malicious user to craft a source path traversing up the directory tree. For example, an attacker can pass in a source file path like "../../../etc/passwd" to access sensitive system files.
```

### Remediation

```java
One way of remediating CWE-022 is to disallow directory traversal by validating user input. For example, in Java, a developer can use the Paths.get() method to validate user input and restrict it to a predetermined list of directories.

String userInput = "../../../unauthorized/file.txt";

//Validate user input against predetermined list of directories
try {
    Paths.get(userInput);
} catch (InvalidPathException e) {
    //Handle exception
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Path Traversal Vulnerability"
    severity = "CRITICAL"
    author = "Security Team"
  strings:
    $st1 = /(\.\.\/)/
    $st2 = /(\.\.\\)/
    $st3 = /(\/\*)/
    $st4 = /(\\\*)/
  condition:
    $st1 or $st2 or $st3 or $st4
}
```

### CodeQL Rule

```ql
import java

class PathTraversalVulnerability extends Rule {
  // Search for a File object being created with a user-provided path
  File(String path) {
    // Check if the path contains an 'upwards directory traversal' 
    // character (../)
    contains(path, "../")
  }
  
  // Check if the file object is being used to read or write to a file 
  // outside the current working directory
  File.read() {
    // Check if the path of the file object is not within the 
    // current working directory
    not within(this.path, cwd())
  }
  
  File.write() {
    not within(this.path, cwd())
  }
  
  // Generate an alert when the vulnerability is found
  alert Path Traversal Vulnerability detected {
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site request forgery (CSRF) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. This attack exploits the trust a web site has for a user. In a CSRF attack, the attacker tricks the user's browser into sending a forged HTTP request, including the user's session cookie and any other authentication information, to a vulnerable web site. The forged request may contain malicious commands, such as changing the user's password or transferring money out of their account. This attack can be used to gain access to the user's account, steal data, or perform other malicious actions without the user's knowledge or consent.

### Vulnerable Code

```java
The following code sample is vulnerable to Cross-Site Request Forgery (CSRF) attacks:

//Retrieve the user's session ID
String sessionId = request.getParameter("sessionId");

//Retrieve user data from the request
String userName = request.getParameter("userName");
String password = request.getParameter("password");

//Create a URL to access the user's account
String url = "http://example.com/account?sessionId=" + sessionId + "&userName=" + userName + "&password=" + password;

//Send a request to the URL
HttpClient client = new DefaultHttpClient();
HttpGet get = new HttpGet(url);
HttpResponse response = client.execute(get);
```

### Remediation

```java
One way to remediate a Cross-Site Request Forgery (CSRF) vulnerability is to implement a unique token system in all requests. This can be done by generating a unique token for each user session and adding it to all requests. Then, when the server receives the request, it can check for the presence of the token and verify it is valid before processing the request. 

For example, each time a client requests a protected resource, the server can generate a unique token and store it in the user's session. Then, the server can add the token to the response and include it in all subsequent requests. The server can then verify that the token is valid before processing the request.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects Cross-Site Request Forgery (CSRF) vulnerability"
    strings:
      $request_csrf = /.*sendRedirect.*/
      $csrf_token = /.*(csrf|CSRF).*/
    condition:
      $request_csrf and not $csrf_token
}
```

### CodeQL Rule

```ql
import java

class CWE352_Cross_Site_Request_Forgery_CSRF {
    // Get all HTTP requests
    private HttpRequest reqs  =  select  distinct t 
                                from HttpRequest t 
                                where t instanceof HttpRequest;
    
    // Get all HTTP responses
    private HttpResponse resps = select distinct t 
                                from HttpResponse t 
                                where t instanceof HttpResponse;
    
    // Get all requests that are sent without a CSRF token
    private HttpRequest noTokenReqs = select t
                                    from HttpRequest t
                                    where not exists(t.getHeaders("CSRF-Token"));
    
    // Get all responses to requests sent without a CSRF token
    private HttpResponse noTokenResps = select t
                                        from HttpResponse
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability that occurs when an application allows a user to upload a file of any type, without restrictions or validation. This can lead to malicious files being uploaded, such as scripts or executables, which can then be used to compromise the system or gain access to sensitive data. The application should always validate the type of file being uploaded and restrict it to only those types that are safe and necessary.

### Vulnerable Code

```java
public void uploadFile(String fileName)
{
    // Get the file from the client
    File uploadedFile = getFileFromHttpRequest();

    // Create the path to the file
    String filePath = "/upload/" + fileName;

    // Save the file to the server
    try {
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(uploadedFile);
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

This code is vulnerable because it does not check the file type of the uploaded file before writing it to the server. This could lead to malicious files, such as executable files, being uploaded to the server and potentially causing damage.
```

### Remediation

```java
Remediation for this vulnerability could include ensuring that any files uploaded to the server are checked for dangerous types or content prior to allowing them to be stored on the server. This could be done by either implementing an antivirus scanner on the server or by performing a file extension check on the uploaded file to ensure it is not one of the types that should not be allowed. Additionally, the server should be configured to restrict the maximum size of files that can be uploaded and only allow certain types of files that are deemed safe.
```

### Semgrep Rule

```yaml
rules:
  - id: cwe-434
    patterns:
      - pattern: |
          (
            command: "upload"
            and param[*].value: /.*\.(php|asp|csh|pl|cgi|exe|bash|sh|py|js)$/
          )
    message: "Unrestricted upload of file with dangerous type detected"
    severity: error
```

### CodeQL Rule

```ql
import java

class UnrestrictedUploadOfFileWithDangerousType extends SecurityCodeScanRule {
  // Checks for code which allows the unrestricted upload of a file with a dangerous type
 
  // Define the query
  Query dangerousTypeUpload = 
    find Method m, Class c, StringLiteral sl
    where sl.value =~ /.*\.(exe|bat|bin|cmd|reg|pif|scr|dll|vbs|vbe|wsf|wsh|shs|com|cpl|jar|js|jse|msi|msp|mst|pcd|scf|lnk|inf|ocx|sys)$/
    and c.hasMethod(m)
    and m.name = "upload"
    and m.hasAnnotation("RequestMapping")
    and m.getAnnotation("RequestM
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306 is a vulnerability that occurs when an application fails to properly authenticate a user before allowing them access to a critical function. This can lead to malicious actors gaining access to sensitive data or functions that should only be accessible to authorized users. Without proper authentication, there is no way to verify that the user is actually who they claim to be. As a result, this vulnerability can lead to a wide range of security risks.

### Vulnerable Code

```java
// vulnerable code
public class AuthenticationCheck {
    public void doSomething() {
        // code to do something
    }
    
    public void doSomethingCritical() {
        // code to do something critical
    }
}

// vulnerable code can be fixed by adding an authentication check
public class AuthenticationCheck {
    public void doSomething() {
        // code to do something
    }
    
    public void doSomethingCritical() {
        // check if user is authenticated
        if (isAuthenticated()) {
            // code to do something critical
        } else {
            // throw an error
            throw new SecurityException("User is not authenticated");
        }
    }
    
    private boolean isAuthenticated() {
        // code to check if user is authenticated
    }
}
```

### Remediation

```java
The following code snippet shows an example of how to remediate a vulnerability of missing authentication for a critical function in Java code:

// Create a user authentication object
UserAuthentication auth = new UserAuthentication();

// Check if user is authenticated
if (auth.isAuthenticated()) {
    // Execute the critical function
    executeCriticalFunction();
}
else {
    // Throw an exception
    throw new AccessDeniedException("User not authenticated!");
}
```

### Semgrep Rule

```yaml
rule = {
        strings:
            $function_name = /.*authentication.*/
        condition:
            all
    }

    not (
        exists(p.CallExpr[f.id == $function_name]
            and p.CallExpr.callee.Object.property.name == "authenticate"
    )
```

### CodeQL Rule

```ql
import java

class CWE306MissingAuthenticationForCriticalFunction extends Security {
    /**
     * Vulnerability: CWE-306: Missing Authentication for Critical Function
     * 
     * This query finds instances of missing authentication for critical functions
     * by looking for methods that are marked as critical but are not using authentication.
     */
    vulnerable_methods() {
        Method m
        m.getAnnotation(java.security.Critical)
        not m.isProtectedByAuthentication()
    }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a common vulnerability that occurs when an application deserializes untrusted data. This vulnerability can be exploited by malicious actors to inject malicious code into the application and gain access to confidential data. When an application deserializes data, it is assumed that the data is valid and safe, however, if the data is not properly validated, attackers can inject malicious code and take control of the application. This can lead to data leakage, system compromise, and other malicious activities.

### Vulnerable Code

```java
public class DeserializeUntrustedData {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // Create an input stream to read the object
        FileInputStream fis = new FileInputStream("data.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        // Read the object
        Object o = ois.readObject();
        ois.close();
 
        // Cast the object to a known type and use it
        String s = (String) o;
        System.out.println(s);
    }
}
```

### Remediation

```java
// Before
ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
Object obj = ois.readObject();

// After
ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
Object obj = null;
try {
    obj = ois.readObject();
} catch (ClassNotFoundException e) {
    throw new RuntimeException("ClassNotFoundException encountered while deserializing untrusted data");
} catch (InvalidClassException e) {
    throw new RuntimeException("InvalidClassException encountered while deserializing untrusted data");
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        id = "CWE-502"
        description = "Detects deserialization of untrusted data"
        author = "Your name here"
    patterns:
        - pattern: "(ObjectInputStream.readObject\( *\)|ObjectInputStream.readUnshared\( *\)|ObjectInputStream.readFields\( *\))"
        message: "Deserialization of untrusted data may lead to CWE-502"
        severity: WARNING
    }
```

### CodeQL Rule

```ql
import cwe502

class DeserializationUntrustedDataVulnerability implements CodeQLSearch {
  // Find calls to deserialize methods that use untrusted data
  @Cwe502
  Query<Invocation> deserializationVuln() {
    Invocation.find(
      // find any method calls
      _, 
      // that involve deserialization
      Method.named("deserialize")
    )
    // where the argument is untrusted data
    .where(
      Invocation.argument(0).hasSource("UntrustedData")
    )
  }
}
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability in which a system does not adequately verify the identity of a user before granting them access. This could be due to a lack of authentication protocols, weak or nonexistent passwords, or a lack of multi-factor authentication. This type of vulnerability can allow an attacker to gain access to a system, data, or accounts they should not have access to.

### Vulnerable Code

```java
String username = request.getParameter("username");
String password = request.getParameter("password");

if (username.equals("admin") && password.equals("admin")) {
    // Allow user to authenticate
}
```

### Remediation

```java
The most effective way to remediate CWE-287: Improper Authentication is to implement multi-factor authentication (MFA). This involves using two or more authentication factors to verify the identity of a user. The factors can include something the user knows (such as a password or PIN), something the user has (such as a security token or key fob), and something the user is (such as a biometric). By requiring the user to provide multiple forms of authentication, it makes it much more difficult for an attacker to gain unauthorized access.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects improper authentication"
      author = "security@example.com"
      id = "CWE-287"
    strings:
      $loginString = /login|authenticate/
    condition:
      $loginString
}
```

### CodeQL Rule

```ql
import java

class ImproperAuthentication extends SecurityCodeQL {
 
  // Query to detect improper authentication
  query improperAuthentication(){
    // Find classes that implement authentication
    Class authClass = find("java.util.concurrent.Callable") 
    // Find methods that check for authentication
    Method authMethod = authClass.getMethod("authenticate")
    // Find any calls to the authentication method
    Call authCall = authMethod.getCalls()
    where(authCall)
  }

}
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability in which an application or system stores and uses hard-coded credentials, such as usernames and passwords, instead of retrieving them from an external source. This vulnerability leaves the system vulnerable to attack because an attacker can easily gain access to the credentials if they know where to look. Hard-coded credentials can also cause an application to behave in unexpected ways, as the credentials might not be updated when they need to be.

### Vulnerable Code

```java
String username = "root";
String password = "password123";
 
Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", username, password);
```

### Remediation

```java
// Before 
String username = "admin";
String password = "password";

// After
String username = System.getProperty("username");
String password = System.getProperty("password");
```

### Semgrep Rule

```yaml
rule = {
  id = "CWE798-hardcoded-credentials",
  pattern = "<[^>]*(username|password|token|secret)[^>]*>",
  message = "Found hardcoded credential(s)",
  severity = "WARNING"
}
```

### CodeQL Rule

```ql
import java

class CWE798HardcodedCredentialsVulnerability {
  // Rule to detect the use of hardcoded credentials
  // https://cwe.mitre.org/data/definitions/798.html
 
  // Find all string literals
  string strLiteral = /".*"/
 
  // Find all string literals which are assigned to variables
  string strLiteralAssignedToVar = strLiteral:Expr |
                                  strLiteral:Expr[AssignExpr]
 
  // Find all variables which are used as credentials
  string credentialVariables = strLiteralAssignedToVar.lhs:Variable
 
  // Find all methods which are used as credentials
  string credentialMethods = credentialVariables.memberAccesses:Method
 
  // Find all method invocations that use the credential
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 is a type of vulnerability where an application or system has incorrect default permissions set on files or directories, which can lead to unauthorized users or processes having access to those files or directories. This can lead to sensitive data or other resources being accessed, modified, or deleted without authorization. In some cases, this can also lead to privilege escalation or other malicious activities.

### Vulnerable Code

```java
File file = new File("C:\\SecretFile.txt");
if(file.exists()) {
    BufferedReader br = new BufferedReader(new FileReader(file));
    String line;
    while ((line = br.readLine()) != null) {
        System.out.println(line);
    }
    br.close();
}

This code creates a file with default permissions that anyone with access to the system can read. This could lead to sensitive data being exposed if the file is not secured with the correct permissions.
```

### Remediation

```java
// Remediation for incorrect default permissions

// Set more restrictive default permissions 
Path path = Paths.get("filePath");
Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r-----"));
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects incorrect default permissions"
      author = "AuthorName"
      version = "0.1.0"
    severity = "WARNING"
    id = "CWE-276"
    tags = ["security", "cwe-276", "java"]
    confidence = "HIGH"
    message = "Incorrect default permissions detected"
   
    source:
      patterns:
       - pattern: 'File.setReadable(true, false)'
       - pattern: 'File.setWritable(true, false)'
       - pattern: 'File.setExecutable(true, false)'
       - pattern: 'File.setReadOnly()'
      
    false-positives:
      - any
 
    detection:
      condition: all
}
```

### CodeQL Rule

```ql
// Finds classes with incorrect default permissions
import java

class IncorrectDefaultPermissions extends Query {
  /**
   * Finds classes with incorrect default permissions
   */
  predicate isVulnerableClass() {
    // Finds classes with incorrect default permissions
    cAccess = c.getAccess()
    return cAccess.contains(java.Access.PRIVATE) or
           cAccess.contains(java.Access.PROTECTED)
  }

  query vulnerableClasses() {
    // Finds classes with incorrect default permissions
    find class c 
    such that isVulnerableClass(c)
  }
}
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that can occur when sensitive information is exposed to an unauthorized actor. This can happen when an application fails to properly protect confidential information such as passwords, credit card numbers, Social Security numbers, or other sensitive data. An attacker may be able to access this information by exploiting weaknesses in the application's authentication, authorization, or encryption mechanisms. This type of vulnerability can lead to serious data breaches and financial losses.

### Vulnerable Code

```java
String sensitiveData = "This is sensitive data";
System.out.println(sensitiveData); // Exposes sensitive data to unauthorized actor
```

### Remediation

```java
// Before Remediation
File file = new File("C:/Users/sensitive_data.txt");

// After Remediation
String filePath = System.getProperty("user.home") + "/sensitive_data.txt";
File file = new File(filePath);
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Exposure of Sensitive Information to an Unauthorized Actor"
    author = "Author Name"
  strings:
    $vuln_data = "SECRET_DATA"
  condition:
    $vuln_data
}
```

### CodeQL Rule

```ql
import cwe200

class CWE200Rule extends Query {
  // Find any sensitive information exposed to an unauthorized actor
  // through a method call or member access
  vulnerableMethodCallOrMemberAccess() {
    MethodCall m | MemberAccess m
      // Check if the receiver of the method call or member access is
      // an unauthorized actor
      where CWE200.isUnauthorizedActor(m.getReceiver())
  }
  
  // Find any sensitive information that is returned from the vulnerable method call or
  // member access
  sensitiveInformationReturned() {
    MethodCall m
      // Find the return type of the method call
      let returnType := m.getType()
      // Check if the return type contains sensitive information
      where CWE200.containsSensitiveInformation(returnType)
  }
  
  // Find any vulnerable method calls or
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a vulnerability which occurs when credentials, such as usernames and passwords, are stored in an insecure manner, making them vulnerable to malicious actors. This could occur if the credentials are stored in plain text, in an unencrypted file, or in a file that is accessible to unauthorized users. If a malicious actor gains access to the credentials stored in this manner, they can use them to gain access to the system or resources associated with them.

### Vulnerable Code

```java
String username = "admin";
String password = "admin";

// Store credentials in plaintext
String credentials = username + ":" + password;

// Store credentials to file
FileWriter fileWriter = new FileWriter("credentials.txt");
fileWriter.write(credentials);
fileWriter.close();
```

### Remediation

```java
The following example shows how to remediate CWE-522 by using an encryption library to encrypt sensitive information before storing it in a database.

//Encrypting sensitive information
public static void encryptData(String data) {
	try {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		String encryptedData = Base64.encodeBase64String(cipher.doFinal(data.getBytes()));
		//Store the encrypted data in a database
		//..
	} catch (Exception e) {
		e.printStackTrace();
	}
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        severity = "medium"
        description = "Insufficiently Protected Credentials"
    strings:
        $user_id_string = /[A-Za-z0-9_]+/
        $password_string = /[A-Za-z0-9_]+/
    condition:
        $user_id_string and $password_string
}
```

### CodeQL Rule

```ql
import cwe522

class InsufficientlyProtectedCredentialsVulnerability(cwe522.Vulnerability):
  // Rule to detect code that stores credentials in plain text,
  // without adequate protection
  //
  // Returns true if the given method stores credentials in plain text
  // without adequate protection
  predicate isVulnerableMethod(Method m) {
    exists(
      Field f,
      Assignment a |
        a.getLeft() = f &&
        f.belongsTo(m) &&
        f.getType() = "String" &&
        a.getRight().contains("plaintext")
    )
  }
}
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a type of security vulnerability in which an XML parser is configured to allow the inclusion of external references, such as external document type definitions (DTDs) or external entities. This can result in an attacker being able to modify or gain access to sensitive data. For example, an attacker could craft an XML document with an external reference to a malicious entity that can be used to execute code or gain access to sensitive system resources.

### Vulnerable Code

```java
// vulnerable code
String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
              "<!DOCTYPE foo SYSTEM \"http://example.com/evil.dtd\">\n" + 
              "<foo>&entity;</foo>";

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(xml));  // vulnerable code
```

### Remediation

```java
// Remediation
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-611-XML-External-Entity-Reference-Vulnerability",
    patterns: [
        {
            pattern: "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse($input)",
            message: "Potential XML External Entity Reference Vulnerability. Consider using an XML parser that disables external entities.",
            severity: "CRITICAL",
        }
    ]
}
```

### CodeQL Rule

```ql
import java

class CWE611_ImproperRestrictionofXMLExternalEntityReference extends SecurityTest {
    // Query to detect when an XML document is parsed and external entity references are enabled
    def vulnerable = from xmlParser: java.xml.XMLParser,
        source: java.io.InputSource
    where xmlParser.isExpandEntityReferences() == true
    select xmlParser, source

    // Query to detect cases where the source is a file or URL
    def vulnerableFileOrURL = 
        vulnerable.where(source.isFile() 
        or source.isURL())

    // Final query to detect the vulnerability
    vulnerableFileOrURL
    report CWE611_ImproperRestrictionofXMLExternalEntityReference 
    "Improper restriction of XML external entity reference" 
    vulnerability vulnerableFileOrURL
}
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-Side Request Forgery (SSRF) is a type of security vulnerability that occurs when an attacker is able to manipulate a web application into making a malicious request to a third-party server. This can be done by submitting malicious data to the application, which is then used to construct a request to an external server. The attacker can then gain access to sensitive information or launch further attacks. In Java, SSRF vulnerabilities can be caused by insecure handling of user-supplied data, such as user input that is not properly validated or sanitized.

### Vulnerable Code

```java
URL url = new URL("http://attacker.example.com/");
HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
InputStream in = urlConnection.getInputStream();
```

### Remediation

```java
The most effective way to remediate SSRF vulnerabilities is to validate all user-supplied URLs and reject any requests that do not match a predefined list. For example, in Java code:

// Create a list of allowed URLs
List<String> allowedURLs = new ArrayList<String>();
allowedURLs.add("http://example.com/validUrl");
allowedURLs.add("ftp://example.com/validUrl");

String userSuppliedUrl = getUserSuppliedUrl();

// Validate the URL
if (allowedURLs.contains(userSuppliedUrl)) {
    // Process the request
    // ...
} else {
    // Reject the request
    // ...
}
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-918-detection",
  patterns: [
    // Detects suspicious requests to internal services
    {
      pattern: "%{url_scheme}:%{url_host}:%{url_port}",
      message: "Detected suspicious request to an internal service",
      severity: "MEDIUM"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe
import java

class ServerSideRequestForgery extends Vulnerability {
  // Rule to detect Server Side Request Forgery
  // CWE-918
 
  // Query for all methods that take a URL string as a parameter
  // and make a request to that URL
  query vulnerableMethodInvocation {
    // Find the method declaration
    MethodDecl decl
    MethodInvocation invok
    where invok.method = decl
    // Check the parameter type of the method
    and decl.getParameters()[0].getType().toString() = "java.net.URL"
    // Check the method is making an HTTP request
    and exists(ClassType ct, MethodDecl md |
      ct.getMethods()[] = md
      and md.getName() = "openConnection"
      and md.getClassType().toString() = "
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

CWE-077 occurs when user input is not sufficiently sanitized before being used in system commands, allowing an attacker to inject malicious commands into a program. This can lead to attackers gaining access to sensitive data, executing arbitrary code, or changing system configurations. In order for this vulnerability to be successful, the attacker must be able to inject commands into the application without being detected.

### Vulnerable Code

```java
String userInput = request.getParameter("command");
Runtime.getRuntime().exec(userInput);
```

### Remediation

```java
One way to remediate CWE-077 Command Injection vulnerabilities is to properly sanitize user input to ensure that only valid characters are accepted. For example, you can use a whitelist approach to validate user input.

Below is an example of how to use a whitelist to validate user input in Java:

String input = request.getParameter("userInput");
String validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

if (input.matches("[" + validCharacters + "]+")) {
    // The input is valid, proceed as normal
    // ...
} else {
    // The input is invalid, throw an exception
    throw new IllegalArgumentException("Invalid input");
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-077-detect",
  patterns: [
    {
      pattern: "eval(${parameter:StringLiteral} + \"${command:StringLiteral}\")",
      message: "Vulnerable to CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')",
      severity: "CRITICAL"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe077

class CWE077_Improper_Command_Injection extends SecurityCodeScanRule {
    // Rule to detect command injection vulnerabilities
    // https://cwe.mitre.org/data/definitions/77.html
   
    // Find any calls to the ProcessBuilder class
    ProcessBuilder builderCall = findConstructor("java.lang.ProcessBuilder", _);
    
    // Find any calls to the constructor of the ProcessBuilder class
    // that pass in a command as an argument
    ProcessBuilder commandCall = findConstructor("java.lang.ProcessBuilder", _, stringLiteral);
    
    // Flag any calls to the ProcessBuilder constructor that
    // pass in a command as an argument
    // as a potential command injection vulnerability
    flag(commandCall, cwe077.getDescription());
}
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295 is a vulnerability that occurs when a program fails to properly validate digital certificates. This can allow attackers to spoof the identity of a trusted server or client, enabling them to intercept and modify data, launch man-in-the-middle attacks, or spoof a legitimate user’s identity. This can result in a variety of security issues, such as malicious code execution, data alteration, and more. Common causes of this vulnerability include improperly configured trust stores, missing or incorrect certificate validation procedures, and weak or outdated encryption algorithms.

### Vulnerable Code

```java
String url = "https://example.com/"; 
URLConnection con = new URL(url).openConnection(); 
HttpsURLConnection httpsCon = (HttpsURLConnection) con; 

// Skip certificate validation 
httpsCon.setHostnameVerifier(new HostnameVerifier() {
    @Override 
    public boolean verify(String s, SSLSession sslSession) {
        return true;
    } 
}); 

// Make the connection 
httpsCon.connect();
```

### Remediation

```java
The following code demonstrates a remediation for CWE-295: Improper Certificate Validation. The code sets up a TrustManager that checks the validity of an X.509 certificate chain presented by a server.

// Create a TrustManager that validates X.509 certificate chains
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
            for (X509Certificate cert : certs) {
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    throw new CertificateException
```

### Semgrep Rule

```yaml
rule = {
	meta:
		author = "anonymous"
		description = "Detects potential improper certificate validation"
		id = "CWE-295"
		severity = "high"
		tags = ["security", "certificate-validation"]
	
	source: 
		exclude = ["java.net.URLConnection", "javax.net.ssl.HttpsURLConnection"]
	
	strings:
		$checkCert = /(?i)(?:checkServerTrusted|verify|validate)(?:Certificate|Server|Host)/
	
	conditions:
		$checkCert
}
```

### CodeQL Rule

```ql
import cwe295
import java

class ImproperCertificateValidation implements Cwe295 {
    // Rule to detect improper certificate validation
    // vulnerabilities
    //
    // References:
    //   https://cwe.mitre.org/data/definitions/295.html
    //
    // Severity: Critical
    
    // Find all calls to X509TrustManager.checkServerTrusted
    X509TrustManager.checkServerTrusted(...) {
        // Find calls that do not provide a valid certificate chain
        not validCertChain {
            // Flag the call as a CWE-295 vulnerability
            cwe295.report("Improper certificate validation detected.")
        }
    }
}
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability that occurs when input data is not correctly sanitized or validated before it is used to generate executable code. This can occur when user input is used in a code generation process, such as when user input is used to generate SQL code or when user input is used to generate HTML code. If the input is not sanitized or validated, an attacker can inject malicious code into the generated code and execute it. This can lead to serious security issues, such as data theft, data manipulation, and system compromise.

### Vulnerable Code

```java
// This code allows a user to input an SQL query 
// which is then executed on a database.
String userInput = request.getParameter("userInput");
String query = "SELECT * FROM table WHERE " + userInput;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Remediation

```java
// Remediation Example
public String sanitizeInput(String input) {
    String sanitizedInput = input.replaceAll("[^a-zA-Z0-9]", "");
    return sanitizedInput;
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      code = "CWE-094"
      description = "Improper Control of Generation of Code ('Code Injection')"
    strings:
      $expr_exec = /\b(eval|assert|exec|execfile|executemany|load_source|compile|eval_js|eval_fn|exec_js|exec_fn|spawn|system|popen|popen2|popen3)\b/
    condition:
      any of ($expr_exec)
}
```

### CodeQL Rule

```ql
import cwe094

from CodeElement c
where c.kind = "METHOD"
and c.containsCall("java.lang.Runtime.exec(String)")

select c, "Improper control of code generation detected"

rule CWE_094_Detection {
 
  // Find calls to java.lang.Runtime.exec(String)
  // which may indicate improper control of code generation
 
  pattern {
    Call c;
    c.target:Method m;
    m.name = "exec" and m.owner.name = "java.lang.Runtime";
    c.args[0]:StringLiteral s;
  }
  
  // Run the CWE-094 checker on the call
 
  checker {
    cwe094.check(c,s);
  }
}
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 Improper Privilege Management is a vulnerability that occurs when an application does not properly manage privileges, allowing unauthorized access to certain areas of the application or granting too much access to certain users. This could allow malicious users to access sensitive data, modify or delete data, or perform other unauthorized operations. It could also lead to elevation of privilege attacks, in which a user is granted privileges beyond what they normally should have access to.

### Vulnerable Code

```java
public class VulnerableClass {
    private int accessLevel = 0;

    public void setAccessLevel(int level) {
        accessLevel = level;
    }

    public void doSomething() {
        if (accessLevel > 0) {
            // Perform privileged operations
        }
    }
}

In this code, the access level is set without any input validation. This means a malicious user can set the access level to any value, bypassing the privilege checks and gaining access to privileged operations. This is a vulnerability due to improper privilege management.
```

### Remediation

```java
Example:

1. Assign roles and privileges to each user, clearly defining what they are allowed to do with the system.

2. Create a system of user account monitoring, logging and reporting to detect any unauthorized activity.

3. Implement a system of password management, ensuring that passwords are changed frequently, are complex and not shared among users.

4. Implement access control mechanisms such as authentication, authorization and encryption to protect data from unauthorized access.

5. Implement a policy that requires users to be trained on security best practices and to update their knowledge regularly.

6. Once privileges have been assigned to a user, monitor and review those privileges to ensure that they are still appropriate for the user's role.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects improper privilege management"
      author = "Your Name"
      id = "CWE-269"
    source:
      lang = "java"
    detection:
      condition: any
      for-each:
        pattern:
          - 'PrivilegedAction.doPrivileged(.*)'
       within:
        - 3
       patterns:
        - "'checkPermission(.*)'"
        - "'AccessController.checkPermission(.*)'"
}
```

### CodeQL Rule

```ql
import cwe269

class CWE269ImproperPrivilegeManagement extends Rule {
  // Detects improper privilege management
  vulnerability {
    // Finds improper privilege management
    CWE269.IncorrectPrivilegeManagement()
  }
  
  // Reports the vulnerability
  defer = CWE269.IncorrectPrivilegeManagement() {
    // Report the vulnerability
    report("Improper privilege management detected.")
  }
}
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

Expression Language Injection (CWE-917) is a type of injection vulnerability that occurs when an application uses an expression language to evaluate user-supplied input. This can allow an attacker to inject malicious code into the application which can then be executed. Expression language injection can occur in Java applications when user-supplied input is used in the expression language statements, such as when using the JavaServer Pages (JSP) language. This can allow an attacker to inject malicious code into the application, such as executing arbitrary system commands. This can result in the application being compromised and data being compromised.

### Vulnerable Code

```java
String username = request.getParameter("username");
String password = request.getParameter("password");
String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
Statement stmt = con.createStatement();
ResultSet rs = stmt.executeQuery(query);

This code is vulnerable to expression language injection because it takes an unvalidated parameter from a user input and directly inserts it into a query string. An attacker could inject malicious code into the query string, which would be executed on the database server.
```

### Remediation

```java
In order to remediate CWE-917, input validation should be performed on user input before the data is processed by the application. For example, if an application is using the Java Expression Language (EL), the following code could be used to validate user input against a whitelist of acceptable characters before it is evaluated as an EL expression:

String userInput = request.getParameter("userInput");
String regex = "^[a-zA-Z0-9_\\-\\.\\(\\)]*$";
if (!userInput.matches(regex)) {
    throw new IllegalArgumentException("Invalid characters found in user input");
}
// Now evaluate the user input as expression language
Object result = expression.getValue(userInput);
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects potential Expression Language Injection vulnerabilities"
      authors = ["Your Name"]
      references = ["https://cwe.mitre.org/data/definitions/917.html"]
    strings:
       $el_func = /\$\{.*\(/
    condition:
       $el_func
}
```

### CodeQL Rule

```ql
import java

class ExpressionLanguageInjection implements Rule {
  // Check for potential Expression Language Injection vulnerabilities
  // in Java code
 
  // Finds all EL expressions in the code
  private Expr elExpression = Expr.regex("\\$\\{[^\\}]+\\}");
  
  // Finds all potential EL expression injection points
  private Expr elExpressionInjectionPoint = Expr.select(CallExpr.class,
    "callExpr",
    (CallExpr callExpr) =>
      callExpr.getTarget().getName() == "setAttribute"
      and callExpr.getArgument(1).matches(elExpression)
  );
  
  // Checks if there are any potential EL expression injection points
  // without proper input sanitization
  private Query elExpressionInjectionQuery =
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability that occurs when a program fails to properly validate or sanitize links before following them. This results in the program accessing files or resources that are not supposed to be accessed, potentially leading to data leakage, information disclosure, or other security risks. This vulnerability can be exploited by malicious actors who craft malicious links or modify existing links to point to unexpected resources.

### Vulnerable Code

```java
File file = new File("../../etc/passwd");
BufferedReader br = new BufferedReader(new FileReader(file));
String line;
while ((line = br.readLine()) != null) {
    System.out.println(line);
}
br.close();

The code above is vulnerable to CWE-059 because it uses a relative path to access the file, which can be manipulated by an attacker to access files outside of the intended directory. For example, an attacker could traverse up the directory tree to access the "/etc/passwd" file, which is not the intended file. To prevent this vulnerability, the code should specify an absolute path to the file.
```

### Remediation

```java
// Before
String fileName = "/etc/passwd"
File file = new File(fileName);

// After
String fileName = "/etc/passwd"
if (Paths.get(fileName).isAbsolute()) {
    File file = new File(fileName);
} else {
    throw new IllegalArgumentException("Path is not absolute");
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper link resolution before file access"
    author = "Security team"
    date = "2020-10-05"
  strings:
    $func_name = /(File|Path).(toRealPath|resolve)/
  condition:
    $func_name
}
```

### CodeQL Rule

```ql
import java

class ImproperLinkResolution extends SecurityCodeScannerRule {
  // Matches an expression that resolves to a file path
  // and is passed as an argument to a File constructor
  // or a method that triggers file access.
  private Expr getFilePathExpr(Expr baseExpr) {
    Expr filePathExpr = baseExpr;
    while (filePathExpr instanceof Expr.BinaryOp) {
      Expr.BinaryOp binaryOpExpr = (Expr.BinaryOp) filePathExpr;
      if (binaryOpExpr.op == BinaryOp.PLUS) {
        filePathExpr = binaryOpExpr.getRightOperand();
      } else {
        break;
      }
    }
    return filePathExpr;
  }

  // Checks that a given expression
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information is transmitted over an unsecure network connection in plaintext (cleartext). This means that the data can be intercepted and viewed by anyone with access to the network, creating a potential security risk. In the case of Java applications, this can occur if the application is set up to send data in plaintext instead of using encryption protocols such as SSL/TLS. This can expose the data to anyone who is monitoring the network and can lead to the theft of sensitive information or other malicious activities.

### Vulnerable Code

```java
String username = "user";
String password = "password";

URL url = new URL("http://example.com/login");
HttpURLConnection connection = (HttpURLConnection) url.openConnection();

connection.setRequestMethod("POST");

String urlParameters = "username=" + username + "&password=" + password;

connection.setDoOutput(true);
DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
wr.writeBytes(urlParameters);
wr.flush();
wr.close();

int responseCode = connection.getResponseCode();
```

### Remediation

```java
// Before
String url = "http://example.com/data.json";

// After
String url = "https://example.com/data.json";
```

### Semgrep Rule

```yaml
rule = {
  severity = "warning"
  id = "CWE-319-cleartext-transmission"
  pattern = "(?i)\\b((?:http|ftp|https):\\/\\/)?[\\w\\d\\-_]+\\.(?:[\\w\\d\\-_]+\\.)*[\\w\\d\\-_]+\\b"
  message = "Cleartext transmission of sensitive information"
}
```

### CodeQL Rule

```ql
import cwe319

class CWE319CleartextTransmissionOfSensitiveInformation : CodeQL

{ 
  // Find all parameters of a method that contain sensitive information
  // and are transmitted in cleartext
  ClassDecl cls
  MethodDecl m

  // Look for methods that contain parameters containing sensitive information
  ParameterDecl sensitiveParam
  sensitiveParam.getAncestors() += {m}

  // Look for methods that transmit data in cleartext
  // over the network
  MethodInvocation mInv
  mInv.getAncestors() += {m}
  mInv.getTarget().getName() = "send"
  mInv.getTarget().getDeclaringType().getName() = "java.net.Socket"

  // Check if the sensitive data is being sent over the network
  // in cleartext
  exists (Parameter
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 is a vulnerability that allows an attacker to redirect a user from a legitimate website to an untrusted website. This can be done by providing a malicious URL within a link or redirect code that points to the malicious website. This is a dangerous vulnerability because it allows attackers to steal sensitive information from users, such as passwords, credit card numbers, and other personal data. A successful attack can also lead to the installation of malicious software on the user's computer. In Java, this vulnerability can be exploited by manipulating URL parameters and redirecting the user to a malicious website.

### Vulnerable Code

```java
// This code redirects the user to a URL specified in the request parameter "url"
String url = request.getParameter("url");
response.sendRedirect(url);
```

### Remediation

```java
// Before Remediation
response.sendRedirect(request.getParameter("url"));

// After Remediation
String url = request.getParameter("url");
if (url != null && url.startsWith("https://www.example.com")) {
    response.sendRedirect(url);
}
```

### Semgrep Rule

```yaml
rule = {
	meta:
		description = "Detects CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
		author = "Semgrep Security"
		date = "2020-08-30"
		severity = "MEDIUM"
		tags = ["CWE-601", "Open Redirect"]
		
		
	// Detects potential open redirects
	// Checks for calls to redirect() using untrusted input
	// as destination URL
	
	strings:
		$redirect_func = /redirect\s*\(/
		$url_param = /[^\s]*\$\w+/
	
	expressions:
		$redirect_func @url_param
}
```

### CodeQL Rule

```ql
import java

class OpenRedirectVulnerability extends Vulnerability {
  /**
   * Finds instances of open redirection
   */
  OpenRedirectVulnerability() {
    super("Open Redirection");
  }

  // Find code that sets the location of an HTTP response
  // to a value provided by an external source
  @FindMethods("java.net.HttpURLConnection#setRequestProperty")
  pred setResponseLocationFromExternalSource(java.net.HttpURLConnection httpConn) {
    exists(String externalSourceValue |
      httpConn.setRequestProperty("Location", externalSourceValue)
  }

  // Issue a warning when the external source value is used as the location
  // of the response
  @Warning("Open Redirection vulnerability")
  warn onOpenRedirect(java.net.HttpURLConnection httpConn) {
    setResponseLocationFromExternal
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability that occurs when sensitive information, such as passwords, credit card numbers, or personal data, is inadvertently inserted into a log file. This information is then stored in the log file, and may be accessed by an attacker if the log file is not properly protected. Attackers can then use this information to gain access to the system, or to commit fraud or identity theft.

### Vulnerable Code

```java
try {
    String sensitiveData = "password123";

    // Perform some action
    // ...

    // Write sensitive data to log file
    FileWriter writer = new FileWriter("logs.txt");
    writer.write(sensitiveData);
    writer.close();
} catch (Exception e) {
    e.printStackTrace();
}
```

### Remediation

```java
// Prevent insertion of sensitive information into log file
public static void logMessage(String message) {
    // Remove any sensitive information from the message
    message = message.replaceAll("(^|\\W)(password|credit card|ssn)(\\W|$)", "***");
    
    // Log the sanitized message
    logger.info(message);
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects insertion of sensitive information into log file"
    author = "Your Name"
    date = "2020-07-01"
  strings:
    $log_entry = /.*/
    $sensitive_data = /(password|credit card|social security number|account number|health record)/
  condition:
    $log_entry contains $sensitive_data
}
```

### CodeQL Rule

```ql
import java

class InsertionOfSensitiveInformationIntoLogFile extends SecurityCodeRule {
 
  InsertionOfSensitiveInformationIntoLogFile() {
    super("InsertionOfSensitiveInformationIntoLogFile");
  }
 
  @Override
  public RuleMatch[] match(Trace trace) {
    List<RuleMatch> matches = new ArrayList<>();
 
    // Check for code that writes sensitive information to a log file
    Collection<MethodCall> calls = trace.getNodes(MethodCall.class);
    for (MethodCall call : calls) {
        // Check for calls to logging methods
        if (call.getTarget().matches("java.util.logging.Logger.log*") ||
            call.getTarget().matches("org.slf4j.Logger.log*") ||
            call.
```


# Python

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of security vulnerability that occurs when an attacker injects malicious code into a web application. This malicious code can be a script, HTML, or other types of code that can be executed by the browser. If the code is not filtered or sanitized, it can be used to manipulate the application’s data or steal confidential information from users, such as usernames and passwords. XSS is a particularly dangerous vulnerability because it can be used to launch more complex attacks, such as distributed denial of service (DDoS) attacks, phishing scams, and malware distribution.

### Vulnerable Code

```python
def vulnerable_function(user_input):
    page_content = "<html><body>User input: %s</body></html>" % user_input
    return page_content

# This code is vulnerable to cross-site scripting, if the user_input is not properly sanitized and filtered. 
# For example, if the user input is "<script>alert('XSS')</script>", the output page will contain the malicious script.
```

### Remediation

```python
# Remediation example

def sanitize_input(user_input):
    # Strip any HTML/JavaScript tags
    user_input = re.sub(r'<[^>]*>', '', user_input)
    
    # Escape HTML characters
    user_input = html.escape(user_input)
    
    # Return the sanitized input
    return user_input
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-079-detection",
  patterns: [
    {
      pattern: "{print,echo,printf,sprintf}.*(?P<input>\$_[A-Z_]*\[['\"](.*)['\"]\]|\$_[A-Z_]*\{['\"](.*)['\"]\})",
      message: "Potential Cross-site Scripting detected: input from ${input} may not be properly sanitized before being used in a web page.",
      severity: "WARNING"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe79

class Cwe79CrossSiteScriptingRule extends Rule {
  // Create a query to detect the vulnerability
  query vulnerable_code() {
    // Look for web page generation code
    WebPageGenerationCode webPageGenCode
    where webPageGenCode.containsVulnerableCode()
  }

  // Check for improper neutralization of user input
  predicate containsVulnerableCode() {
    // Look for user input being passed to the web page generation code
    exists(UserInput ui)
    such that ui.isPassedTo(WebPageGenerationCode.allInstances())
    // Check if the input is properly neutralized
    and not cwe79.isNeutralized(ui)
  }
}
```

## CWE-020: Improper Input Validation

### Description

Improper input validation is a vulnerability that occurs when an application does not properly validate user input before passing it to a system or application. This can be exploited by malicious users to inject malicious code or data into the system, leading to security issues such as buffer overflows, cross-site scripting, and SQL injection attacks. Improper input validation can also allow attackers to bypass authentication and authorization checks, allowing them to gain access to sensitive data or perform malicious actions.

### Vulnerable Code

```python
def add_user(username, password):
    # add username and password to database
    query = "INSERT INTO users (username, password) VALUES ('{}', '{}')".format(username, password)
    cursor.execute(query)

# Vulnerable code
query = "INSERT INTO users (username, password) VALUES ('{}', '{}')".format(username, password)
cursor.execute(query)

# Unsanitized input is being used in the query, which can lead to SQL injection attacks.
# Proper input validation should be used to prevent malicious input from being used.
query = "INSERT INTO users (username, password) VALUES (?, ?)"
cursor.execute(query, (username, password))
```

### Remediation

```python
def validate_input(input):
  if not input.isalpha():  # Check if input is alphabetic
    raise ValueError('Input must be alphabetic only')
  return input # If input is valid, return it
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-020-Improper-Input-Validation",
  pattern: "input[*] not in __import__('whitelist')",
  message: "Input validation is not properly enforced.",
  severity: "error"
}
```

### CodeQL Rule

```ql
import cwe

class CWE020ImproperInputValidation:
  // Checks for functions that do not validate user input
  // and adds the input directly to a database query
  // without any sanitization.
 
  @Name("CWE-020: Improper Input Validation")
  @CWE(cwe.CWE_020)
 
  def vulnerable(Function func) {
    // Find all calls to database query functions
    QueryCall queryCall = func.getCallees().select(QueryCall)
 
    // Find all user input variables
    Variable inputVar = queryCall.getArgs().select(Variable).where(isUserInput)
 
    // Check if the user input is not sanitized
    Sanitize sanitize = queryCall.getCallees().select(Sanitize).where(sanitize.getInput()
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of security vulnerability that occurs when an attacker is able to inject malicious commands into an operating system (OS) command. These malicious commands can be used to modify, delete or even execute files on the target system. This type of attack is easy to carry out, as it requires only an injection of a single command into an application. The vulnerability is enabled when user inputs are not properly sanitized, allowing malicious code to be executed on the system.

### Vulnerable Code

```python
import os

#Vulnerable code
user_input = input("Enter a command: ")
os.system(user_input)
```

### Remediation

```python
import subprocess

def execute_command(cmd):
    # We create an array with the command and its parameters
    command = cmd.split()
    # We use subprocess.call to execute the command
    subprocess.call(command)

# We call execute_command to execute a command
execute_command("ls -l")
```

### Semgrep Rule

```yaml
rule = {
	id: "CWE-078-OS-Command-Injection",
	pattern: {
		anyWith: {
			code: /system\(|exec\(|popen\(|shell_exec\(|`/
			all: [
				{
					// Verify that the command is not hardcoded
					not: {
						code: /"|'/,
						anyWith: {
							code: /system\(|exec\(|popen\(|shell_exec\(|`/
						}
					}
				},
				{
					// Verify that user input is not directly passed to
```

### CodeQL Rule

```ql
import cwe
import os

class OsCommandInjection(cwe.Vulnerability):
    def __init__(self):
        self.id = 78
        self.severity = "High"
        self.title = "Improper Neutralization of Special Elements used in an OS Command"
        self.description = "The application fails to properly neutralize special elements used in an OS command, allowing attackers to execute arbitrary code."
 
    def getVulnerabilityName(self):
        return self.title
 
    def getVulnerabilityId(self):
        return self.id
 
    def getSeverity(self):
        return self.severity
 
    def detect(self, qctx):
        # search for call to "os.system" without proper sanitization
        qctx.for_stmt("$cmd", """
            ExprSt
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

SQL injection is a type of security vulnerability that occurs when malicious code is inserted into an SQL query through user input. This can allow attackers to gain access to restricted databases, modify or delete data, or even execute system commands. Attackers can use this vulnerability to gain unauthorized access to sensitive data or execute malicious code on the server.

### Vulnerable Code

```python
import sqlite3

# Variable user_input is obtained from the user
user_input = "admin'"

# Establish a connection to the SQLite database
connection = sqlite3.connect("database.db")

# Create a cursor object
cursor = connection.cursor()

# Execute the SQL query
cursor.execute("SELECT username FROM users WHERE username = '" + user_input + "'")

# Fetch the results of the query
results = cursor.fetchall()

# Close the connection
connection.close()

# Print the results
print(results)
```

### Remediation

```python
# Remediation code example

# Sanitize user input to prevent SQL injection
def sanitize_inputs(user_input):
    # Strip all special characters
    input_sanitized = re.sub('[^\w]', '', user_input)
    
    # Escape all apostrophes
    input_sanitized = input_sanitized.replace("'", "''")
    
    return input_sanitized

# Use sanitized user input in SQL query
sql_query = "SELECT * FROM users WHERE username = '{}'".format(sanitize_inputs(user_input))

# Execute query
cursor.execute(sql_query)
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects SQL injection vulnerabilities"
    id = "CWE-089"
    severity = "CRITICAL"
  strings:
    $sql = /.*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXECUTE).*/ 
    $special = /.*('|"|;|\||--|#|%|&|\*|\+|=|\\).*/
  condition:
    any of them
}
```

### CodeQL Rule

```ql
import python

class SqlInjectionVulnerability(Vulnerability):
    def __init__(self):
        super().__init__()
        
    def vulnerable_function(self, func):
        return func.has_name("execute") and func.has_return_type(python.VoidType)
    
    def predicate(self, q):
        vulnerable_functions = select(f for f in python.Functions if self.vulnerable_function(f))
        vulnerable_calls = select(c for c in python.Calls if c.get_function().in(vulnerable_functions))
        return exists(vulnerable_calls, lambda c: c.has_argument_with_string_literal_contains_sql_keyword(q))

rule SqlInjectionVulnerability
    when SqlInjectionVulnerability()
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal is a type of vulnerability that occurs when an attacker can gain access to files and directories that are stored outside the intended directory. This can happen when a web application allows user-supplied input, such as a file name or a directory, to be used without proper validation. If the application does not properly validate the user-supplied input, the attacker may be able to traverse the file system to access files and directories that are outside of the intended directory. This can lead to unauthorized access to sensitive information or even system compromise.

### Vulnerable Code

```python
# This code is vulnerable to CWE-022

file_name = request.GET('file_name')

# Open the file
with open(file_name, 'r') as f:
    # Read the contents of the file
    contents = f.read()
```

### Remediation

```python
# Before
filename = request.form.get('filename')
f = open(filename, 'r')

# After
filename = os.path.basename(request.form.get('filename'))
f = open(os.path.join(allowed_directory, filename), 'r')
```

### Semgrep Rule

```yaml
rules:
  - id: PATH_TRAVERSAL
    severity: critical
    patterns:
    - pattern: 'open(.*?[\\/][.][.][\\/])'
      message: 'Possible Path Traversal vulnerability detected'
    filters:
    - 'open'
```

### CodeQL Rule

```ql
import cwe

class PathTraversalVulnerability(cwe.Vulnerability):
    def __init__(self):
        self.id = "CWE-022"
        self.name = "Path Traversal Vulnerability"
        self.description = "Improper limitation of a pathname to a restricted directory allows attackers to gain access to resources that should not be publicly available."
        self.severity = cwe.Severity.HIGH
        self.cwe_id = "CWE-022"
        self.references = ["https://cwe.mitre.org/data/definitions/22.html"]
        
    def check(self, qg):
        # Look for cases where a user-controlled input is used as a pathname
        return qg.query("""
            // Check for user-controlled input
            let user_controlled
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-Site Request Forgery (CSRF) is a type of attack in which an attacker tricks a user into performing unwanted actions on a web application in which the user is currently authenticated. The attacker does this by sending a malicious request from a trusted website or application to the vulnerable web application. This malicious request will appear to the web application as if it originated from the user's own browser, and the web application will process the request as if it were a legitimate request. This can result in the attacker gaining access to sensitive data or the ability to perform unauthorized actions on the vulnerable web application.

### Vulnerable Code

```python
import flask

app = flask.Flask(__name__)

@app.route('/update_user', methods=['POST'])
def update_user():
    # get data from form
    user_data = flask.request.form
    
    # update user_data in database
    db.update_user(user_data)
    return 'User data updated!'

The above code is vulnerable to a CSRF attack, as it does not have any sort of CSRF token verification, or any sort of user authentication. An attacker could send a malicious POST request to the '/update_user' route, and update data in the database without the user's knowledge.
```

### Remediation

```python
# Create a CSRF token
def generate_csrf_token():
    csrf_token = uuid.uuid4().hex
    session['csrf_token'] = csrf_token
    return csrf_token

# Check if the csrf token is valid
def csrf_protection(request):
    token = session.get('csrf_token')
    if not token or token != request.form.get('csrf_token'):
        abort(403)
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-352-Detection",
  patterns: [
    {
      pattern: "http.request(param: *, method: 'POST')",
      message: "Potential Cross-Site Request Forgery (CSRF) vulnerability detected"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe352

from BaseNode import *
from HTTPRequest import *

class CWE352CrossSiteRequestForgeryRule(Rule):
    def __init__(self):
        Rule.__init__(self, name="CWE352CrossSiteRequestForgeryRule",
        target=HTTPRequest,
        severity="CRITICAL")
    
    def evaluate(self, target):
        if (target.method == "POST"):
            if not target.has_csrf_protection():
                return Report(cwe=cwe352.id,
                confidence="HIGH")
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a type of vulnerability that allows an attacker to upload files of a dangerous type onto a web application without any restrictions. This can lead to malicious code being executed on the server, which can cause data leakage, system access, or even more serious damage. The dangerous types of files can include .exe, .bat, .php, .js, and other files that can be used to execute malicious code. This vulnerability can be exploited by an attacker if the application does not have proper file type restrictions in place.

### Vulnerable Code

```python
# The following code allows a user to upload any type of file to the server

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('uploaded_file',
                                filename=filename))

# The code does not check the type of file being uploaded, allowing users to upload malicious files.
```

### Remediation

```python
# Sanitizing File Uploads

def sanitize_file_upload(file):
  # Get the file type
  file_type = file.content_type
  
  # List of allowed file types
  allowed_file_types = [
    'image/jpeg',
    'image/png',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]
  
  # If the file type is not allowed, reject the file
  if file_type not in allowed_file_types:
    raise Exception('Unallowed file type')
  
  # Return the sanitized file
  return file
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-434-unrestricted-upload-file-dangerous-type",
  patterns: [
    {
      pattern: "file_name = request.files.get(file_parameter)",
      qualifiers: ["+"]
    },
    {
      pattern: "file_name.filename",
      qualifiers: ["+"]
    },
    {
      pattern: "file_name.save(file_path)",
      qualifiers: ["+"]
    }
  ],
  message: "Possible unrestricted upload of file with dangerous type detected."
}
```

### CodeQL Rule

```ql
import cwe
import python

class UnrestrictedUploadofDangerousType(python.PythonRule):
  def __init__(self):
    super().__init__()
    self.id = "CWE-434"
    self.vuln_id = cwe.CWE434
    self.severity = "high"
    self.description = "Unrestricted upload of file with dangerous type"

  def getQuery(self):
    return """
      from FileUpload upload, FilePermission perm, Call call, 
      Function func, File filename
      where upload.filePermission = perm 
      and upload.call = call
      and call.callee = func
      and perm.filename = filename
      and filename.extension in {"php", "asp", "cgi"}
      and upload.isSink
      select upload, "Un
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306: Missing Authentication for Critical Function is a vulnerability that occurs when an application fails to properly authenticate a user before allowing them to access a critical function. This can allow attackers to gain unauthorized access to sensitive data or perform certain actions that they would not normally have access to. Without proper authentication, malicious users could potentially bypass security controls and gain access to sensitive resources or perform actions that are not authorized.

### Vulnerable Code

```python
def update_profile_info(user, info):
    # code to update user profile information
    # ...
    user.profile.update(info)
    user.save()

# Vulnerable code - No authentication
update_profile_info(user, info)
```

### Remediation

```python
# Example code

# Sanitize user input
def secure_input(user_input):
    return re.sub(r'[^a-zA-Z0-9]', '', user_input)

# Enforce authentication
def authenticate_user(user_input):
    # Check if user is authenticated
    if secure_input(user_input) == ‘authenticated’:
        return True
    else:
        return False

# Function that requires authentication
def critical_function(user_input):
    # Check if user is authenticated
    if authenticate_user(user_input):
        # Execute critical function
        # ...
        return
    else:
        # Require authentication
        print('You must authenticate first!')
        return
```

### Semgrep Rule

```yaml
rule = [{
  "id": "CWE-306",
  "severity": "error",
  "message": "Critical function is missing authentication",
  "patterns": [
    {
      "regexp": "^(?!.*(auth|authenticate)).*critical_function.*$"
    }
  ]
}]
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.dataflow

class MissingAuthForCriticalFunction extends SecurityHardeningChecker {
  // Check if the program calls a critical function without authentication
  predicate isCriticalFunction(Function f) {
    // Insert code here to determine if f is a critical function
  }
  
  @Override
  check(CallExpr call) {
    if (call.getTarget().matches(isCriticalFunction) &&
       !call.hasArgument(isAuthenticationCheck)) {
      // Report the vulnerability
      reportCWE(call, cwe.Missing_Authentication_for_Critical_Function);
    }
  }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability related to deserialization of untrusted data. This vulnerability occurs when a program deserializes data from an untrusted source without proper validation, allowing attackers to execute malicious code within the system. This can be exploited to gain access to confidential data or to cause a denial of service. It is important to properly validate all data before deserializing it, as deserialization can lead to serious security vulnerabilities.

### Vulnerable Code

```python
import pickle

# Deserializing untrusted data
untrusted_data = b"cos\nsystem\n(S'echo hello world'\ntR."
result = pickle.loads(untrusted_data)

# This code will execute the command 'echo hello world'
# which can lead to unintended consequences such as
# executing malicious code or accessing sensitive data.
```

### Remediation

```python
# Before
import pickle

user_data = pickle.loads(data)

# After
import pickle
import json

user_data = json.loads(data)
```

### Semgrep Rule

```yaml
rule = {
  id: "deserialization-of-untrusted-data",
  patterns: [
    {
      pattern: "{function_name}(.*, pickle.loads(.*)",
      message: "Deserialization of untrusted data is vulnerable to attack.",
      metadata: {
        description: "Deserialization of untrusted data can lead to remote code execution.",
        cwe: 502
      }
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe502

class CWE502Detector:
  def __init__(self):
    self.vulnerable_methods = ["pickle.loads"]
  
  def onCall(self, call, ctx):
    if call.getTarget().matches(self.vulnerable_methods):
      ctx.report(call.getSourceLocation(), "Vulnerable call to '" + str(call.getTarget()) + "' detected.")

cwe502.addDetector(CWE502Detector())
```

## CWE-287: Improper Authentication

### Description

CWE-287 is a type of security vulnerability that occurs when an application or system does not properly authenticate users. This means that the authentication process does not properly verify the identity of the user or does not provide sufficient protection against unauthorized access. This vulnerability can be exploited by attackers to gain access to sensitive data or to perform malicious activities. To prevent this vulnerability, authentication processes should be designed to verify the identity of the user and provide strong protection against unauthorized access.

### Vulnerable Code

```python
# This code is vulnerable to improper authentication

username = input("Please enter your username: ")
password = input("Please enter your password: ")

if username == 'admin' and password == 'password':
    print("Login successful")
else:
    print("Login failed")
```

### Remediation

```python
# Remediation Example

# 1) Ensure user authentication is properly implemented

# Create a secure login process that requires a unique user ID and password
# Store user passwords using strong encryption methods
# Use multi-factor authentication whenever possible
# Enforce a password policy that includes a minimum length, complexity, and expiration
# Require users to change their passwords regularly
# Implement a lockout policy after a certain number of unsuccessful login attempts
# Monitor user authentication attempts and log any suspicious activity
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-287-Improper-Authentication",
  patterns: [
    pattern: "if (.*?== *?null)",
    message: "Improper Authentication detected",
    severity: "warning"
  ],
}
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthentication_CWE287:
    def predicate(self, ctx):
        return cwe287.hasImproperAuthentication(ctx)

class VulnerableFunction:
    def predicate(self, ctx):
        return ( ctx.get_caller() as Function ).has_vulnerability(ImproperAuthentication_CWE287)
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability in which hard-coded credentials are used in software applications. This type of vulnerability allows attackers to gain access to sensitive information or system resources by using a password or other authentication information which is stored directly in the application's code. This type of vulnerability is especially dangerous because the credentials are stored in plaintext, making them easily accessible to attackers. Additionally, these credentials are not updated or changed regularly, making them even more vulnerable to attack.

### Vulnerable Code

```python
username = "admin"
password = "admin123"

if (username == "admin" and password == "admin123"):
    print("Login successful")
else:
    print("Login failed")
```

### Remediation

```python
# Remediation:

# Store credentials in a secure configuration file
# Ensure that the configuration file is not accessible to the public
# Use environment variables to store credentials
# Generate random passwords for each user
# Use a password manager to store and manage credentials
# Utilize multi-factor authentication whenever possible
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-798-detection",
  pattern: "username=\"*\" password=\"*\"",
  message: "Possible use of hard-coded credentials detected!",
  severity: "WARNING"
}
```

### CodeQL Rule

```ql
import cwe
import python

class HardCodedCredentialsVuln(python.PythonQuery):
    def __init__(self):
        super().__init__()

    def after_query(self):
        for literal in python.Literal:
            if literal.is_string() and self.is_credential(literal) and literal.is_hardcoded():
                self.report(literal, "Hard-coded credentials detected")
    
    def is_credential(self, literal):
        return "password" in literal.value or "username" in literal.value
```
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 (Incorrect Default Permissions) is a vulnerability that occurs when software is installed with insecure default permissions that allow non-privileged users to access sensitive information or perform privileged actions. These insecure default permissions can allow attackers to gain access to sensitive data, gain elevated privileges, or cause denial-of-service attacks. In a Python environment, this vulnerability can be introduced when developers do not configure secure default permissions on files and folders during installation. For example, if a folder containing sensitive data is installed with world-readable permissions, then any user on the system would be able to access the sensitive data.

### Vulnerable Code

```python
f = open("myfile.txt", "w") 
f.write("This is some sensitive data") 
f.close() 

# This code creates a file with default permissions (which is usually read and write for the owner) that can be accessed by anyone.
```

### Remediation

```python
Create a script to set secure default permissions on files and directories. For example, the script could set permissions on newly created files and directories to read and write for the owner, and read for the group and others. The script could be run on a regular basis to ensure that all files and directories have the correct default permissions.
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-276-incorrect-default-permissions",
  strings: {
    // match any file permissions that give owner, group, and everyone else full access
    // e.g. chmod 777 file.txt
    $set_permissions = /chmod\s+777\s+\S+/,
  },
  condition: allof($set_permissions)
}
```

### CodeQL Rule

```ql
import cwe276
from AccessControl import FileAccess

class CWE_276_Incorrect_Default_Permissions:
    def __init__(self):
        self.vuln_name = "CWE-276: Incorrect Default Permissions"
        self.severity = "High"
    
    def get_vuln_name(self):
        return self.vuln_name

    def get_severity(self):
        return self.severity

    def query(self):
        return cwe276.Query.select(f)
        .where(f.kind == FileAccess.File)
        .and(f.permissions != FileAccess.Public)
        .and(f.permissions != FileAccess.Private)
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that occurs when sensitive information is exposed to an unauthorized actor. This can occur when data is improperly stored, transmitted, or accessed, leading to a breach of security. This type of vulnerability can lead to the exposure of information such as passwords, usernames, financial data, or other sensitive information. An attacker may be able to exploit this vulnerability to gain access to various systems and resources, or to access sensitive information.

### Vulnerable Code

```python
# This code reads a file containing sensitive information and prints it to the console

with open('sensitive_data.txt', 'r') as f:
    data = f.readlines()
    print(data)
```

### Remediation

```python
One way to remediate CWE-200 would be to ensure that all sensitive information is encrypted when stored or transmitted across a network. For example, when an application needs to store sensitive information in a database, it can use encryption algorithms to encrypt the data before sending it to the database. Additionally, when the application needs to transmit sensitive information over a network, it can use secure protocols such as TLS or SSH to protect the data in transit.
```

### Semgrep Rule

```yaml
# CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
rules:
- id: CWE-200
  patterns:
  - pattern: |
      (data|information|credentials|secrets)[^\n]*(stored|saved|transmitted|shared|exposed)[^\n]*(publicly|without encryption|without authentication|without authorization|without permission)
    message: "Potential exposure of sensitive information to an unauthorized actor"
    severity: critical
```

### CodeQL Rule

```ql
import python

class CWE200ExposureOfSensitiveInformationRule extends Rule {
    // Context related to the vulnerability
    // ...
    
    // Helper methods
    // ...
    
    // Entry point of the rule
    // ...
    @Query
    def getVulnerableUsage(): Query {
        // Return the nodes in the program that can lead to the vulnerability
        // ...
    }
    
    // Method to verify if the program actually contains the vulnerability
    // ...
    @Query
    def isVulnerable(Node node): Boolean {
        // Check if the node can lead to the vulnerability
        // ...
    }
}
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a vulnerability that occurs when credentials such as usernames and passwords are not sufficiently protected. This means that the credentials may be stored in plain text, or encrypted in a weak or easily broken manner. This can lead to a breach of security, as malicious actors can gain access to sensitive data. Attackers may also be able to gain privileges to systems and networks by using the leaked credentials.

### Vulnerable Code

```python
# This code will store the user's login credentials in plaintext
username = input("Please enter your username: ")
password = input("Please enter your password: ")

credentials = username + ":" + password

# Store the credentials in a file
with open('credentials.txt', 'w') as f:
    f.write(credentials)
```

### Remediation

```python
# Before:
username = 'admin'
password = 'admin123'

# After:
import bcrypt

# Generate a salt
salt = bcrypt.gensalt()

# Hash the password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

# Store the username and hashed password
username = 'admin'
password = hashed_password
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-522-insufficiently-protected-credentials",
    patterns: [
        {
            pattern: "{string} == {string}",
            message: "Potential credentials stored in plaintext. Consider encrypting or hashing the credentials.",
            severity: "WARNING"
        }
    ]
}
```

### CodeQL Rule

```ql
import cpp
import semmle.code.cpp.dataflow

class InsufficientlyProtectedCredentialsRule extends SecurityHardeningChecker {
  Credential getCredential(DataFlow::Node source) {
    switch source.kind {
      // Check for credential sources
      case DataFlow::Node::Kind::StringLiteral: 
        return source.asStringLiteral.credential
      case DataFlow::Node::Kind::IntegerLiteral:
        return source.asIntegerLiteral.credential
      case DataFlow::Node::Kind::FuncCall:
        return source.asFuncCall.credential
      // ... more cases
      default:
        return none
    }
  }

  // Check for insecure storage of credentials
  // For example, hard-coded credentials
  @Override
  predicate is
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a type of XML injection vulnerability that occurs when an application references an external XML entity in its XML processing, allowing an attacker to modify or access sensitive files or data. This vulnerability can be exploited to access local files, execute malicious code, or create a denial of service attack. This vulnerability can be caused by insufficient input validation, incorrect use of XML parsers, or code that references external entities without verifying their contents.

### Vulnerable Code

```python
import xml.etree.ElementTree as ET

# Load XML file
tree = ET.parse('test.xml')
root = tree.getroot()

# Get XML element
vulnerable_element = root.find('vulnerable_element')

# Get value from vulnerable element
value = vulnerable_element.text

# Use external entity reference
value = vulnerable_element.text + "&external_entity;"
```

### Remediation

```python
One way to remediate CWE-611 is to ensure that any XML parsing is done using a secure parser. This means that all external entities must be explicitly disabled to prevent malicious content from being parsed.

For example, if using the Python xml.etree.ElementTree library, the following code can be used to disable external entities:

import xml.etree.ElementTree as ET

# Parse the XML with external entities disabled
ET.parse("myfile.xml", parser=ET.XMLParser(resolve_entities=False))
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects XML External Entity Reference vulnerability"
  patterns:
    - pattern: '<!ENTITY(\s+)(?P<entity_name>\w+)(\s+)(?P<entity_value>.*?)>(?P<rest>.*)'
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
    message: "XML External Entity Reference vulnerability detected"
    severity: "CRITICAL"
}
```

### CodeQL Rule

```ql
import cpp
import semmle.codeql.dataflow.dataflow_types

class XMLExternalEntityReferenceVulnerability(Query):
    def vulnerable_code(c):
        cpp.CallExpr.select(
          lambda call: call.getFunction().getName() == "parseXML" and
            call.hasArg(0) and
            call.getArg(0).getType().isSubtypeOf(semmle.codeql.dataflow.dataflow_types.XML_INPUT)
        )
    
    def query(c):
        vulnerable_code = vulnerable_code(c)
        return vulnerable_code.withFalse(
            vulnerable_code.getArg(0).hasProperty("externalEntitiesAllowed")
        )
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-Side Request Forgery (SSRF) is a type of web application vulnerability which allows an attacker to send malicious requests from a vulnerable web application to an internal system. This type of attack can be used to access sensitive data from internal systems, gain remote code execution, and more. SSRF vulnerabilities can be exploited in a wide variety of ways, including probing for open ports, redirecting to malicious sites, or even exploiting internal services that are vulnerable to attack.

### Vulnerable Code

```python
import requests 

url = input("Enter the URL to make a request to: ")

response = requests.get(url)
html = response.text

print(html)
```

### Remediation

```python
# Replace any user-supplied URL values with a whitelisted list of approved URLs

approved_urls = ["https://www.example.com/", "https://www.example2.com/"]

def validate_url(url):
    if url not in approved_urls:
        raise ValueError("URL is not whitelisted")
    else:
        return url

# Use the validate_url() function when handling requests with user-supplied URLs

def handle_request(request):
    if 'url' in request.data:
        user_url = request.data['url']
        validated_url = validate_url(user_url)
        # Continue with request handling
        ...
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-918-ssrf-detection",
  description: "Detects Server-Side Request Forgery (SSRF) attempts",
  author: "Your name here",
  references: ["https://cwe.mitre.org/data/definitions/918.html"],
  tags: ["security", "cwe", "ssrf"],
  detection: {
    name: "ssrf-detection",
    code: {
      pattern: "http.request(.*)",
      message: "Server-Side Request Forgery (SSRF) vulnerability detected",
    }
  }
}
```

### CodeQL Rule

```ql
import cwe918

class CWE918Rule extends Rule {
  // Check requests for suspicious URLs
  // that could be used for SSRF
  //
  // Example of suspicious URLs:
  // - Localhost
  // - Internal IP addresses
  // - File paths
 
  // Find all requests
  Query RequestMethods = MethodInvocation 
  and getName() in {"get", "post", "delete", "put", "patch"}

  // Find all suspicious URLs
  Query SuspiciousURLs = 
  RegexReplaceExpr
  and getRegex() = "^localhost$|^127\.0\..*$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^file:.*$"

  // Find all requests with suspicious
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of vulnerability that allows an attacker to execute arbitrary commands on a system by injecting malicious code into a vulnerable program. This type of attack is especially dangerous as it can be used to gain access to sensitive data, modify system configurations, and even launch additional attacks on other systems. Command injection can occur when user input is not properly sanitized before being passed to a system command. Without proper sanitization, attackers can use special characters to inject malicious code into the vulnerable program, which can then be executed by the system.

### Vulnerable Code

```python
import subprocess 

def execute_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.communicate()[0]

# Vulnerable code
user_input = input("Enter a command: ")
output = execute_command(user_input)
print(output)
```

### Remediation

```python
# Before remediation
query_string = input("Enter your query: ")
query_result = execute_query(query_string)

# After remediation
query_string = input("Enter your query: ")
sanitized_query_string = sanitize_input(query_string)
query_result = execute_query(sanitized_query_string)
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-077-detection",
  patterns: [
    {
      pattern: "{string_literal, identifier} / {string_literal, identifier}",
      message: "Potential command injection vulnerability detected",
      severity: "WARNING"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe077

class CWE077CommandInjectionRule extends Rule {
    // Rule body
   
    // Finds calls to system() or exec()
    // that do not sanitize user input
    // before inserting it into the command
    @Cwe077
    def vulnerable_system_exec_calls(call : Call) : QueryNode[Call] {
        call.getTarget().name("system") or call.getTarget().name("exec")
    }
    
    // Finds calls to system() or exec()
    // that contain user input
    @Cwe077
    def system_exec_with_user_input(call : Call) : QueryNode[Call] {
        vulnerable_system_exec_calls(call)
            .hasAnArgument("user_input")
    }
    
    // Checks
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295 is a vulnerability that occurs when an application fails to properly validate a digital certificate before accepting it. This can lead to a variety of security issues, including the potential for attackers to use forged or expired certificates to gain access to resources or data that should be otherwise restricted. This vulnerability can be especially dangerous when used in conjunction with other attack vectors, such as man-in-the-middle attacks.

### Vulnerable Code

```python
import ssl

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket in an SSL context
context = ssl.SSLContext()

# Connect the socket to the remote server
sock.connect(('www.example.com', 443))

# Perform certificate validation
# This is the vulnerable line
context.verify_mode = ssl.CERT_NONE

# Send data
sock.sendall(b'Hello, world')

# Receive response
response = sock.recv(1024)
```

### Remediation

```python
# Remediating CWE-295: Improper Certificate Validation

def verify_ssl_certificate(server_cert, root_cert):
    """Verifies the server certificate against the root certificate."""
    try:
        if root_cert.verify(server_cert) is not True:
            raise Exception('Server certificate verification failed.')
    except Exception as e:
        print(e)
        return False
    return True
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-295-Improper-Certificate-Validation", 
    patterns: [
        {
            pattern: 'ssl.verify_mode == ssl.CERT_NONE',
            message: 'Improper Certificate Validation detected'
        },
        {
            pattern: 'ssl.verify_mode == ssl.CERT_OPTIONAL',
            message: 'Improper Certificate Validation detected'
        }
    ]
}
```

### CodeQL Rule

```ql
import cwe
import python

// CWE-295: Improper Certificate Validation

class ImproperCertificateValidation extends PythonQuery {
    // Query for verifying the validity of certificates
    def query_for_verifying_certificates() {
        // Find the method which verifies the validity of certificates
        MethodCall.find(
            'ssl.match_hostname',
        )
    }
    
    // Query for not verifying the validity of certificates
    def query_for_not_verifying_certificates() {
        // Find the method which does not verify the validity of certificates
        MethodCall.find(
            'ssl.verify_mode',
            'ssl.CERT_NONE'
        )
    }

    // Rule for improper certificate validation
    rule isVulnerableToImproperCertificateValidation {
        // Check if
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability where the application generates code without proper validation or sanitization, allowing an attacker to inject malicious code into the application. This can be done through user input, such as when a user is allowed to submit code as part of a form or through a file upload. If the application fails to properly validate and sanitize the user input, the attacker can execute malicious code on the system. This can result in the attacker gaining access to sensitive data, manipulating data within the application, or even executing malicious code on the server.

### Vulnerable Code

```python
def malicious_function(data):
  # data is passed from the user
  code = data + 'print("Hello World!")'
  exec(code)

malicious_function(input("Enter some code: "))
```

### Remediation

```python
Remediation for CWE-094 can be achieved by using input validation methods. This involves checking user input for malicious content and encoding it, if necessary. Below is an example of a function that uses input validation to prevent code injection:

def validate_input(input):
    # Remove all non-alphanumeric characters
    input = re.sub(r'[^a-zA-Z0-9 ]', '', input)
    
    # Encode the input
    input = html.escape(input)
    
    return input
```

### Semgrep Rule

```yaml
rules:
  - id: cwe-094
    severity: critical
    message: "Detected code injection vulnerability"
    patterns: 
      - pattern: 'eval(${parameter})'
        message: "Detected code injection vulnerability"
        targets:
          - "**/*.py"
```

### CodeQL Rule

```ql
import cpp
import semmle.codeql.dataflow.dataflow

class CWE094CodeInjection extends SecurityTest {
  // Look for a call to the system() or exec() function
  predicate isSystemCall(Expr call) {
    exists(Call c | c.getTarget() = call and c.getKind() in {"CXXMemberCall", "CXXOperatorCall"} and c.getDecl().getName() in {"system", "exec"})
  }

  // Find assignments of user-controlled data to system calls
  @EntryPoint
  @DontReport
  predicate isUserControlledAssignment(Expr lhs, Expr rhs) {
    decl lhsDecl := lhs.getDecl()
    lhsDecl != null and
    lhsDecl.getName() in {"__builtin_va_arg", "
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 is a vulnerability related to improper privilege management. This means that an application or system may be configured in a way that allows a user to access resources or functions they should not be able to access. This can occur when a user is given access to a system or application with more privileges than necessary, or when an application or system is not configured to restrict access to certain resources. In the case of Python applications, this vulnerability can occur when the software is not configured to properly check user authorization or authentication before allowing access to restricted resources.

### Vulnerable Code

```python
def get_admin_access():
  username = input("Please enter your username: ")
  password = input("Please enter your password: ")
  if username == "admin" and password == "password":
    return True
  else:
    return False
  

# This code grants access to the "admin" user without any additional authentication or authorization checks. This could allow any user to gain admin access without the proper credentials.
```

### Remediation

```python
# Remediate CWE-269 - Improper Privilege Management

# Ensure that only authorized users have the necessary privileges to perform any given task
def restrict_privileges():
    # Retrieve the list of current users
    users = get_users()
    
    # Remove all unnecessary privileges from each user
    for user in users:
        remove_privileges(user)
    
    # Create a list of authorized users
    authorized_users = get_authorized_users()
    
    # Grant only the necessary privileges to each authorized user
    for user in authorized_users:
        grant_privileges(user)
```

### Semgrep Rule

```yaml
rule = "

// CWE-269: Improper Privilege Management

import "strings"

@violation[severity = "critical"]
def cwe_269_improper_privilege_management() {
    // Look for code that attempts to grant privileges to a user 
    // without ensuring the user has the appropriate permissions 
    // or credentials to do so

    // Look for functions that grant privileges, such as 
    // setuid, setgid, seteuid, etc.
    setuid, setgid, seteuid, setegid, initgroups
    = "strings.RegexMatch"
   
    // Look for functions that grant privileges, such as 
    // setcap, setresuid, setresgid, etc.
    setcap, setresuid, setresgid
    = "strings.RegexMatch"
```

### CodeQL Rule

```ql
import cwe269

class ImproperPrivilegeManagement(cwe269.Vulnerability):
  def predicate(self, qctx):
    return (
      qctx.select("privilege", "p", 
        qctx.call("os", "geteuid"))
      .where(lambda p: p.has_privilege() and
        p.privilege_is_not_acquired_properly())
    )
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917, also known as Expression Language Injection, is a vulnerability that occurs when an attacker is able to inject malicious code into an expression language statement. Expression language statements are commonly used in web applications to evaluate and manipulate data. Attackers can leverage this vulnerability to gain access to sensitive data, execute arbitrary code, or even modify application logic. This vulnerability can be exploited when an application does not properly neutralize user input, allowing attackers to inject malicious code into the statement. This can lead to a variety of security issues and potentially result in data loss or system compromise.

### Vulnerable Code

```python
def get_greeting(name):
    return f"Hello, {name}!"

user_name = request.args.get('name')
return get_greeting(user_name)

The code above is vulnerable to expression language injection because it fails to properly neutralize user input. A malicious user could enter an expression language statement as their name, which could be evaluated by the application and potentially lead to an injection attack. For example, a user could enter the string "${system.exit()}" as their name, which would terminate the application.
```

### Remediation

```python
# Before
user_input = request.args['user_input']
query = "SELECT * FROM users WHERE name='" + user_input + "'"

# After
from sqlalchemy.sql import text
user_input = request.args['user_input']
query = text("SELECT * FROM users WHERE name=:user_input").bindparams(user_input=user_input)
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-917",
  patterns: [
    {
      pattern: '(?P<expression>.*)(?P<injection>\$\{.*\})',
      message: "Expression language injection detected at {{file}}:{{line}}:{{column}}",
      severity: "CRITICAL"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe

class CWE917ExpressionLanguageInjection:
 
  //Checks for the presence of expression language injection
  //vulnerabilities in code
 
  @Override
  predicate check() {
    //Check for the presence of expression language injection:
    Expr.all(e | 
		e.isa(EvalExpr) and
		e.getArgument().getText().contains("EL")
    )
  }
  
  //Returns the CWE for expression language injection
  @Override
  vulnerable_pattern() {
    cwe.CWE917
  }

}
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a type of security vulnerability that occurs when a program follows a link or reference to a file without properly validating the target of the link. This type of vulnerability can lead to security issues such as directory traversal and/or privilege escalation, as an attacker may be able to manipulate the link and access other files or directories without the proper security validation.

### Vulnerable Code

```python
import os

filename = input("Enter a filename: ")

# Incorrectly assume that filename is a relative path
file_path = os.path.join(os.getcwd(), filename)

# Try to open the file
with open(file_path) as f:
    contents = f.read()

print(contents)
```

### Remediation

```python
# Remediate CWE-059

def secure_file_access(filepath):
    
    # Check if the path is absolute
    if not os.path.isabs(filepath):
        # Create an absolute path using os.path.abspath()
        abs_filepath = os.path.abspath(filepath)
    else:
        # Use the absolute path provided
        abs_filepath = filepath
    
    # Check if the path is valid
    if not os.path.exists(abs_filepath):
        raise FileNotFoundError
    
    # Check if the file is inside the current directory
    if not os.path.dirname(abs_filepath).startswith(os.getcwd()):
        raise PermissionError
    
    # If all checks pass, return the absolute filepath
```

### Semgrep Rule

```yaml
# CWE-059: Improper Link Resolution Before File Access ('Link Following')
rule = {
    meta:
      cwe = "CWE-059"
    strings:
      $func1 = /open(?:at)?/
      $func2 = /readlink/
    condition:
      $func1 and $func2
}
```

### CodeQL Rule

```ql
import cwe
import python

class ImproperLinkResolutionBeforeFileAccessRule extends Rule {
 
  // Rule meta data
  meta.ruleName = "Improper Link Resolution Before File Access"
  meta.cwe = cwe.CWE_059
  
  // Rule class body
 
  // Find all function calls
  def callExpr = Expr.call
  
  // Find all functions that have access to the filesystem
  def vulnerableFunc = callExpr.hasTarget(
    PythonFunction("open")
    or PythonFunction("os.open")
    or PythonFunction("os.openpyxl")
    or PythonFunction("os.path.exists")
    or PythonFunction("os.path.isfile")
    or PythonFunction("os.path.isdir")
    or PythonFunction("pickle.load")
    or
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability where sensitive information is transmitted in plaintext. This means that the data is not encrypted and can be easily read by anyone with access to the transmission. This is a major security risk as attackers can easily intercept and read the information being sent, which can be used to gain access to private accounts, sensitive data, or confidential information. It is important to ensure that any sensitive information is encrypted before it is transmitted to ensure its security.

### Vulnerable Code

```python
# This code sends a username and password over an unencrypted connection
import requests

username = "admin"
password = "mypassword"

# Unencrypted connection
r = requests.post("http://example.com/api/login", data={'username': username, 'password': password})
```

### Remediation

```python
# Remediation for CWE-319: Cleartext Transmission of Sensitive Information

#1: Encrypt Sensitive Data
To prevent cleartext transmission of sensitive data, any data that needs to be sent over the network should be encrypted using a strong encryption algorithm. This can be done using tools such as OpenSSL or TLS/SSL.

#2: Use HTTPS
When sending data over the network, use HTTPS instead of HTTP. This will ensure that the data is encrypted before it is transmitted.

#3: Enforce Access Controls
Make sure that access to any sensitive data is restricted to authenticated and authorized users. This will prevent unauthorized users from accessing the data.

#4: Utilize Network Segmentation
Network segmentation can be used to separate sensitive data from other parts of the network. This will ensure that the data is not accessible from untrusted networks.
```

### Semgrep Rule

```yaml
rule = {
	id: "CWE-319-detection",
	severity: "warning",
	pattern: "http(s)?://[a-zA-Z0-9_.-]*(password|credentials|secret|key|token)"
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.dataflow.TaintTracking

class CleartextTransmissionVulnerability(cwe.Vulnerability):
    
    def __init__(self):
        cwe.Vulnerability.__init__(self, "CWE-319")
 
    def predicate(self, q):
        return q.exists(
            semmle.code.cpp.dataflow.TaintTracking.DataFlow,
            lambda df: 
                df.taintSource.taintType == "plaintext" 
                and df.taintSink.sinkType == "network"
        )
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601, also known as an Open Redirect, is a type of vulnerability in which an application or website allows a user to be redirected to an untrusted or malicious website, often without the user's knowledge or consent. This type of vulnerability can be exploited by attackers to launch phishing attacks, spread malware, and direct users to malicious websites. This vulnerability can occur when a web application does not properly validate user-supplied input before using it to construct a redirect URL. Attackers can take advantage of this vulnerability by crafting malicious URLs that redirect users to malicious websites.

### Vulnerable Code

```python
# This is an example of vulnerable code that is susceptible to CWE-601.

def redirect_to_site(site_url):
    # Redirect user to the given URL
    return redirect(site_url)

# This code is vulnerable because the user could be redirected to an untrusted site.
# If an attacker were to craft a malicious URL and pass it to the function, 
# the user could be redirected to a malicious site. 
# This could lead to phishing attacks or other malicious activity.
```

### Remediation

```python
# Before
def redirect_to_url(url):
    return redirect(url)

# After
def redirect_to_url(url):
    if is_safe_url(url):
        return redirect(url)
    else:
        return redirect('/error')
```

### Semgrep Rule

```yaml
rule = {
  id: "open_redirect_detection",
  pattern: "urlparse(param, allow_fragments=True, scheme='http')",
  message: "Potential URL Redirection to Untrusted Site detected.",
  severity: "error"
}
```

### CodeQL Rule

```ql
import cwe601

class CWE601_URL_Redirect_Untrusted_Site:
    def sanitize_redirect_url(url: String):
        return url
    
    def get_redirect_url(url: String):
        return sanitize_redirect_url(url)
    
    def vulnerable_url_redirection(url: String):
        redirect_url = get_redirect_url(url)
        if cwe601.is_unsafe_redirect(redirect_url):
            return redirect_url
        else:
            return ""
    
violation{
  when CWE601_URL_Redirect_Untrusted_Site.vulnerable_url_redirection(url)
  then
    alert("Vulnerable URL redirection detected to an untrusted site!")
}
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability that occurs when sensitive information, such as passwords or other private data, is inserted into log files. This can be a security risk because log files are often exposed to unauthorized users, and the sensitive data can be used to gain access to systems or sensitive data. Attackers can also use the information to gain an understanding of system activity, or to identify possible targets.

### Vulnerable Code

```python
import logging

# Create a logger
logger = logging.getLogger(__name__)

# Create a username and password
username = "user1"
password = "MySecretPassword"

# Log a message with the username and password
logger.info("Username and Password: %s, %s", username, password)
```

### Remediation

```python
Remediation of CWE-532 can be achieved by implementing the following best practices:

1. Ensure that sensitive information is not logged in plaintext. 

2. Use encryption to protect sensitive information before it is logged.

3. Utilize log management tools to consistently monitor and rotate log files.

4. Develop and implement policies and procedures for logging, reviewing, and storing log files.

5. Establish user access controls to restrict and monitor access to log files.

6. Establish an audit trail to track changes and access to log files.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-532",
  pattern: "[log.info, log.warning, log.error] (parameter|input|args|arguments|query|credentials|password|token|key)",
  message: "Sensitive information has been inserted into a log file",
  severity: "error"
}
```

### CodeQL Rule

```ql
import cwe
import python

class CWE532LogFileSensitiveInfoInsertion:
  def predicate(self):
    return exists(
      python.Call('logging.debug', 
        lambda c: exists(c.arg.string_literal, lambda s: cwe.contains_sensitive_information(s)))
    )
```


# Csharp

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is an attack that involves injecting malicious code into a web page or application. This code can be used to execute malicious scripts or redirect users to malicious websites. XSS attacks occur when a web application does not properly neutralize user input, allowing attackers to inject malicious code into the page or application. This malicious code can be used to access sensitive data, steal user information, or even execute malicious scripts on the user's browser.

### Vulnerable Code

```csharp
String userInput = Request.QueryString["userInput"];
Response.Write("<p>User Input: " + userInput + "</p>");

The above code is vulnerable to Cross-site Scripting (XSS) because the userInput variable is being directly output to the page without being properly sanitized. An attacker could inject malicious scripts into the userInput and it would be executed in the user's browser.
```

### Remediation

```csharp
One way to remediate CWE-079 is to use input validation. This means that all user input is checked against a whitelist of accepted values to ensure that only expected data is accepted. For example, if a web page contains a form field in which the user is asked to enter their age, the application can validate that the user has entered an integer value between 0 and 150. Any input that is not an integer value within this range could be rejected or sanitized.

Another way to remediate CWE-079 is to use output encoding. This means that all data outputted to the user's browser is encoded so that any potentially malicious code is rendered harmless. For example, if the user is allowed to enter HTML code into a form field, the application can use HTML encoding to convert the code into its corresponding HTML entities, making it harmless.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper neutralization of user-supplied input in web page generation (CWE-079: Cross-site Scripting)"
    author = "Your Name Here"
  strings:
    $input = /(?:<[^>]*(?:value|src|href|action)\s*=\s*["'][^"']*)(?<script>\s*<\s*script\s*>)/
  condition:
    $input
}
```

### CodeQL Rule

```ql
import csharp
import semmle.code.cpp.dataflow

class XSSVulnerability : Vulnerability {
  // Test if the input is being printed to the output
  // without sanitization
  predicate isVulnerable(DataFlow::Node source) {
    exists(DataFlow::Node sink |
      source.flowsTo(sink) and
      sink.asExpr()?.hasAncestor(
        csharp.CWE_079_Sink()
      )
    )
  }
}

class CWE_079_Sink : Stmt {
  CWE_079_Sink() {
    // Find statements that print to the output without
    // sanitizing the input
    this.containsExpr(
      csharp.Print()
    )
  }
}
```

## CWE-020: Improper Input Validation

### Description

Improper input validation is a vulnerability in which user-supplied input is not properly validated and can be used to cause malicious code execution. Input validation can involve verifying the syntax of the input, verifying that the user-supplied input is within the expected range, or other measures to ensure that the input is valid and not malicious. Improper input validation can lead to various security breaches, including SQL injection, buffer overflows, and cross-site scripting attacks.

### Vulnerable Code

```csharp
public void ProcessInput(string input)
{
    // vulnerable code
    // no validation of the input
    int result = 0;
    for (int i = 0; i < input.Length; i++)
    {
        result += (int)input[i];
    }
    // do something with the result
}
```

### Remediation

```csharp
// Before Remediation:
string userInput = Request.QueryString["userInput"];

// After Remediation:
if (Request.QueryString["userInput"] != null)
{
    string userInput = Regex.Replace(Request.QueryString["userInput"], "[^a-zA-Z0-9]", "");
}
```

### Semgrep Rule

```yaml
rule = 
    regexp: /^(?!.*\b(?:[a-zA-Z0-9_]+\(\)))
    message: "Potential Improper Input Validation found"
```

### CodeQL Rule

```ql
import csharp

class ImproperInputValidation extends SecurityPolicyRule
{
    // Rule is triggered when a function is called with an untrusted input
    // and no input validation is performed
    @Override
    // Declare the query to identify the vulnerability
    source query isVulnerable() {
        // Find functions that accept user input as arguments
        // and do not perform input validation
        (Method m, Expr e) = Method.allMethods()
            // m accepts user input as an argument
            .hasParameterWithType(t => t.isSubtypeOf("System.String")) 
            // m does not perform input validation on user input arguments
            .not(m2 => m2.anyDescendant(e2 =>
                e2.isCall("System.String.IsNullOrEmpty") and
                e2.getArgument(0).equals(
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of security vulnerability that occurs when an attacker exploits a lack of input validation or sanitization by injecting malicious code or commands into an application. This type of injection can be used to bypass authentication, modify or delete data, or even execute arbitrary code. If an application is not properly neutralizing special elements such as user input, environment variables, or other system components, an attacker may be able to inject malicious code or commands into the application, resulting in a security vulnerability.

### Vulnerable Code

```csharp
string command = string.Format("ping {0}", userInput);
ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c " + command);
Process.Start(procStartInfo);

In the above code, the userInput variable is unsanitized before being used in the ping command. This allows an attacker to inject malicious commands into the system, potentially allowing them to gain unauthorized access.
```

### Remediation

```csharp
//Prevent user input from being executed as a system command
string userInput = Console.ReadLine();

//Sanitize user input for any malicious code
userInput = Regex.Replace(userInput, @"[^\w\s]", "");

//Execute the user input as a parameterized query
SqlCommand command = new SqlCommand("SELECT * FROM table WHERE column = @input", connection);
command.Parameters.AddWithValue("@input", userInput);
command.ExecuteNonQuery();
```

### Semgrep Rule

```yaml
rule = {
  strings:
    $str_1 = "system("
    $str_2 = "exec("
    $str_3 = "shell("
  condition: $str_1 or $str_2 or $str_3
}
```

### CodeQL Rule

```ql
import csharp

class CWE_078_OS_Command_Injection extends Rule
{
    // expand the query to find all instances of functions that can be used to execute OS commands
    // (system, exec, etc)
    query vulnerableFunctions(){
        CSharp.MethodInvocationExpr(meth : CSharp.SystemCommandExecutionMethod)
    }

    // check the parameters of the vulnerable functions
    // if one of them is user-supplied input, this is a potential vulnerability
    query isVulnerable(){
        vulnerableFunctions() & CSharp.MethodInvocationExpr.hasArgument(arg : CSharp.Expr, idx : int)
    }
 
    // if the user-supplied input is not properly sanitized, this is a vulnerability
    // use the taint.tainted* family of methods to detect user-supplied
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089 is a type of vulnerability that occurs when user-supplied input is not validated, sanitized or properly escaped before being passed to an SQL query. This can result in malicious SQL code being executed in the database which can grant an attacker unauthorized access to sensitive data, modify the contents of the database, or even delete data. To mitigate this vulnerability, developers should perform input validation and parameterized queries to ensure that the data being passed to the database is safe.

### Vulnerable Code

```csharp
SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE username='" + userName + "'");
```

### Remediation

```csharp
// Example using parameterized queries 
using (SqlConnection conn = new SqlConnection(connectionString))
{
    conn.Open();
    string sql = "SELECT * FROM Users WHERE Username = @username";
    SqlCommand cmd = new SqlCommand(sql, conn);
    cmd.Parameters.AddWithValue("@username", username);
    SqlDataReader reader = cmd.ExecuteReader();
    // Process the data 
}
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-089
    strings:
      - $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'"
    patterns:
      - pattern: "$username' AND password='$password'"
        message: "Potential SQL injection vulnerability detected"
        severity: WARNING
```

### CodeQL Rule

```ql
import csharp

class Vulnerability_CWE_089_SQL_Injection extends SecurityFocus {
    // Create a predicate to match a vulnerable query
    predicate vulnerableQuery() {
        exists(MethodInvocation inv |
            inv.getTarget().getName() == "ExecuteNonQuery" and
            inv.getArgument().hasType(csharp.StringType)
        )
    }

    // Create a predicate to match an unprotected user input
    predicate unprotectedInput() {
        exists(VariableRef vr |
            vr.getVariable().hasAnnotation("unprotected") and
            vr.getAnAccess().getReceiver()
        )
    }

    // Create a predicate to match a vulnerable query that uses an unprotected user input
    vulnerableQuery() and unprotectedInput()
}
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal is a security vulnerability that occurs when a web application or a program uses user-supplied input to construct a pathname that is intended to access files or directories stored outside of the program's root folder. In this way, attackers can traverse the file system to access restricted files, view sensitive information, or even execute malicious code on the server. Path traversal attacks can be prevented by using input validation techniques to ensure that user-supplied paths contain only characters that are authorized and necessary for the application to access the requested files.

### Vulnerable Code

```csharp
string path = "/path/to/file";
string input = "../../../../../../etc/passwd";

//The following code is vulnerable to path traversal
string filePath = Path.Combine(path, input);
//This code would allow an attacker to access the file /etc/passwd
//This is because the user input was not properly validated, allowing it to escape the restricted directory
```

### Remediation

```csharp
// Remediation Example 

string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "users.xml");

// This will ensure that the filePath is always relative to the application's base directory 
// and will prevent any attempts to access a file outside of this directory.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Path Traversal vulnerability"
    author = "Semgrep team"
    id = "CWE-022"
  strings:
    $s1 = /\.\.\/.*\//
    $s2 = /\~\//
  condition:
    $s1 or $s2
}
```

### CodeQL Rule

```ql
import csharp

class PathTraversalVulnCheck:
    // Find potential dangerous calls
    Query potentialDangerousCalls {
        // Check for System.IO.Path calls with user-controlled input
        CSharpMethodInvocation m
        where m.getTarget().getName().matches("Path")
        and m.hasArgumentWithValue(v) 
        and v.mayPointToUserControlledInput()
    }
    
    // Check if the user-controlled input is being used to build a path
    Query dangerousPathBuildingCalls {
        potentialDangerousCalls p
        where p.getName().matches("Combine|GetFullPath|GetDirectoryName")
    }
    
    // Flag calls to Combine, GetFullPath, or GetDirectoryName that do not restrict the path
    vulnerability PathTraversalVuln
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site request forgery (CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to do. It occurs when a malicious website or application causes a user's web browser to perform an unwanted action on a trusted site for which the user is currently authenticated. This can be done by sending a malicious request from the malicious website to the vulnerable website, which then is executed by the user's browser without their knowledge or consent. It is one of the most common web security vulnerabilities, and it can be used to compromise user accounts and steal sensitive data.

### Vulnerable Code

```csharp
// Client side code
<form action="http://www.example.com/action.php" method="POST">
  <input type="hidden" name="_csrf" value="<?php echo $csrf_token; ?>">
  <input type="text" name="username" value="<?php echo $username; ?>">
  <input type="password" name="password" value="<?php echo $password; ?>">
  <input type="submit" value="Submit">
</form>

// Server side code
<?php
$csrf_token = $_POST['_csrf'];
$username = $_POST['username'];
$password = $_POST['password'];

// Verify CSRF token
if ($csrf_token != 'abc123') {
    // CSRF token is invalid
    // Do not process the request
    exit
```

### Remediation

```csharp
Example:

// CSRF protection

// Generate a unique token for each request
var token = GenerateToken();

// Add the token to all POST requests
$('form').submit(function() {
    $(this).append('<input type="hidden" name="csrf_token" value="' + token + '" />');
});

// Validate the token on the server
if(Request.Form["csrf_token"] != token)
{
    // Invalid token - reject request
}
else
{
    // Valid token - continue with request
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects Cross-Site Request Forgery (CSRF) vulnerability"
        author = "Your Name"
        date = "2020-04-24"
    strings:
        $s1 = "csrf_token"
    condition:
        all of them
}
```

### CodeQL Rule

```ql
import csharp

class CSRFVulnerability : Vulnerability {
 
  // Vulnerability title
  let title = "Cross-Site Request Forgery (CSRF) Vulnerability"
  
  // Query to detect the vulnerability
  // Checks for a web request that does not have an anti-CSRF token
  // or a verification of the origin of the request
  query isVulnerable {
    for webReq in WebRequest.calls
    where webReq.hasNoAntiCSRFToken && webReq.hasNoOriginCheck
    select webReq
  }
  
  // Severity of the vulnerability
  // High severity
  let severity = "High"

  // Remediation advice
  let remediation = "Implement an anti-CSRF token or a verification of the origin of the request."
}
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a type of vulnerability that allows attackers to upload malicious files to a server without any restrictions in place. This can be done by exploiting the lack of proper file type validation on the server, allowing attackers to upload and execute malicious code on the target system. This vulnerability can lead to a variety of attacks, such as data theft, defacement, and privilege escalation, as well as providing a foothold for further attacks.

### Vulnerable Code

```csharp
//This code allows a user to upload a file without restriction on file type:

string filename = "C:\\uploads\\myFile.txt";

if (File.Exists(filename))
{
    File.Delete(filename);
}

File.Copy(Request.Files["fileUpload"].FileName, filename);
```

### Remediation

```csharp
Remediation of this vulnerability can involve validating the type and size of the uploaded file before allowing it to be uploaded, and restricting the types of files that can be uploaded.

For example, the following code can be used to validate the type of files before allowing them to be uploaded:

// Validate the type of the uploaded file
string[] allowedExtensions = {".jpg", ".png", ".gif", ".docx"};
string fileExtension = Path.GetExtension(file.FileName).ToLower();
if (!allowedExtensions.Contains(fileExtension))
{
    // File type is invalid, reject it
    return false;
}

The code can also be used to restrict the size of the uploaded file:

// Restrict the size of the uploaded file
if (file.ContentLength > 5 * 1024 * 1024)
{
    // File size is too large,
```

### Semgrep Rule

```yaml
rule = {
	meta:
	  description = "Detects Unrestricted Upload of File with Dangerous Type"
	  author = "Your Name"
	  severity = "high"
	  
	source:
	  lang = "csharp"
	  
	strings:
	  $dangerous_types = /\.exe|\.bat|\.cmd|\.com|\.cpl|\.msi|\.dll|\.vb(s|e)|\.js|\.jse|\.wsf|\.wsh/
	  
	patters:
	  $dangerous_file = /File\.Upload\(.*, $dangerous_types\)/
	  
	 
	
	antipatterns:
	  $dangerous_upload = $dangerous_file
}
```

### CodeQL Rule

```ql
import csharp

class UnrestrictedUploadOfDangerousFileType extends SecurityCodeScannerRule {
  // Rule to detect potential unrestricted upload of dangerous file types
  // File types that should not be allowed are specified in a list of extensions
 
  // list of file types to detect
  string[] extensions = {"exe", "dll", "js", "vbs", "bat", "bin", "scr"};
 
  // query to detect potential unrestricted upload of file types
  query qFileUpload() {
    FileStream f |
    MemberAccess m
    & m.target = f
    & f.name.like("*.(extensions[])")
  }
  
  // method to obtain the list of dangerous file types
  public string[] getExtensions() {
    return extensions;
  }
  
  // rule to detect potential unrestricted upload of dangerous
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306: Missing Authentication for Critical Function is a vulnerability that occurs when authentication is not properly implemented or enforced for a critical function. This type of vulnerability allows attackers to access restricted areas or functions without proper authentication, granting them access to sensitive data and resources. These functions can range from administrative tasks to data manipulation, and an attacker can exploit this vulnerability to gain access to sensitive information or alter data and disrupt operations.

### Vulnerable Code

```csharp
public class UserController
{
    public void CreateUser()
    {
        // code to create a user
    }

    public void UpdateUser()
    {
        // code to update a user
    }

    public void DeleteUser()
    {
        // code to delete a user
    }
}

The problem with the above code is that there is no authentication or authorization check when calling any of the methods. This means that any user can call the CreateUser(), UpdateUser(), and DeleteUser() methods, which can lead to serious security issues.
```

### Remediation

```csharp
The following code remediation example shows how an authentication system can be implemented to ensure that only authorized users can access a critical function:

// Begin authentication system

// Check if user is authorized
if (IsAuthorized(user))
{
   // User is authorized. Allow access to the critical function
   ExecuteCriticalFunction();
}
else 
{
   // User is not authorized. Deny access to the critical function
   LogAccessDenial();
   ThrowUnauthorizedAccessException();
}

// End authentication system
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Missing Authentication for Critical Function"
        id = "CWE-306"
    strings:
        $func1 = "critical_function"
    condition:
        not all and $func1 @within 5 lines of /authentication/
}
```

### CodeQL Rule

```ql
import csharp

class MissingAuthForCriticalFunction extends SecurityRiskRule {
  // Search for methods with a critical function
  // that are not protected by authentication
  @Override
  def getQueries() {
    Q.select(m, s)
      .from(csharp.Method, m)
      .from(csharp.StringLiteral, s)
      .where(m.body().contains(s))
      .where(s.matches(".*critical.*function.*"))
      .where(m, "hasAnnotation", csharp.Annotation.Authentication, false)
  }

  // Reports security risk
  @Override
  def getRiskMessage() {
    return "Missing authentication for critical function"
  }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability that occurs when untrusted data is deserialized. This can lead to malicious code being executed, or sensitive information being exposed. Attackers can exploit this vulnerability by introducing malicious code or data into the system, which can be deserialized by the application and executed. This could allow an attacker to gain access to the system or sensitive information, or to cause damage.

### Vulnerable Code

```csharp
// Deserialization of untrusted data, vulnerable to CWE-502
using System.Runtime.Serialization.Formatters.Binary;

byte[] data = GetUntrustedData();

BinaryFormatter formatter = new BinaryFormatter();
object deserializedObject = formatter.Deserialize(new MemoryStream(data));
```

### Remediation

```csharp
Example of Deserialization of Untrusted Data remediation:

// Declare a new SerializationBinder
SerializationBinder binder = new MyCustomBinder();

// Set the SerializationBinder on the SerializationSettings
var serializationSettings = new JsonSerializerSettings { 
    SerializationBinder = binder 
};

// Use the serializationSettings when deserializing
var deserializedObject = JsonConvert.DeserializeObject<MyObject>(jsonString, serializationSettings);
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects deserialization of untrusted data"
    id = "CWE-502"
  strings:
    $deserialize = "Deserialize"
    $untrusted = "untrusted"
  condition:
    $deserialize and $untrusted
}
```

### CodeQL Rule

```ql
import csharp

class DeserializationOfUntrustedData extends SecurityCodeQL {
    // CWE-502: Deserialization of Untrusted Data

    // Finds all methods that call Deserialize on an untrusted object
    query untrustedDeserialize(){
        MethodInvocation m |
        // Find the method invocation of Deserialize
        m.getName().matches("Deserialize") and 
        // Identify the receiver of the method invocation
        exists(ObjectCreation c | c.getObjects().references(m.getReceiver())) and 
        // Identify the creation of untrusted data
        // Replace "untrustedData" with the type of untrusted data
        exists(ObjectCreation c2 | c2.getObjects().references(m.getReceiver()) and c2.getType().
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability that occurs when an application or system fails to properly authenticate users or verify their credentials. When this happens, an attacker can gain access to data or resources that should be restricted. This type of vulnerability can be exploited by attackers to gain access to sensitive data, files, and services in the system. Additionally, improper authentication can lead to privilege escalation or account hijacking.

### Vulnerable Code

```csharp
public void Login(string username, string password) 
{ 
    if (username == "admin" && password == "admin") 
    { 
        // allow authentication 
    } 
} 

In the code above, the authentication process is vulnerable to a brute force attack. This is because the username and password are both hard-coded within the code, making it easy for an attacker to guess the correct credentials.
```

### Remediation

```csharp
1. Ensure that all users are required to authenticate using a strong password that meets certain requirements (e.g. minimum length, combination of letters, numbers and special characters).

2. Use a two-factor authentication system, such as a one-time password (OTP) or biometric authentication, to verify the identity of users.

3. Ensure that authentication credentials are securely stored, using a secure hashing algorithm such as SHA-2 or bcrypt.

4. Monitor authentication attempts and lock out user accounts after a certain number of failed attempts.

5. Use a secure connection (e.g. SSL/TLS) to protect the transmission of authentication credentials.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects CWE-287: Improper Authentication"
    author = "Security Team"
    id = "CWE-287-1"
  strings:
    $password = /\b(password|passwd)\b/
    $user = /\b(user|username)\b/
  condition:
    $password and $user
  message: "CWE-287: Improper Authentication detected"
}
```

### CodeQL Rule

```ql
import csharp

class ImproperAuthenticationVulnerability implements CxChecks {
  CxList authenticationMethods = Find_Methods().FindByShortName("authenticate*", false);

  @Override
  public CheckResult test() {
    if(authenticationMethods.Count == 0){
      return CheckResult.failure("No authentication methods found");
    }
    CxList passwords = authenticationMethods.FindByParameterName("password", false);
    
    if (passwords.Count == 0){
      return CheckResult.failure("No password parameter found in authentication methods");
    }
    CxList hashes = passwords.FindByShortName("hash*", false);
    if (hashes.Count == 0){
      return CheckResult.fail("Password parameter not hashed in authentication methods");
    }
    return CheckResult.success();
  }
}
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability where a program or application uses hard-coded credentials, such as a username and password, to access restricted resources. This is a security issue because anyone that knows the credentials can gain access to the resource, and potentially cause damage or steal data. It also makes it difficult to change or revoke access as the credentials cannot be easily changed or updated. Additionally, hard-coded credentials are typically stored in plain text, which leaves them exposed to anyone who is able to access the source code or executable file.

### Vulnerable Code

```csharp
string username = "admin";
string password = "admin123";

if(username == "admin" && password == "admin123")
{
   // grant access
}
else
{
   // deny access
}
```

### Remediation

```csharp
// Before 
string connectionString = "Data Source=database_server;User Id=username;Password=password;";

// After 
string connectionString = "Data Source=database_server;User Id=@username;Password=@password;";

// Retrieve credentials from an encrypted configuration file or user prompt
string username = GetUsername();
string password = GetPassword();

// Create connection string with retrieved credentials
string connectionString = "Data Source=database_server;User Id=" + username + ";Password=" + password + ";";
```

### Semgrep Rule

```yaml
rule = {
 	meta:
 		description = "Detection of hard-coded credentials"
 		author = "Author Name"
 	strings:
 		$creds_1 = "*username*"
 		$creds_2 = "*password*"
 		$creds_3 = "*key*"
 		$creds_4 = "*token*"
 		$creds_5 = "*secret*"
 		$creds_6 = "*account*"
 		$creds_7 = "*api-key*"
 		$creds_8 = "*auth-token*"
 		$creds_9 = "*access-key*"
 		$creds_10
```

### CodeQL Rule

```ql
import csharp

class HardcodedCredentialsVulnerability {
  /**
   * Finds uses of hard-coded credentials
   */
  predicate isHardcodedCredential(Credential c) {
    exists(Identifier id, MemberAccess ma |
           ma.getTarget() = c &&
           ma.getName() = id &&
           id.getName().matches("password|username|token")
    )
  }
  
  //Vulnerable code should be flagged
  //If the credentials are hardcoded
  @CxSecurityCodeMarker
  @CxSecurityVulnerability(type="CWE-798: Use of Hard-coded Credentials")
  void vulnerableMethod(Credential c) {
    if (isHardcodedCredential(c)) {
      //Vulnerable code
    }
  }
}
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 is a vulnerability that occurs when a system has incorrect default permissions set, which can lead to unauthorized access to sensitive information or code. This vulnerability can arise in several ways, including when a system is installed with default settings that provide more access to the system than necessary, or when a system is configured to allow access to privileged accounts without proper authentication. Attackers can exploit this vulnerability to gain access to sensitive data, modify system settings, or even take control of the system.

### Vulnerable Code

```csharp
// This code sets the default permissions for a file to 0666
FileStream fs = new FileStream("file.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
fs.SetAccessControl(new FileSecurity("file.txt", AccessControlSections.Access));
fs.SetAccessControl(new FileSecurity("file.txt", FileSystemRights.Modify, AccessControlType.Allow));
```

### Remediation

```csharp
// Remediation

// Create a new policy to ensure that all files and folders are given the correct default permissions. 

// Steps:

// 1. Create a new security group and add all users who need access to the files and folders.

// 2. Create a new Group Policy Object (GPO) and set the default permissions for the security group.

// 3. Link the GPO to the domain, so that all files and folders have the correct default permissions.

// 4. Test the policy to ensure that all files and folders have the correct default permissions.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-276-Incorrect-Default-Permissions",
  patterns: [
    // Look for permissions settings that are less restrictive than expected
    pattern: "permission == '*' or permission == 'Everyone' or permission == 'World' or permission == 'Anonymous'",
    message: "Incorrect default permissions detected",
    severity: "WARNING"
  ]
}
```

### CodeQL Rule

```ql
import csharp

class IncorrectDefaultPermissions : CodeQLQuery {
  // Find all method declarations
  private query MethodDecl() {
    m:MethodDecl
  }
  
  // Find all access modifiers
  private query AccessModifier() {
    m:AccessModifier
  }
  
  // Find all constructors
  private query ConstructorDecl() {
    m:ConstructorDecl
  }
  
  // Find all classes
  private query ClassDecl() {
    m:ClassDecl
  }

  // Find all method declarations with public or private access modifiers
  private query MethodDeclWithAccessModifier() {
    MethodDecl(
      AccessModifier(
        m.getModifier() in {"public", "private"}
      )
    )
  }

  // Find all constructor declarations with public or private access modifiers
  private query
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability which occurs when sensitive information, such as passwords, credit card numbers, or personal data, is exposed to an unauthorized actor. This data may be exposed either through the malicious actions of an attacker, accidental disclosure, or a lack of security measures in place to protect the sensitive information. This vulnerability can lead to identity theft, financial fraud, and other malicious activities.

### Vulnerable Code

```csharp
using System.Net;

// Receive data from a web service
string data = "";

using (WebClient client = new WebClient())
{
    data = client.DownloadString("http://example.com/data.txt");
}

// Display the data on the screen
Console.WriteLine(data);
```

### Remediation

```csharp
The following example shows how to remediate a CWE-200 vulnerability by using encryption to protect sensitive data:

1. Identify the sensitive data and the unauthorized actors who could have access to it.

2. Decide on an appropriate encryption algorithm and key size.

3. Implement the encryption algorithm to encrypt the sensitive data.

4. Store the encrypted data in a secure location and limit access to only authorized personnel.

5. Use secure protocols to transmit the encrypted data over an untrusted network.

6. Utilize secure authentication methods to verify the identity of authorized personnel.

7. Monitor and audit access to the encrypted data.
```

### Semgrep Rule

```yaml
rule = {
	id: CWE-200
	pattern: "*(password|passwd|credentials|secret|access_token|auth_token)[^\s]*="
	message: "Possible exposure of sensitive information to an unauthorized actor detected"
	severity: WARNING
}
```

### CodeQL Rule

```ql
import csharp

class CWE_200 : CodeQLSecurityVulnerability {

  // Checks if a sensitive information is passed to an unauthorized actor
  CxList sensitiveInfo = Find_Sensitive_Data_Stored_In_Variables();
  CxList unauthorizedActors = Find_Unauthorized_Actors();
  CxList potentialVulnerabilities = sensitiveInfo.DataInfluencingOn(unauthorizedActors);
  
  // Checks if the sensitive information is used in a method call
  CxList methods = Find_Methods();
  CxList methodCall = potentialVulnerabilities.FindByType(typeof(MethodInvokeExpr));
  CxList vulnerableMethods = methods.FindByParameters(potentialVulnerabilities);
  
  // Checks if sensitive data is used in an assignment
  CxList assignments = Find_Assignments();
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522: Insufficiently Protected Credentials is a vulnerability that occurs when authentication credentials are stored in a way that does not protect them from unauthorized access. This could be done by storing them in plaintext, using weak encryption, or not using any encryption at all. By not properly protecting credentials, an attacker could gain access to an application or system, compromising the security of the system and any data it contains.

### Vulnerable Code

```csharp
string user = "admin";
string pass = "password"; 

// This code doesn't use any encryption
if (user == "admin" && pass == "password")
{
    // user is authenticated
}
else
{
    // user is not authenticated
}
```

### Remediation

```csharp
Remediation for CWE-522: Insufficiently Protected Credentials involves implementing strong authentication and access control measures. Specifically, organizations should take steps to ensure that passwords or other credentials used to access sensitive systems or data are sufficiently protected from unauthorized use or access.

Some best practices for protecting credentials include:

1. Requiring strong passwords that are at least 8-10 characters long and difficult to guess.

2. Limiting the number of failed login attempts before locking out the user account.

3. Ensuring that passwords are not shared or stored in plaintext.

4. Utilizing multi-factor authentication.

5. Enforcing regular password changes.

6. Encrypting passwords and other confidential information.
```

### Semgrep Rule

```yaml
rules:
  - id: insufficiently-protected-credentials
    patterns:
    - pattern: 'username=${username:regex(".*")}&password=${password:regex(".*")}'
    message: 'Credentials are not sufficiently protected.'
    severity: ERROR
    metadata:
      cwe: 'CWE-522'
```

### CodeQL Rule

```ql
import csharp

class InsufficientlyProtectedCredentialsRule extends Rule {
 
  // Query to find all instantiations of the DataProtection class
  query dataProtectionClass() {
    DataProtection dp
  }
  
  // Query to find all instantiations of the System.Configuration.ConfigurationManager class
  query configManagerClass() {
    ConfigurationManager cm
  }
  
  // Query to find all calls to DataProtection.Protect()
  query protectMethod() {
    DataProtection.Protect(...)
  }
  
  // Query to find all calls to System.Configuration.ConfigurationManager.AppSettings.Get()
  query getMethod() {
    ConfigurationManager.AppSettings.Get(...)
  }
  
  // Query to find instances of credentials stored in the configuration that are not sufficiently protected
  query insufficientlyProtectedC
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability that occurs when an application parses XML input without properly restricting external entity references. This vulnerability allows attackers to access sensitive data and potentially execute malicious code by exploiting references to outside resources. By manipulating the XML input, an attacker could access files on the server or even remote systems, resulting in unauthorized access to confidential data or remote code execution.

### Vulnerable Code

```csharp
// Vulnerable Code
XmlDocument xmlDoc = new XmlDocument();
xmlDoc.Load("http://example.com/file.xml");

// The URL provided in the Load method is not sanitized which can allow attackers to exploit XXE vulnerabilities by providing an external entity reference in the file.xml file. This can lead to sensitive information disclosure, denial of service, and other attacks.
```

### Remediation

```csharp
Example:

// Before
XmlDocument doc = new XmlDocument();
doc.LoadXml(xmlString);

// After
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
XmlReader reader = XmlReader.Create(new StringReader(xmlString), settings);
XmlDocument doc = new XmlDocument();
doc.Load(reader);
```

### Semgrep Rule

```yaml
rule = {
  strings:
    // detect usage of XML External Entity Reference
    $xml_ee_ref="<!ENTITY"
  condition: $xml_ee_ref
}
```

### CodeQL Rule

```ql
import csharp

class VulnerableXMLRefInjectionRule extends Rule {
  // Rule to detect improper restriction of XML external entity reference
 
  // Finds any XML document created from a string
  query XMLDocFromString(){
    XmlDocument.ctor(string)
  }
 
  // Finds any suspicious external entity references
  query ExternalEntityRef(){
    XmlDocument.CreateEntityReference(string)
  }
 
  // Matches any XML document created from a string that contains a suspicious external entity reference
  query result(){
    XMLDocFromString()
    ctor <- ExternalEntityRef()
  }
 
  // Reports the vulnerability
  vuln_msg = "Improper restriction of XML external entity reference detected"
 
  // Entry point
  @Override
  public predicate isVulnerable(){
    result()
  }
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

CWE-918 is a type of attack which allows attackers to send malicious requests to a web server from a trusted source. This type of attack allows attackers to bypass authentication and access internal systems and data that would otherwise be inaccessible. It is possible to use this vulnerability to scan internal networks, access restricted files, and gain access to sensitive information. Additionally, attackers can use SSRF to launch denial of service attacks, or even launch attacks against other servers.

### Vulnerable Code

```csharp
public async Task<string> GetData(string url) 
{
    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
    request.Method = "GET";
    string response = "";
    using (HttpWebResponse resp = (HttpWebResponse)await request.GetResponseAsync())
    {
        using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
        {
            response = reader.ReadToEnd();
        }
    }
    return response;
}

The above code is vulnerable to a server-side request forgery attack. An attacker could provide a malicious URL in the “url” parameter, which the code would then send an HTTP request to, potentially exposing the server to attack.
```

### Remediation

```csharp
Example:

The following code implements a SSRF vulnerability remediation strategy in Csharp:

// Check if the request is local
if (!Request.IsLocal)
{
    // Redirect to an error page
    Response.Redirect("/Error.aspx?ErrorCode=403");
}

// Validate the request by comparing the Host header with the domain name
if (Request.Url.Host != "domain.com") 
{
    // Redirect to an error page
    Response.Redirect("/Error.aspx?ErrorCode=403");
}

// Verify the request is for a valid endpoint
if (!Request.Url.PathAndQuery.StartsWith("/validEndpoint")) 
{
    // Redirect to an error page
    Response.Redirect("/Error.aspx?ErrorCode=403");
}
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-918-SSRF
    severity: critical
    message: "Server-Side Request Forgery (SSRF) detected"
    patterns:
      - pattern: '<\s*[a-zA-Z0-9]+\s*(?:src|action|href)\s*=\s*[^\s]*(?:http|https)\s*:'
        qualifiers:
          - "diagnostics.severity='critical'"
    metadata:
      cwe: 918
      cve: 
      capec: 
      references: 
        - name: OWASP
          url: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
```

### CodeQL Rule

```ql
import csharp

class ServerSideRequestForgeryVulnerability: Vulnerability {
  // Checks if request can be sent to an external URL
  // and the URL is not validated
  predicate isExternalRequest() {
    // Checks if a Uri object is instantiated with a user-controlled string
    exists(MethodInvocation mi | 
      mi.getTarget().getType().getName() = "System.Uri" and
      mi.getArgumentCount() > 0 and
      mi.getArgument(0).hasStringValue()
    )
  }
  
  // Checks if the URL is being verified
  predicate isUrlValidated() {
    // Checks for any method that validates the URL
    exists(MethodInvocation mi | 
      mi.getTarget().getType().getName() = "System.Uri" and
      (mi.getName
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of vulnerability that allows an attacker to execute arbitrary commands on a vulnerable system. This vulnerability occurs when an application takes user input and passes it directly to a system command without sufficient validation. The attacker can then inject malicious commands into the application, which are then executed by the system. This can allow an attacker to gain access to sensitive information or make changes to the system.

### Vulnerable Code

```csharp
string userInput = Console.ReadLine();
Process.Start("cmd.exe","/c " + userInput);

This code is vulnerable to command injection as it does not properly handle user input. An attacker could pass malicious input to the program, which would be executed without validation.
```

### Remediation

```csharp
// Before Remediation 
string cmd = "dir" + input;
System.Diagnostics.Process.Start("cmd.exe",cmd);

// After Remediation 
string cmd = "dir";
System.Diagnostics.Process.Start("cmd.exe",cmd);
string[] args = input.Split(" ");
System.Diagnostics.Process.Start("cmd.exe",cmd + string.Join(" ", args));
```

### Semgrep Rule

```yaml
rule = { 
    meta: 
        description = "Detects command injection vulnerabilities"
    source: 
        language = "Csharp"
    patterns: 
        - pattern: 
            multi-patterns: 
                - '" | cmd.exe /c \"'
                - 'System.Diagnostics.Process.Start("'
    message: "Command injection vulnerability detected"
}
```

### CodeQL Rule

```ql
import csharp

class CWE077ImproperCommandInjection : CodeQLSecurityVulnerability {
  CWE077ImproperCommandInjection() {
    super("CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')");
  }

  override predicate isVulnerable(Method m) {
    // Look for methods that use user-provided input to construct a command
    m.getInstructions()
    .matching(
      Instruction.Call(Method.Named("System.Diagnostics.Process.Start"),
                       _,
                       // The second argument of Start() is a string that is passed to the shell
                       Instruction.LoadConst(userInput)
                      )
    )
  }
}
```

## CWE-295: Improper Certificate Validation

### Description

Improper Certificate Validation is a vulnerability that occurs when an application fails to properly validate digital certificates. This can allow an attacker to use forged or otherwise maliciously created certificates to bypass authentication and authorization, hijack sensitive data, or launch man-in-the-middle attacks. Improper certificate validation can also lead to an application trusting a malicious certificate presented by an attacker, leading to a variety of security issues.

### Vulnerable Code

```csharp
// This code does not validate the server certificate properly
HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://www.example.com/");
request.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
HttpWebResponse response = (HttpWebResponse)request.GetResponse();
```

### Remediation

```csharp
using System.Security.Cryptography.X509Certificates;

// Check the certificate chain
bool VerifyCertificateChain(X509Certificate2 certificate)
{
    X509Chain chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
    chain.ChainPolicy.VerificationTime = DateTime.Now;
    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
    
    if (!chain.Build(certificate))
    {
        return false;
    }

    foreach (X509ChainElement element in chain.ChainElements)
    {
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects Improper Certificate Validation vulnerability"
      author = "Your Name"
      id = "CWE-295"
      references = "https://cwe.mitre.org/data/definitions/295.html"
    strings:
      $cert_validation = /(?i)\b(ssl|tls|certificate)\b.*\b(validate|verify|authenticate)\b/
    condition:
      $cert_validation
}
```

### CodeQL Rule

```ql
import csharp

class ImproperCertificateValidationVulnerability {
  //This query looks for classes that contain methods that call X509Certificate2.Verify()
  // without passing a parameter to set the revocation flag
  // as this allows the possibility of a man-in-the-middle attack
  // to take place.
  private static Method X509Certificate2Verify =
    method("System.Security.Cryptography.X509Certificates.X509Certificate2.Verify() : void");

  public predicate isVulnerable() {
    //The query looks for classes that contain the X509Certificate2.Verify() method
    // but does not pass in a parameter to set the revocation flag
    // The parameter is called 'showUI' and is a boolean
    exists(Method m, Parameter p |
      m.getContainingType() == this
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 describes a vulnerability where untrusted input is used to generate code that is then executed in the system. This type of vulnerability can occur when a program takes user-supplied input, such as a data string, and uses it to dynamically generate code. This code can then be executed as part of the program, creating a vulnerability that can be exploited by an attacker. In the worst case, the attacker can use this vulnerability to inject malicious code into the system, allowing them to gain control of the system.

### Vulnerable Code

```csharp
string input = Console.ReadLine();
Process.Start("cmd.exe", "/c " + input);

This code is vulnerable to code injection because it allows user input to be passed directly to the Process.Start command without any sanitization or validation. This can allow an attacker to inject malicious code into the system, potentially allowing for remote code execution.
```

### Remediation

```csharp
Example:

// Before
string command = Request.QueryString["cmd"];
Process.Start(command);

// After
string command = Request.QueryString["cmd"];
if (IsValidCommand(command))
{
    Process.Start(command);
}
else
{
   // Handle invalid command
}

// IsValidCommand() is a custom validation function to ensure that only safe commands are executed.
```

### Semgrep Rule

```yaml
rule = {
  strings:
    $cmd = /.+/
  condition:
    $cmd
}
```

### CodeQL Rule

```ql
import csharp

class ImproperControlOfGenerationOfCode extends SecurityCodeScannerRule {
  // Define the query for the rule
  Query query() {
    // Find all instances of System.Diagnostics.Process.Start
    ProcessStart[] starts = ProcessStart.all;
    // Filter for only calls that accept user input
    starts = starts.select(s | s.HasUserInput)
    // Return the results
    return starts;
  }

  // Provide a description
  Description description() {
    return Description("CWE-094: Improper Control of Generation of Code (Code Injection)");
  }
 
  // Provide a remediation
  Message remediation() {
    return Message("Ensure that user input is sanitized before being passed to System.Diagnostics.Process.Start.");
  }
}
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 Improper Privilege Management is a vulnerability that arises when an application or system does not properly manage user privileges. This can be caused by granting excessive privileges to users, not properly restricting access to certain resources, or failing to properly assign privileges to users. Attackers may be able to take advantage of this vulnerability to gain access to resources that should not be accessible to them, or to elevate their privileges to gain access to more sensitive resources. Additionally, attackers may be able to use this vulnerability to impersonate other users, bypass authentication, or elevate privileges to become a superuser.

### Vulnerable Code

```csharp
public class VulnerableClass
{
    public void DoSomething()
    {
        // Get the current user's credentials
        string username = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

        // Give the current user elevated privileges 
        System.Security.Principal.WindowsPrincipal principal = 
            new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent());
        principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
```

### Remediation

```csharp
The best way to remediate CWE-269 is to ensure that user privileges are managed correctly. This can be done by making sure that only the necessary privileges are granted to each user, and that they are not given privileges that could be used to gain unauthorized access to data. Additionally, user privileges should be periodically reviewed and revoked when no longer needed. Finally, it is important to ensure that privilege escalation attacks are prevented by implementing strong authentication measures, such as multi-factor authentication.
```

### Semgrep Rule

```yaml
rule = {
    strings:
    // Detects any assignments to a user's privilege level
    $privilege_level = *
    
    condition: $privilege_level
}
```

### CodeQL Rule

```ql
import csharp

class CWE269ImproperPrivilegeManagement extends Query {
    private BooleanExpression isPublicMethod = 
        (m: Method) => m.access == Access.PUBLIC;

    private BooleanExpression isWriteFileMethod = 
        (m: Method) => m.getName().matches("WriteFile");
    
    private BooleanExpression isCreateFileMethod = 
        (m: Method) => m.getName().matches("CreateFile");

    private BooleanExpression isSetAccessControlMethod = 
        (m: Method) => m.getName().matches("SetAccessControl");

    query hasVulnerability() {
        Method.find(isPublicMethod, isWriteFileMethod
            or isCreateFileMethod, isSetAccessControlMethod).hasAtLeast(3)
    }
}
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is a vulnerability which occurs when input provided by a user is used in an Expression Language (EL) statement without proper neutralization. This can lead to attackers manipulating the EL statement in order to execute dangerous commands or access sensitive data. These attacks can be performed by injecting specially crafted input into the application which can then be executed by the EL statement. The application may also be vulnerable if it uses user-supplied input as part of an EL statement without properly validating or sanitizing it first.

### Vulnerable Code

```csharp
string name = Request.QueryString["name"];
string sqlQuery = "SELECT * FROM Users WHERE Name=" + name;
SqlCommand command = new SqlCommand(sqlQuery, connection);
SqlDataReader reader = command.ExecuteReader();

In this example, the code does not properly sanitize user input for the "name" parameter before using it as part of a SQL query. This can lead to an Expression Language Injection vulnerability, which can allow an attacker to manipulate the SQL query to gain access to sensitive information or execute malicious code.
```

### Remediation

```csharp
Example 1:

//Pre-remediation
String queryString = "SELECT * FROM Users WHERE Id = " + userId;

//Remediation
String queryString = "SELECT * FROM Users WHERE Id = @userId";
SqlCommand cmd = new SqlCommand(queryString);
cmd.Parameters.Add("@userId", userId);
```

### Semgrep Rule

```yaml
rule = {
	meta:
		description = "Detects CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement"
		author = "Your Name"
		date = "YYYY-MM-DD"
		reference = "CWE-917"
		tags = ["security", "cwe-917"]
		severity = "CRITICAL"
		confidence = "HIGH"
		
	pattern: 
		expression:
			"${.*?}"
			
		message:
			"Possible CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement"
			
}
```

### CodeQL Rule

```ql
import csharp

class ExpressionLanguageInjection:

    // Rule to detect improper neutralization of special elements used in an expression language statement
    // that may lead to expression language injection
    rule ExpressionLanguageInjection {
        // Finds calls to methods that use an expression language
        // statement with user input
        when
            m1 := csharp.Method("<expression language method>")
            p1 := csharp.Parameter(m1, 0)
            u1 := csharp.UserInput(p1)
        then
            // Warns of potential expression language injection
            csharp.reportWarning("Expression language injection detected", u1)
    }
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

The CWE-059 vulnerability is a type of security issue that can occur in software when a program is able to gain access to files on a system without ensuring that the files are legitimate. This type of vulnerability can occur when an application follows a link to an external source, such as a web page or file, without checking that the target is valid before accessing it. This type of vulnerability can result in malicious code being executed on the system or sensitive data being exposed.

### Vulnerable Code

```csharp
string fileName = "C:\\Users\\user\\Documents\\file.txt";
File.Open(fileName, FileMode.Open);

In the above code, the application does not check the validity of the file path prior to attempting to open the file. This can lead to the application attempting to open a file that does not exist, or a malicious file that has been placed in the same directory as the application.
```

### Remediation

```csharp
The following code shows an example of remediation for this vulnerability:

// Before file access, check that the path is valid and canonicalized 
string path = Path.GetFullPath(requestedPath);
if (!Path.IsPathRooted(path))
{
    throw new SecurityException("Path not rooted");
}

// Check to see if the path is within the allowed directory structure
string canonicalizedAllowedPath = Path.GetFullPath(allowedPath);
if (!path.StartsWith(canonicalizedAllowedPath))
{
    throw new SecurityException("Path not allowed");
}

// All checks passed so the file can now be accessed safely
FileStream fs = File.OpenRead(path);
```

### Semgrep Rule

```yaml
rule = {
	meta:
	  description = "Detects improper link resolution before file access"
	  id = "CWE-059"
	  author = "Signed security"
	  severity = "MEDIUM"
	
	source:
	  include = "**/*.cs"
	  
	strings:
	  $fopen_str = "File.Open("
	  $link_str = "Link("
	  
	condition:
	  $fopen_str and not $link_str
}
```

### CodeQL Rule

```ql
import csharp

class CWE059ImproperLinkResolutionBeforeFileAccess extends Query {
  // Finds calls to System.IO.File.Open that 
  // access files without first verifying the path
  predicate isFileOpenCall(Expr filePathExpr, Expr fileModeExpr, Expr fileAccessExpr) {
    exists(MethodInvocation mi |
      mi.getTarget().matchesName("System.IO.File.Open") and 
      mi.getArgument(1).equals(filePathExpr) and
      mi.getArgument(2).equals(fileModeExpr) and
      mi.getArgument(3).equals(fileAccessExpr)
    )
  }

  // Finds calls to System.IO.File.Open that 
  // access files without first verifying the path
  predicate is
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information is transmitted in plaintext without being encrypted. This can occur when sensitive data is sent over an unsecured network, such as the internet, or when it is stored in cleartext on a computer system. This type of vulnerability can lead to data breaches and other security issues. Attackers can easily access this sensitive data and use it to gain access to other areas of a system or to steal the data. By not encrypting sensitive information, organizations are leaving their data open to potential malicious actors.

### Vulnerable Code

```csharp
string username = "admin";
string password = "password";

//Connect to database
SqlConnection conn = new SqlConnection("Data Source=localhost;User Id=" + username + ";Password=" + password);
conn.Open();
```

### Remediation

```csharp
Remediation for this vulnerability involves implementing encryption for any sensitive data transmission. For example, if a website is transmitting sensitive user data over the internet, the website should use encryption protocols such as SSL/TLS or IPSec. This will ensure that the data is encrypted and not readable by any malicious third-party. Additionally, the website should also use secure authentication methods, such as two-factor authentication, to prevent unauthorized access to the data.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects cleartext transmission of sensitive information"
    severity = "high"
  strings:
    $sensitive_info = /[a-zA-Z0-9_\-.]+@[a-zA-Z0-9_\-.]+/
  expressions:
    $sensitive_info
}
```

### CodeQL Rule

```ql
import csharp

class CleartextTransmissionVulnerability {
  // Finds any instance of sensitive information being sent over an insecure connection
  // without encryption.
  //
  // @cwe CWE-319
  //
  // @example
  //  // Example vulnerable code
  //  var webRequest = WebRequest.Create("http://example.com");
  //  webRequest.Method = "POST";
  //  webRequest.ContentType = "text/plain";
  //  webRequest.ContentLength = data.Length;
  //  using (var streamWriter = new StreamWriter(webRequest.GetRequestStream()))
  //  {
  //    streamWriter.Write(data);
  //  }
  //
  // @example
  //  // Example secure code
  //  var webRequest = WebRequest.Create("https
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 is a type of vulnerability that allows attackers to redirect users from a trusted website to an untrusted one. This can be done by manipulating the URL of the website, inserting malicious code, or using malicious redirects. When a user visits the trusted website, they are unknowingly redirected to the untrusted site, which can be used to collect sensitive data or execute malicious code. This vulnerability can be exploited by attackers to gain access to confidential data or perform malicious activities, such as phishing or malware distribution.

### Vulnerable Code

```csharp
// vulnerable code example

string redirectUrl = Request.QueryString["redirectUrl"]; 

if (!string.IsNullOrEmpty(redirectUrl)) 
{ 
    Response.Redirect(redirectUrl); 
}
```

### Remediation

```csharp
// Before Remediation
public ActionResult Redirect(string url)
{
    return Redirect(url);
}

// After Remediation
public ActionResult Redirect(string url)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return BadRequest();
    }

    // whitelist of trusted domains
    string[] trustedDomains = { "example.com", "example.org" };
    Uri uri;
    if (Uri.TryCreate(url, UriKind.Absolute, out uri) && trustedDomains.Contains(uri.Host))
    {
        return Redirect(url);
    }
    else
    {
        return BadRequest();
    }
}
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-601-open-redirect",
  patterns: [
    {
      pattern: "{string_lit:url}",
      qualifiers: [{
        qualifier: "location",
        kind: "URL"
      }]
    },
    {
      pattern: "Response.Redirect({string_lit:url})",
      qualifiers: [{
        qualifier: "location",
        kind: "URL"
      }]
    }
  ],
  message: "URL redirection to untrusted site detected: {{url}}",
  severity: "error"
}
```

### CodeQL Rule

```ql
import csharp
import semmle.code.cpp.dataflow.TaintTracking

class OpenRedirectVulnerability : CodeQLSecurityVulnerability {
    // Look for a method that takes a URL as an argument
    // and checks if the domain is trusted
    predicate isTrustedDomainCheck(MethodCall m) {
        exists(string s,
            m.getArgument(0).asExpr() = s.toExpr()
            and m.getTarget().getName().matches("*isTrustedDomain*")
        ) 
    }
    
    // Check for a method that takes a URL as an argument
    // and redirects the user to the given URL
    predicate isRedirect(MethodCall m) {
        exists(string s,
            m.getArgument(0).asExpr() = s.toExpr()
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability that occurs when sensitive information, such as passwords, usernames, or other confidential data, is inadvertently inserted into a log file. This can occur when programs are not properly configured to protect and filter sensitive data before it is written to a log file. Attackers can potentially gain access to this data, leading to potential data breaches or other malicious activity.

### Vulnerable Code

```csharp
string username = "exampleuser";
string password = "examplepassword";

// Log the user information in a file
File.AppendAllText("log.txt", "Username: " + username + " Password: " + password);
```

### Remediation

```csharp
The application should be designed to avoid the insertion of sensitive information into log files. This can be done in a number of ways, such as:

-Creating separate log files for sensitive information and non-sensitive information
-Ensuring that any sensitive information is encrypted before being written to a log file
-Limiting access to log files to authorized personnel only
-Ensuring that any log files are regularly monitored for suspicious or malicious activity.
```

### Semgrep Rule

```yaml
rule = {
    strings:
    // Sensitive information
    $sensitive_info = /(password|credit card number|social security number)/
    // Logging
    $logging = /(log|write)/
    // Sensitive information being logged
    $log_sensitive_info = /$sensitive_info $logging/
   
    condition: $log_sensitive_info 
}
```

### CodeQL Rule

```ql
import csharp

class CWE532_Insertion_Of_Sensitive_Information_Into_Log_File extends Rule {
    // Find any calls to a logging function
    // that contain sensitive information
    // as an argument
    //
    // e.g. log.Info("User password: "+password);
    //
    // Note: This rule won't detect all cases as it may not
    // be possible to identify sensitive information
    // without additional context
   
    // Find any logging functions
    predicate logFunctions() {
        exists(Method m |
            m.getDeclaringType().getName().matches("ILog")
            and m.getName().matches("Info|Warn|Error|Fatal"))
    }
    
    // Find any sensitive data from the parameters
    // of a function call
    predicate sensitiveData
```


# Swift

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of vulnerability that occurs when a malicious script is injected into an application. This script is then executed by a user's browser, allowing attackers to gain access to sensitive information, such as cookies or session tokens. In the case of Swift, this vulnerability can arise when user-supplied data is not properly sanitized before being included in the generated webpage, allowing attackers to inject malicious scripts that can be executed in the user's browser.

### Vulnerable Code

```swift
let userInput = "Hello <script>alert('XSS');</script>"

let output = "<h1>\(userInput)</h1>"

print(output)
```

### Remediation

```swift
// Before
let name = request.value(forKey: "name")
let html = "<html><body><h1>Welcome, \(name)!</h1></body></html>"

// After
let name = request.value(forKey: "name")
let html = "<html><body><h1>Welcome, \(name.sanitizedForHTML())!</h1></body></html>"
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: "\\[.*?\\]\\(.*?\\)",
      message: "Potential Cross-site Scripting vulnerability detected, consider validating user input before generating web page"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe079

class CWE079Rule extends Rule {
  // Define the query
  query CWE079Rule() {
    // Identify a potential vector of attack
    Vector v = InputVector()
    // Find a vulnerable context
    VulnerableContext ctx = VulnerableContext.find(v)
    // Report any vulnerable contexts
    report ctx
  }
}
```

## CWE-020: Improper Input Validation

### Description

Improper input validation is a vulnerability that occurs when an application does not validate or properly sanitize user input before using it. This can allow malicious users to inject malicious code into the application, which can be used to gain access to sensitive information or perform malicious actions.

### Vulnerable Code

```swift
let inputString = "12345"
let intValue = Int(inputString)

if intValue! > 5 {
    // Do something
}

// This code is vulnerable to CWE-020 because it does not properly validate the input string and could lead to unexpected results if the input string is not a valid integer.
```

### Remediation

```swift
// Remediation
func validateInput(input: String) -> Bool {
    let validInputs = ["foo", "bar", "baz"]
    if validInputs.contains(input) {
        return true
    } else {
        return false
    }
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-020",
  pattern: "{left: /(let|var) +[a-zA-Z]+ *=/ *\\d+/, right: /}/, message: "Improper input validation detected"}
```

### CodeQL Rule

```ql
import cwe020

class CWE020ImproperInputValidation:
 
    // Rule to detect if user input is not properly validated
    // before being used.
   
    // Finds functions that have arguments which are used without
    // validating them.

    // Finds variables which are set from a function call
    // without validating the input.

    // Finds variables which are set from user input
    // without validating the input.
 
    // Finds unsafe type casts that could lead to
    // improper input validation.
    
    // Finds functions which take user input without
    // validating it.
    
    // Finds calls to functions that are vulnerable to
    // improper input validation.
 
    // Finds code which does not properly validate user
    // input before being used.
    
    // Finds code which does not
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

OS Command Injection is a type of vulnerability in which an attacker can execute arbitrary system commands by manipulating input data sent to an application or system. This vulnerability is caused by a lack of proper input validation and sanitization, allowing attackers to modify their input in a way that can execute malicious commands on the system. These commands can be used to gain access to sensitive data, alter or delete files, and even execute malicious code. This vulnerability can be exploited by malicious actors to gain unauthorized access to a system and cause significant damage.

### Vulnerable Code

```swift
//In this example, a user input is passed as an argument to the 'system()' function call without any validation or sanitization.

let userInput = "rm -rf /"
system(userInput)
```

### Remediation

```swift
// The following code can be used to prevent OS Command Injection

let userInput = "someInput"

let allowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

if userInput.rangeOfCharacter(from: CharacterSet(charactersIn: allowedCharacters).inverted) == nil {
    // Proceed with userInput
} else {
    // Exit immediately
}
```

### Semgrep Rule

```yaml
rule = [{
    "id": "CWE-078",
    "severity": "warning",
    "message": "Possible OS Command Injection detected",
    "pattern": [
        {
            "regexp": "(system|popen|execvp?|spawnvp?|spawnlp?|execlp?|fork|wait|systemf|exec|spawnl|spawnv|execl|spawn)",
            "modifiers": "i",
            "inverse": true
        },
        {
            "regexp": "(.*)(\\s*)(\\S+)(\\s*)\\(",
            "modifiers": "i"
        }
    ]
}]
```

### CodeQL Rule

```ql
import cwe

class CWE_078_OS_Command_Injection:
  // Rule checks for the use of user input in OS commands.
  // A vulnerable line of code may look like this:
  // system("rm -rf " + userInput)
 
  // Declare a query to find the relevant code
  query vulnerableCode {
    decl _userInput as String
    // Find the use of user input in system calls
    SystemCall.withArg(_userInput)
  }
  
  // Report the finding  
  vulnerableCode
  => issue("CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", cwe.CWE_078)
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

SQL injection occurs when an attacker is able to inject malicious SQL code into an application, allowing them to gain access to or modify the underlying database. This can be done by exploiting the dynamic queries used by the application, or by exploiting user input that is not correctly sanitized and validated. By doing so, attackers can bypass authentication, delete or modify data, or even gain access to other systems.

### Vulnerable Code

```swift
let query = "SELECT * FROM users WHERE username = '\(username)'"
let result = try database.executeQuery(query)
```

### Remediation

```swift
// Example of Remediation

// Using Prepared Statements to prevent SQL injection

let statement = "SELECT * FROM User WHERE email = ?"
let email = "user@example.com"

let preparedStatement = try db.prepare(statement)
let queryResults = try preparedStatement.run([email])

for row in queryResults {
    // do something with each row
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects potential SQL injection vulnerabilities"
    id = "CWE-089"
    severity = "WARNING"
  strings:
    $s1 = "SELECT"
    $s2 = "INSERT"
    $s3 = "UPDATE"
    $s4 = "DELETE"
    $s5 = "TRUNCATE"
    $s6 = "EXEC"
    $s7 = "DROP"
  condition:
    ($s1 or $s2 or $s3 or $s4 or $s5 or $s6 or $s7)
}
```

### CodeQL Rule

```ql
import cwe089

class CWE089_SQLInjection:
    def __init__(self):
        self.cwe089_error_message = "Possible SQL injection vulnerability found"

    def CWE089_detect_vulnerability(self):
        vulnerable_query = cwe089.find_vulnerable_query()
        if vulnerable_query:
            cwe089.report_error(self.cwe089_error_message, vulnerable_query)
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal (also known as directory traversal) is a vulnerability that occurs when an attacker uses a relative pathname to gain access to directories outside of the intended directory. This vulnerability is often exploited by malicious actors to gain access to sensitive files and data. For example, a web application could be vulnerable to path traversal if it accepts a user-supplied filename without properly validating it, allowing the user to traverse outside of the intended directory. This could result in the attacker accessing sensitive files, such as system configuration information, or even allowing them to run arbitrary code on the server.

### Vulnerable Code

```swift
let path = "../../../../etc/passwd"
let file = try! Data(contentsOf: URL(fileURLWithPath: path))
```

### Remediation

```swift
// Swift

// Before Remediation
let filePath = "/User/Documents/\(userInput)"

// After Remediation
let filePath = "/User/Documents/\(userInput.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")"
```

### Semgrep Rule

```yaml
rule = {
    meta:
        id = "CWE-022"
        description = "Detects Path Traversal"
        severity = "CRITICAL"
        author = "Semgrep"
    source:
        language = "Swift"
    detection:
        any:
            - pattern: |
                open(_ fname: String, _ mode: String,
                pathContains("..")
            - pattern: |
                NSURL(fileURLWithPath:
                pathContains("..")
}
```

### CodeQL Rule

```ql
// Create the CodeQL query to detect the vulnerability
import cwe022

class PathTraversalVulnerability extends Vulnerability {
    PathTraversalVulnerability() {
        this.cwe = cwe022
    }
    
    // This predicate returns true if the given method takes a file path as parameter
    predicate isFilePath(Method m) {
        exists(Parameter p | m.getParameters().contains(p) and p.getType().isSubtypeOf("String") and p.hasAnnotation("Path"))
    }
    
    // This predicate returns true if the given method sanitizes the file path
    predicate isSanitized(Method m) {
        exists(Call c | c.getTarget().getName() =~ ".*sanit.*" and m.getCalls().contains(c))
    }
    
    // This predicate
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-Site Request Forgery (CSRF) is a type of web security vulnerability that allows an attacker to remotely execute malicious requests on behalf of a legitimate user. In a CSRF attack, a malicious actor tricks a legitimate user into making a request to a vulnerable web application without their knowledge. This type of attack can be used to modify the user’s data, delete data, or even gain access to sensitive information. In the case of Swift, CSRF attacks can be performed by sending a malicious request from a legitimate user's browser that interacts with the vulnerable application. This type of attack is especially dangerous because the malicious request can be sent from the user’s browser without their knowledge or consent.

### Vulnerable Code

```swift
This example of vulnerable code shows an action endpoint that is vulnerable to Cross-Site Request Forgery (CSRF) attacks: 

@IBAction func transferMoney(_ sender: Any) {
    let parameters = ["amount": amountTextField.text ?? "",
                      "recipient": recipientTextField.text ?? ""]
    
    let url = URL(string: "https://example.com/transferMoney")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
 
    // Note: This code is vulnerable to CSRF attack as it does not include any anti-CSRF token
    request.httpBody = parameters.percentEscaped().data(using: .utf8)
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        guard let data = data,
            let
```

### Remediation

```swift
The best way to remediate a Cross-Site Request Forgery (CSRF) vulnerability is to implement a CSRF token. A CSRF token is a unique, secret, unpredictable value that is generated by the server and included in the HTML form or in the URL. When the form or the URL is submitted, the server checks the request to make sure that the CSRF token included in the request is valid. If the token is not valid or is missing, the request is blocked.

Example implementation of CSRF token in Swift:

// Generate a CSRF token
let csrfToken = UUID().uuidString

// Store the CSRF token in the user's session
session[.csrfToken] = csrfToken

// Include the CSRF token in the HTML form
<input type="hidden" name="csrfToken" value="\(csrfToken)" />

// Validate
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects Cross-Site Request Forgery (CSRF)"
        severity = "CRITICAL"
    source:
        lang = "swift"
    patterns:
        - pattern: 
            message: |
                "GET"
            negated: true
        - pattern: 
            message: |
                "POST"
            negated: true
        - pattern:
            message: |
                "PUT"
            negated: true
        - pattern:
            message: |
                "DELETE"
            negated: true
        - pattern:
            message: |
                "PATCH"
            negated: true
        - pattern:
            message: |
                "dataTask(with:)"
            negated: false
        - pattern:
            message: |
                "check
```

### CodeQL Rule

```ql
import cwe352

class CrossSiteRequestForgeryVulnerability:
  // Rule to detect code that is vulnerable to Cross-Site Request Forgery (CSRF)
  CWE352
  {
    // Find any methods that do not have a CSRF token
    // as a parameter or in the body
    method
    {
      // Check that the method does not contain a CSRF token
      not exists(Parameter p | p.hasAnnotation("CSRFToken")) and
      not exists(MethodCall mc | mc.getTarget().hasAnnotation("CSRFToken"))
    }
  }
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability that occurs when an application allows users to upload files without restrictions on the type of file. This can lead to malicious files being uploaded, such as scripts or executable programs, which can be used to compromise the system. Additionally, since unrestricted file uploads can allow for large files to be uploaded, this could cause a denial of service attack by exhausting system resources.

### Vulnerable Code

```swift
let fileURL = Bundle.main.url(forResource: "dangerousFile", withExtension: "exe")
let fileData = try? Data(contentsOf: fileURL!)
let fileName = "dangerousFile.exe"
let uploadPath = "uploads/" + fileName

let fileManager = FileManager.default
try? fileManager.copyItem(atPath: fileURL!.path, toPath: uploadPath)
```

### Remediation

```swift
First, a whitelist of allowed file extensions should be created and enforced. This whitelist should include only safe file types such as .jpg, .txt, .pdf, etc. Any files with an extension not in the whitelist should be blocked from being uploaded.

Additionally, a content type check should be performed when a file is uploaded. This ensures that the file is actually the type of file that the user claims it is. For example, if a user uploads a file with a .jpg extension, the content type should be checked to ensure that it is actually a JPEG image file. If the content type check fails, the file should be rejected.
```

### Semgrep Rule

```yaml
rules:
  - id: unrestricted_upload
    files:
      - '*.swift'
    message: 'Unrestricted Upload of File with Dangerous Type'
    expression: |
      let fileName := /[^/]+\.(?P<extension>[^/\.]+)$/
      let dangerousExtensions := ["exe", "dll", "bat", "sh"]
      fileName.extension in dangerousExtensions
```

### CodeQL Rule

```ql
import cwe
import swift

class UnrestrictedUploadOfDangerousFileType:
 
    // Find any FileUpload functions
    FileUpload = method(m:swift.FunctionDeclaration)
    {
        m.name =~ /.*upload.*/i 
    } 
    
    // Get any file extensions used in the FileUpload function
    FileExtension = FileUpload.body.containsSubstring(pattern:"\\.\\w*$")
 
    // Search for any dangerous file extensions
    DangerousFileExtension = FileExtension.literal.stringValue matches regex "\\.(exe|bat|bin|sh)$"
 
    // Flag any unrestricted upload of dangerous file type
    flag cwe`CWE-434` for DangerousFileExtension

}
```

## CWE-306: Missing Authentication for Critical Function

### Description

This vulnerability occurs when a critical function within an application or system does not require authentication in order to access and manipulate data. Without authentication, any user can access confidential data and make changes to it, which can lead to data corruption, unauthorized access, or even malicious attacks. Additionally, this vulnerability can allow attackers to gain access to sensitive data, such as passwords and financial information.

### Vulnerable Code

```swift
// This code defines a function that allows a user to access restricted resources
func accessRestrictedResources() {
    // The function does not require any authentication
    // The user can access the restricted resources without any authentication
}
```

### Remediation

```swift
One way to remediate CWE-306 is to add an authentication layer to the application. This can be done by implementing an authentication system that requires users to provide a valid username and password before they can access the critical function. The authentication system should also be configured to use the latest security measures, such as two-factor authentication, to ensure the highest level of security. Additionally, the authentication system should be monitored regularly to ensure it is still secure, and any breaches should be addressed quickly.
```

### Semgrep Rule

```yaml
rule = {
    id = "CWE-306-Missing-Authentication-For-Critical-Function",
    patterns = ["if !authenticated()"],
    message = "Missing authentication for critical function", 
    severity = "WARNING"
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.security

class MissingAuthenticationCriticalFunction extends SecurityHardeningChecker {
  public MissingAuthenticationCriticalFunction() {
    super("Missing Authentication for Critical Function");
  }

  @Override
  Prediction canHardeningBeApplied(Cwe cwe, SemmleCode code) {
    // CWE-306 is an authentication issue
    if (cwe != Cwe.CWE_306) {
      return Prediction.NO;
    }
    
    // Check if the function is critical
    if (!code.getFunction().isCritical()) {
      return Prediction.NO;
    }

    // Check if the function is missing authentication
    if (!code.getFunction().isMissingAuthentication()) {
      return Prediction.NO;
    }

    return Prediction.YES;
  }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability that occurs when an application deserializes untrusted data, allowing malicious data to be executed. This can lead to code execution, denial of service, or other malicious actions. The data could be from a file, a database, or from a network connection and can be exploited by an attacker to gain access to sensitive information or cause other malicious actions.

### Vulnerable Code

```swift
let jsonData = Data(bytes: [0x7b, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x22, 0x42, 0x6f, 0x62, 0x22, 0x7d])
let decoder = JSONDecoder()
let user = try decoder.decode(User.self, from: jsonData)

// Vulnerable code
let user = try! decoder.decode(User.self, from: jsonData)
```

### Remediation

```swift
// Before Remediation
let decodedData = try? JSONDecoder().decode(MyData.self, from: data)

// After Remediation
guard let decodedData = try? JSONDecoder().decode(MyData.self, from: data) else {
    throw DeserializationError.invalidData
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-502-Deserialization-of-Untrusted-Data",
  patterns: [
    {
      pattern: "{NSKeyedUnarchiver, NSSecureUnarchiver} unarchiveObjectWithData:",
      languages: ["Swift"]
    }
  ]
}
```

### CodeQL Rule

```ql
import swift

class DeserializationOfUntrustedDataCWE502Rule extends Rule {

  // Rule metadata
  string info = "CWE-502: Deserialization of Untrusted Data";

  // Query for vulnerable code
  query vulnerableQuery {
    // Find calls to methods that deserialize untrusted data
    call as untrustedCall where (
      untrustedCall.name =~ "deserialize.*"
    )
    // Find the source of untrusted data
    source as untrustedSource where (
      untrustedSource.hasAncestor(untrustedCall)
    )
    // Find any of the untrusted sources without explicit validation
    not exists(Validation v | untrustedSource.hasAncestor(v))
  }

  // Report any matches
  protected violation() {
    for (un
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability that occurs when an application fails to properly authenticate users before allowing them access. This can result in unauthorized access to sensitive data or systems, or the ability to perform malicious actions. This can also happen when authentication credentials are not properly validated or stored, allowing attackers to gain access with stolen credentials.

### Vulnerable Code

```swift
let username = "admin"
let password = "password"

if username == "admin" && password == "password" {
    // Allow user access
} else {
    // Deny user access
}
```

### Remediation

```swift
The best way to remediate this type of vulnerability is to ensure that proper authentication measures are put in place. This would include implementing stronger authentication methods such as multi-factor authentication, using secure passwords, and using a secure authentication protocol. Additionally, any authentication processes should be monitored and tested regularly to ensure that they remain secure.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper authentication"
    author = "security expert"
    severity = "critical"
  source:
    lang = "swift"
  included:
    strings:
      - "authentication"
      - "login"
      - "log in"
  detection:
    condition: not strings.login and not strings.log in
}
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthentication: Rule {
  // Find all places where authentication is checked
  predicate isAuthenticationCheck(Expr e) {
    e.hasAncestor(FunctionDecl f) and f.getName() == "authenticate"
  }
  
  // Find all if statements where authentication is checked
  predicate isAuthenticationIfStatement(Expr e) {
    e.hasAncestor(IfStmt ifs) and isAuthenticationCheck(ifs.getCondition())
  }
  
  // Check if the authentication check is incorrect or insufficient
  @Override
  predicate isVulnerable(Expr e) {
    isAuthenticationIfStatement(e) and cwe287.isVulnerable(e.getParent())
  }
  
  @Override
  void check(Expr e) {
    if (
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability where an application uses hard-coded credentials, such as passwords, to authenticate with a system or service. This means that the credentials are stored in the application's code, making them easily accessible to anyone who can view the code. This poses a security risk as these credentials can be used to gain unauthorized access to the system or service.

### Vulnerable Code

```swift
let username = "admin"
let password = "password123"

let authString = "\(username):\(password)"
let authData = authString.data(using: String.Encoding.utf8)!
let authValue = "Basic \(authData.base64EncodedString())"

let headers: [String: String] = [
    "Authorization": authValue
]
```

### Remediation

```swift
// Remediation example

let username = ""
let password = ""

func authenticateUser(username: String, password: String) {
    // Check for hard-coded credentials
    guard username != "admin" && password != "admin" else {
        print("Hard-coded credentials detected")
        return
    }

    // Authenticate user
    // ...
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        id = "CWE-798"
        description = "Detects the use of hard-coded credentials"
        author = "Semgrep"
    source:
        lang = "swift"
    detection:
        passwords:
            regexp: "username=\".*\" password=\".*\""
            message: "Hard-coded credentials detected"
}
```

### CodeQL Rule

```ql
import cwe

class CWE_798_Hardcoded_Credentials:
  vulnerability as cwe.Vulnerability {
  cwe = "CWE-798"
  }

  // Find string literals with the word "password"
  stringLiteral as LiteralString hasValue "password"
 
  // Find assignments from string literals
  assignment as Assignment from stringLiteral
  
  // Find declarations of variables used in assignments
  decl as VariableDecl from assignment
  
  // Find the declarations used in credentials
  credential as VariableDecl from assignment, decl.HasAnnotation("credential")
  
  // Flag any hardcoded credentials
  flag as Report from credential, assignment, stringLiteral, cwe.Vulnerability
  where credential.HasAnnotation("credential") and assignment.ToVariable = credential and stringLiteral.Value
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 is a vulnerability that occurs when default permissions are set incorrectly, allowing unauthorized users to access sensitive data or resources. This vulnerability can be exploited by setting weak or no permissions on files, directories, or other system resources, allowing malicious users to gain access to confidential data or system functionality. For example, if a file is set to 777 (read-write-execute for all users) instead of 644 (read-write for the owner, read for everyone else), an attacker could gain access to that file and modify or delete it.

### Vulnerable Code

```swift
// This code sets the default permissions on a file to world-writeable
let fileURL = URL(fileURLWithPath: "/path/to/file")
let fileManager = FileManager.default
try? fileManager.setAttributes([.posixPermissions: 0o777], ofItemAtPath: fileURL.path)
```

### Remediation

```swift
// Remediate incorrect default permissions on a file

let filePath = "<file path>"
let fileManager = FileManager.default

let fileAttributes = [FileAttributeKey.posixPermissions: 0o755]

do {
    try fileManager.setAttributes(fileAttributes, ofItemAtPath: filePath)
} catch {
    print("Error setting permissions: \(error.localizedDescription)")
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detect incorrect default permissions"
    author = "Your name here"
  source:
    source = "swift"
  detection:
    condition:
      all:
        - pattern:
            regexp: "\\.defaultPermissions\\s*=\\s*\\w*\\(\\s*[^\\)]*\\)"
            modifiers: "s"
        - pattern:
            regexp: "\\w*\\(\\s*[^\\)]*\\)[^\\s]*\\s*\\.\\s*write\\b"
            modifiers: "s"
}
```

### CodeQL Rule

```ql
import cwe
import swift

class IncorrectDefaultPermissionsRule extends Rule {
 
  // Query to detect incorrect default permissions
  query IncorrectDefaultPermissions() {
    // Find all declarations of fields and properties
    FieldDecl | SwiftPropertyDecl(
      // Make sure the fields or properties are not declared with a specific permission
      permission => permission == cwe.Permission.Default
    )
  }
 
  // Report an issue when the query finds an incorrect default permission
  getIssueMessage(FieldDecl fd) {
    return "Field '" + fd.name + "' is declared with incorrect default permissions."
  }
 
  // Report an issue when the query finds an incorrect default permission
  getIssueMessage(SwiftPropertyDecl spd) {
    return "Property '" + spd.name + "' is declared with incorrect default permissions."
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that occurs when sensitive information is exposed to an unauthorized actor. This type of vulnerability can occur when a system does not have proper authentication or access controls in place, allowing unauthorized actors to gain access to sensitive data. This type of vulnerability can also occur when unencrypted data is transmitted across insecure networks or stored in clear text on public-facing systems. In some cases, the information exposed can be used to gain access to other systems or even commit identity theft.

### Vulnerable Code

```swift
let password = "myPassword123"
print(password) // Prints "myPassword123"
```

### Remediation

```swift
Remediation of this vulnerability requires properly encrypting any sensitive information that is being transmitted or stored. Where possible, use industry standard encryption protocols such as TLS/SSL or AES. Additionally, make sure that the encryption keys are protected and stored securely. Finally, ensure that any and all sensitive data is accessed only by authorized users and that access is properly tracked and monitored.
```

### Semgrep Rule

```yaml
rule = [
  id = "CWE-200",
  message = "Possible exposure of sensitive information to an unauthorized actor.",
  expr = "database.query($x) and not ($x in ['SELECT * FROM secure_table'])",
  severity = "error"
]
```

### CodeQL Rule

```ql
import cwe
import swift

class CWE_200_Vulnerability:
    def get_sensitive_data():
        return swift.select("Stmt")
        .where(lambda stmt: 
            stmt.isInstanceOf("Decl") 
            and stmt.hasDescendant("StringLiteral")
        )
        .hasDescendant("Identifier", 
            lambda id: id.hasAnnotation("sensitive")
        )

    def vulnerable_code():
        return get_sensitive_data()
        .where(lambda stmt:
            stmt.hasAncestor("FunctionCall")
            and stmt.parent().isInstanceOf("PropertyWrapperValue")
            and stmt.hasAncestor("ClassDecl")
            and stmt.hasAncestor("StructDecl")
            and stmt.hasAncestor("
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a type of vulnerability that arises when credentials are not sufficiently protected. This type of vulnerability can occur when credentials are stored in plaintext or when access control measures are not in place to prevent unauthorized access to credentials. Additionally, this vulnerability can occur when credentials are transmitted over insecure channels, such as in plaintext over HTTP or FTP. This can leave credentials exposed to potential attackers, who can then gain access to the system or data that the credentials are meant to protect.

### Vulnerable Code

```swift
let username = "admin"
let password = "password123"

// Vulnerable code
let userData = [username: password]
let success = checkUserData(userData)
```

### Remediation

```swift
Remediation for this vulnerability would involve implementing a more secure credential management system. This could include using a secure password manager, using two-factor authentication for authentication and authorization, and using a secure authentication protocol such as OAuth. Additionally, it is important to ensure that all passwords are stored in an encrypted format and that access to these passwords is restricted to only those who need it.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects insufficiently protected credentials"
        severity = "MEDIUM"
        reference = "CWE-522"
    strings:
        $cred1 = "username"
        $cred2 = "password"
        $cred3 = "API key"
    condition:
        any of ($cred*)
}
```

### CodeQL Rule

```ql
import swift

class InsufficientlyProtectedCredentials: CodeQLAnalysis {
  predicate isCredentialAccess() {
    exists(
      Variable v,
      MethodAccess ma,
      Assignment a |
        a.getAssignedValue() = v 
        and ma.getMethod() = v 
        and ma.getType() = "credential"
    )
  }
  
  predicate isCredentialStoredInString() {
    exists(
      Variable v,
      Assignment a |
        a.getAssignedValue() = v 
        and v.isString()
    )
  }

  predicate isCredentialStoredInPlainText() {
    isCredentialAccess() and isCredentialStoredInString()
  }

  query insufficientlyProtectedCredential() {
    isC
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability that occurs when an XML document includes an external entity reference in an unsafe manner. This allows malicious actors to access data stored in external locations, or to execute arbitrary code on the vulnerable system. This can be exploited by an attacker sending crafted XML requests to a vulnerable system, which can then be used to gain unauthorized access to sensitive data or execute malicious code.

### Vulnerable Code

```swift
let xmlData = "<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE foo [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]> 
<results> 
  &xxe; 
</results>"

let xmlDoc = try? XMLDocument(xmlString: xmlData, options: .documentTidyXML)
```

### Remediation

```swift
In Swift, it is possible to prevent XML external entity references by using the NSXMLParser class’s setShouldProcessExternalEntities method. This method should be set to false, which will disable the processing of external entities.

For example, the following code snippet shows how to use the setShouldProcessExternalEntities method to disable external entity processing for an NSXMLParser instance:

let parser = NSXMLParser(data: data)
parser.setShouldProcessExternalEntities(false)
```

### Semgrep Rule

```yaml
description: Detect improper restriction of XML external entity reference

codesnippet: /\bXMLParser\b/

severity: warning

conditions:

- pattern: '!doctype\s+\w+\s*\[\s*(\s*<\s*!\s*entity\s+\w+\s*system\s+[^>]+>\s*)+'
message: "This XML document contains an improper restriction of XML external entity reference."
```

### CodeQL Rule

```ql
import cwe
import swift

class VulnCWE611 : CWE611

{
  // create a query to find instances of XML external entity references
  // that have not been restricted
  // this includes uses of the URL loading system

  // find XML documents that have been parsed and loaded
  // using the URL loading system
  query xmlLoadedFromURL(){
    let url = URL.init()
    let xmlDoc = Document.init(contentsOf: url)
    XMLDocument.parse(contentsOf: xmlDoc)
  }
  
  // find references to external entities that are not properly
  // restricted
  query externalReference(){
    // find references to external entities
    XMLNode.referencesExternalEntities()
    // find any reference that is not properly restricted
    XMLNode.referencesExternalEntities() 
    and not External
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-side request forgery (SSRF) is a type of web application vulnerability that allows an attacker to send malicious requests from a vulnerable server to other systems or services. This type of attack can be used to gain access to private networks, sensitive data, or other restricted resources. In Swift, an SSRF vulnerability can occur if an application allows user-supplied input to be used as part of a URL, and does not properly validate the input. This can allow an attacker to send malicious requests from the vulnerable server to other systems or services, potentially bypassing access control mechanisms.

### Vulnerable Code

```swift
let urlString = "http://[attacker controlled server]:8080"
let url = URL(string: urlString)
let request = URLRequest(url: url!)
let task = URLSession.shared.dataTask(with: request) { data, response, error in
    // Handle Response
}
task.resume()
```

### Remediation

```swift
One way to remediate CWE-918 is to use a whitelist of allowed URLs or IP addresses when making requests from the server. This way, requests from malicious sources can be blocked from reaching the server. The following example in Swift shows how to create a whitelist of allowed IP addresses for making requests:

let allowedIPs = ["127.0.0.1","192.168.1.1"]

let request = URLRequest(url: URL(string: "https://example.com"))

if let remoteIP = request.remoteIP(), allowedIPs.contains(remoteIP) {
    // Make request
} else {
    // Block request
}
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-918-ssrf-detection"
  patterns: [
    {
      pattern: 'URL(url:|.init|.init(string:)?|.absoluteString)? *?(=|==|<|>) *?(URL(Components|QueryItem)?|URLComponents|String|["']{1}http)',
      message: "Potential Server-Side Request Forgery (SSRF) vulnerability detected.",
      severity: "WARNING"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe918

class CWE918Rule extends Rule {

  // Checks for server-side request forgery issues
  CWE918Pattern
    = classDeclaration(name:"*")
    & methodDeclaration(name: "*")
    & callExpression(callee: memberAccess(property: "url"))
    &+ callExpression(callee: memberAccess(property: "open"));

  // Checks for user input being used to construct a URL
  CWE918UserInput
    = classDeclaration(name:"*")
    & methodDeclaration(name: "*")
    & callExpression(
        callee: memberAccess(property: "stringByAddingPercentEncodingWithAllowedCharacters"),
        arguments: contains(stringLiteral())
    )
    &+ callExpression(callee: member
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of security vulnerability that occurs when an attacker is able to inject malicious commands into an application or system. This occurs when user input is not properly sanitized or validated, allowing an attacker to execute system commands, malicious code, or other malicious actions on the underlying system. In Swift, this vulnerability can manifest itself when user input is used to form a system command, such as using a string to create a system call or using an input parameter in a call to a library function that uses the input as a command.

### Vulnerable Code

```swift
let input = "cat /etc/passwd";
let command = "sh -c \"" + input + "\"";
system(command);
```

### Remediation

```swift
The following code snippet illustrates how an application can perform proper input sanitation to prevent command injection attacks. 

func validateInput(input: String) -> Bool {
    let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    return input.rangeOfCharacter(from: allowedCharacters.inverted) == nil
}
```

### Semgrep Rule

```yaml
rule = {
    strings:
    $cmd = /.*/
    condition: $cmd
}
```

### CodeQL Rule

```ql
import swift

class CommandInjectionVulnerability: Vulnerability {
  // The source of the vulnerability
  // should be the injection of user-controlled 
  // data into a system call.
  //
  // The vulnerability is detected when a user-controlled
  // string is used as part of a command without
  // proper sanitization.
  //
  // Sanitization should include removing metacharacters,
  // like "<>&;, and escaping quotes.
  //
  // In Swift, use of the Process class to spawn
  // subprocesses is the most likely source of this
  // vulnerability.
 
  // Find all calls to Process.launch
  // that do not use proper sanitization.
  //
  // Note: This rule is a basic proof-of-concept and
  // should be further refined.
 
  //
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295 is a vulnerability where an application fails to properly validate an SSL/TLS certificate presented by a remote server. This can allow an attacker to intercept and potentially modify traffic between the affected application and the remote server, potentially allowing them to gain access to sensitive data or perform malicious actions. In Swift, this vulnerability can be introduced when developers fail to properly validate the server certificate, usually by not verifying the chain of trust or the certificate's expiration date.

### Vulnerable Code

```swift
let url = URL(string: "https://example.com")!
let session = URLSession(configuration: .default)
let task = session.dataTask(with: url) { data, response, error in
    if let error = error {
        // Handle error
    }

    guard let data = data,
        let response = response as? HTTPURLResponse,
        (200 ..< 300) ~= response.statusCode
    else {
        // Handle error
    }

    // The code below is vulnerable to CWE-295
    let serverTrustPolicy = ServerTrustPolicy.disableEvaluation
    let serverTrustPolicies = [url.host!: serverTrustPolicy]
    let serverTrustManager = ServerTrustManager(policies: serverTrustPolicies)
    let session = URLSession(configuration: .default, serverTrustManager: server
```

### Remediation

```swift
// Remediation:
guard let serverTrust = challenge.protectionSpace.serverTrust else {
    completionHandler(.cancelAuthenticationChallenge, nil)
    return
}

let policies: [SecPolicy] = [SecPolicyCreateSSL(true, serverTrust.host as CFString)]
let trust = SecTrustCreateWithPolicies(serverTrust, policies as CFTypeRef, nil)
let result = SecTrustEvaluateWithError(trust!, nil)

if result == errSecSuccess || result == errSecTrustResultUnspecified {
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
} else {
    completionHandler(.cancelAuthenticationChallenge, nil)
}
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-295-Improper-Certificate-Validation
    severity: warning
    patterns:
      - pattern: 'URLRequest(url: .*?, settings: .*?, validatesSecureCertificate: false)'
        message: 'The application is using an invalid or untrusted certificate with URLRequest'
        contexts:
          - call: URLRequest(url: .*?, settings: .*?, validatesSecureCertificate: false)
```

### CodeQL Rule

```ql
import cwe
import Swift

class ImproperCertificateValidation: CodeQLSecurityVulnerability {
  override func vulnerableCodePatterns() -> [CodeQLSecurityVulnerability.VulnerableCodePattern] {
    let pattern = VulnerableCodePattern(language: .swift) {
      // Pattern to detect code that could be vulnerable to CWE-295
      // Improper Certificate Validation
      BinaryOperation("==", 
        FunctionCall("URL", any()),
        FunctionCall("URL", any()))
    }
    return [pattern]
  }
}
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability in which an attacker is able to inject malicious code into an application. This type of vulnerability is particularly dangerous because the malicious code can be executed with the same privileges as the application and can lead to data theft, data destruction, or other malicious activities. In Swift, this vulnerability can occur when user input is not properly validated, allowing an attacker to inject malicious code into an application. If this malicious code is then executed, the attacker can gain access to sensitive information, or cause other malicious activities.

### Vulnerable Code

```swift
//In this code, userInput is taken from an untrusted source
let userInput = getUntrustedUserInput()
let command = "echo \(userInput)"
system(command) //This line allows for code injection attacks if user input is not properly validated
```

### Remediation

```swift
// Remediation Example

// Prevent unsanitized user input from being used in code
let userInput = readLine()
let sanitizedInput = userInput.trimmingCharacters(in: .whitespacesAndNewlines)
let codeToExecute = "print(\(sanitizedInput))"

if let result = try? NSExpression(format: codeToExecute) {
    let evaluatedExpression = result.expressionValue(with: nil, context: nil)
    
    if let evaluatedValue = evaluatedExpression as? String {
        print(evaluatedValue)
    } else {
        print("Invalid input")
    }
} else {
    print("Invalid input")
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      author = "your_name"
      description = "detects improper control of generation of code"
      risk = "high"
    source:
      languages = ["swift"]
    detection:
      condition:
        all:
          - pattern:
              regexp: "\s*(eval|exec)\s*\("
              message: "Improper control of code generation detected."
}
```

### CodeQL Rule

```ql
import cwe094

class CWE094CodeInjectionDetector extends Rule {

    // Find initialization of strings from external sources
    // such as user input or files
    private pattern userInputStrings :=
        // `let` is used to initialize a string from user input
        let _ = StrLiteral.from(_)

        // `String(contentsOf:)` is used to initialize a string from a file
        | String(_) <- contentsOf(_)

    // Find initialization of any type from external sources
    // such as user input or files
    private pattern userInputAny :=
        // `init()` is used to initialize any type from user input
        init(_)

        // `decode()` is used to initialize any type from a file
        | decode(_) <- contentsOf(_)

    // Find code which is executed from the string initialized from
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 is a type of vulnerability where an application or system fails to properly manage users' privileges, allowing users to gain access to resources or functions that they should not be able to access. This could include granting a user administrative privileges when they should only have access to limited resources, or allowing a user to access sensitive data that should remain confidential. It can also include granting privileges to malicious or unauthorized users.

### Vulnerable Code

```swift
let fileManager = FileManager.default
let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
let fileURL = documentsDirectory?.appendingPathComponent("file.txt")

//Write to the file
let data = Data(...)
try? data.write(to: fileURL)

//Set the file to be publicly readable
try? fileManager.setAttributes([.posixPermissions: 0o777], ofItemAtPath: fileURL!.path)
```

### Remediation

```swift
To remediate this vulnerability, a code change should be made that ensures the application is granting privileged access only to those users who have been authorized to access it. This can be done by implementing role-based access control (RBAC) system that clearly defines what access and privileges each user/role has. Additionally, the application should be configured to log all access attempts and activities, so that any suspicious activities can be identified and investigated.
```

### Semgrep Rule

```yaml
rules:
  - id: Improper_Privilege_Management
    message: "Improper privilege management detected"
    severity: warning
    patterns:
      - pattern: "if (let |var )?(?<privilege>[A-Za-z]+) = .*?.authorization(For|Status)((For|From|To)Item)?\\(([A-Za-z]+\\s+)?(?<item>[A-Za-z]+)"
        filters:
          - $privilege != $item
```

### CodeQL Rule

```ql
import cwe269

class CWE269ImproperPrivilegeManagement: CodeQL.Vulnerability {
  provider CWE269

  // find functions that set privileges
  let setPrivileges =
    CallGraph.nodes(
      Function(
        name: /[sS]et[Pp]rivileges/,
        type: /void\s*\(\s*\)\s*$/
      )
    )

  // find functions that set privileges without checking the privilege level
  let setNoCheck =
    setPrivileges.select(
      CallGraph.calls(
        Function(
          name: /[cC]heck[Pp]rivileges/,
          type: /void\s*\(\s*\)\s*$/
        )
      ).not
    )

  // flag any calls to the functions that
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

Expression Language Injection is a type of vulnerability that occurs when user-supplied inputs are used to construct an expression language statement without proper neutralization. In Swift, this can occur when user-supplied values are used to create a string without proper sanitization. This can allow malicious code to be injected in the application, potentially leading to privilege escalation, data leakage, or other malicious activities.

### Vulnerable Code

```swift
let userInput = "{{userInput}}"
let sqlQuery = "SELECT * FROM users WHERE username = '\(userInput)'"

// The code above is vulnerable to Expression Language Injection, since userInput is not properly sanitized before being used in the SQL query. An attacker could craft a malicious input, such as ' OR ''=' to return all rows from the users table.
```

### Remediation

```swift
//Remediation Example
let inputString = "userInput"

//Sanitize user input
let sanitizedInput = inputString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)

//Use the sanitized input for expression language statement
let expressionLanguageStatement = "MyExpressionLanguageStatement \(sanitizedInput)"
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects potential Expression Language Injection vulnerabilities in Swift code"
      author = "Semgrep"
      id = "S1001"
      references = ["https://cwe.mitre.org/data/definitions/917.html"]
    strings:
     $unsafe_string1 = "\\$\\{"
     $unsafe_string2 = "\\}"
    condition: 
      all of them
}
```

### CodeQL Rule

```ql
import swift

class ExpressionLanguageInjectionRule extends Audit.Rule {
 
  // Define the query to detect the vulnerability
  // Search for 'stringByEvaluatingJavaScriptFromString' which is used to evaluate an expression language statement
  // Check for any user-controlled input passed as an argument
  // If the user-controlled input is not properly sanitized, the app is vulnerable to expression language injection
 
  meta.severity = Audit.Severity.High
 
  predicate isExpressionLanguageInjectionVulnerable(call: Call) {
    exists(call.target.accessibility == swift.staticAccessibility.public &&
           call.target.belongsTo("String") &&
           call.name == "stringByEvaluatingJavaScriptFromString(_:)" &&
           exists(callArgument: Expr, call.arguments[0] |
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability related to improper link resolution before file access (also known as "link following"). This vulnerability occurs when a program follows a link to a file without properly verifying the target of the link. This can lead to a malicious file being opened or executed, resulting in a security breach. In order to prevent this type of attack, developers must ensure that all links are validated before they are followed. This can be done by using the proper APIs or using checksums to verify the integrity of linked files.

### Vulnerable Code

```swift
let filePath = "../../MyFile.txt"
let fileURL = URL(fileURLWithPath: filePath)
let fileContents = try String(contentsOf: fileURL)
```

### Remediation

```swift
// Before
let fileName = "example.txt"
let filePath = "Documents/\(fileName)"

// After
let fileName = "example.txt"
let filePath = NSURL(fileURLWithPath: "Documents/\(fileName)").standardizedFileURL.absoluteString
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "CWE-059: Improper Link Resolution Before File Access ('Link Following')"
    severity = "WARNING"
  strings:
    $path = /\.\/[^/]*/
    $dynamic_path = /\$\{[^\}]*\}/
  condition:
    allof them
}
```

### CodeQL Rule

```ql
import cwe059

class CWE059_ImproperLinkResolutionBeforeFileAccessRule extends Rule {
  // Rule to detect improper link resolution before file access
 
  Query fileAccessQry() {
    // Queries for all file access operations
    FileAccess[]
  }
  
  Query linkResolutionQry(FileAccess fa) {
    // Queries for all link resolution operations from the file access operations
    FileAccess[] = fa.getLinkResolvedFiles()
  }
  
  @Override
  public boolean isVulnerable(Query q) {
    // Checks if any link resolution operations have been performed before any file access operations
    return q.exists(fileAccessQry(),
                    fa | linkResolutionQry(fa) not empty)
  }
}
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information, such as passwords, credit card numbers, or other personal information, is transmitted in plaintext, rather than being encrypted. This means that any malicious actor who is able to intercept the data could read it and misuse it. Furthermore, it also means that the data is vulnerable to attack from man-in-the-middle attacks, as the malicious actor could modify the data before it is sent to its destination.

### Vulnerable Code

```swift
let data = "sensitive_data"
let url = URL(string: "http://example.com/senddata")!
var request = URLRequest(url: url)
request.httpMethod = "POST"
request.httpBody = data.data(using: .utf8)
URLSession.shared.dataTask(with: request) { data, response, error in
    if let error = error {
        // Handle error
    }
    if let response = response {
        // Handle response
    }
}.resume()

The vulnerable code in this example is the lack of encryption when sending sensitive data over the network. Instead of using a secure protocol such as HTTPS, the data is sent in cleartext, which can be intercepted by malicious actors. To fix this vulnerability, the code should be modified to use an encrypted protocol such as HTTPS:

let data = "sensitive_data"
```

### Remediation

```swift
// Remediation
let apiURL = "https://example.com"
let urlRequest = URLRequest(url: URL(string: apiURL)!)
urlRequest.httpShouldHandleCookies = false
let sessionConfiguration = URLSessionConfiguration.default
sessionConfiguration.httpShouldSetCookies = false
sessionConfiguration.httpCookieAcceptPolicy = .never
sessionConfiguration.allowsCellularAccess = false
sessionConfiguration.protocolClasses = [MyCustomUrlProtocol.self]
let urlSession = URLSession(configuration: sessionConfiguration)
urlSession.dataTask(with: urlRequest) { (data, response, error) in
    // handle response
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects cleartext transmission of sensitive information"
    author = "Security Team"
    date = "2020-08-01"
  strings:
    $sensitive = /(password|credential|key)/i
  condition:
    any of them
}
```

### CodeQL Rule

```ql
import cwe319
import swift

class CWE319_Cleartext_Transmission_of_Sensitive_Information:
 
  // Finds calls to functions that could transmit sensitive information in cleartext
  @Rule()
  def cwe_319_cleartext_transmission_of_sensitive_information(func: Function):
      conn := func.calls(
          swift.func("NSURLConnection.sendSynchronousRequest(_:returningResponse:)",
              "Foundation", "NSURLConnection"),
          swift.func("NSURLConnection.connectionWithRequest(_:delegate:)",
              "Foundation", "NSURLConnection")
      )
      if conn {
          cwe319.reportCleartextTransmission(conn)
      }
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 is a type of security vulnerability that occurs when a web application or server redirects a user to an untrusted or malicious website. This can occur when a user clicks on a malicious link or is tricked into entering a malicious URL into the address bar. The malicious website can then be used to steal information or inject malicious code into the user's device. In Swift, this vulnerability can be found when developers use an unvalidated external source for redirecting users, such as a malicious URL.

### Vulnerable Code

```swift
// This code snippet is vulnerable to an open redirect vulnerability.

let urlString = "http://evil.example.com/?redirect=" + request.queryString["url"]
UIApplication.shared.open(URL(string: urlString)!, options: [:], completionHandler: nil)
```

### Remediation

```swift
// Before
func redirectToURL(_ url: String) {
    let redirectURL = url
    if let url = URL(string: redirectURL) {
        UIApplication.shared.open(url)
    }
}

// After
func redirectToURL(_ url: String) {
    let allowedRedirectURLs = [
        "https://example.com/ok-redirect"
    ]
    
    if allowedRedirectURLs.contains(url) {
        if let url = URL(string: url) {
            UIApplication.shared.open(url)
        }
    }
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects open redirects"
    author = "semgrep"
  strings:
    $s1 = /.*redirect_to.*/
    $s2 = /.*http.*/
  condition:
    $s1 and $s2
}
```

### CodeQL Rule

```ql
import cwe601

class OpenRedirect:
  // Detects attempts to perform an open redirect
  // using a URL with a user-controlled parameter
  // as the target
 
  // Find all URL objects
  QueryURLObjects() {
    URLObject
  }
  
  // Find all URL objects with a user-controlled parameter as the target
  QueryTargetURLs() {
    URLObject[parameter != ""]
  }
  
  // Find all locations where the target URL is used to perform a redirect
  QueryRedirectLocations() {
    // Find all function calls to the URL
    let call = OpenRedirect.QueryTargetURLs().HasFunctionCall()
    // Find all locations that use the URL as the target of a redirect
    call.FindLocations(Redirect.To(call.GetTarget()))
  }
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a type of vulnerability where sensitive information is inadvertently logged by a system or application. This could be information such as passwords, credit card numbers, or any other type of confidential data. This could occur if a system is configured to log any data that is input into the system, but fails to take into account the possibility of sensitive data being logged. The logging of such information can put both the system and its users at risk, as the confidential data can be accessed by unauthorized users.

### Vulnerable Code

```swift
let userInput = "password123"

// Log user input
print("User input: \(userInput)")
```

### Remediation

```swift
// Remediation

func logSensitiveData(sensitiveData: Any) {
    // Don't log sensitive information
    print("Sensitive data not logged")
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects insertion of sensitive information into log files"
        severity = "high"
    strings:
        $logs = /.*/(log|LOG|Log).*/
        $sensitive_data = /.*(password|credit card number|social security number|date of birth).*/
    condition:
        $logs and $sensitive_data
}
```

### CodeQL Rule

```ql
import cwe

class CWE_532_Log_File_Sensitivity : SecurityCodeScanRule {
 
  // Rule metadata
  meta.ruleName = "CWE-532 Log File Sensitivity"
  meta.description = "Detects the insertion of sensitive information into log files."
  meta.rationale = cwe.cwe_532_log_file_sensitivity_rationale
  meta.type = "cwe"
 
  // Query
  // The query looks for log functions that take in sensitive information.
  query log_file_sensitivity_query {
    // Look for usages of logging functions
    LogFunc = LogFunction()
    // Look for sensitive information being passed as an argument to the logging functions
    SensitiveArgument = Identifier(LogFunc.parameter.name == "sensitiveData")
    // Report the
```


# Kotlin

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

CWE-079, also known as Cross-site Scripting (XSS), is a vulnerability in which malicious code is inserted into an application or website. This malicious code can be used to gain unauthorized access to user data and other sensitive information. In a web page, the vulnerability occurs when user input is not properly validated or escaped, allowing an attacker to inject malicious code into the web page which is then executed by the user's browser. This can be used to gain access to the user's session or to perform other malicious actions.

### Vulnerable Code

```kotlin
val userInput = request.getParameter("userInput")

response.writer.println("<html>")
response.writer.println("<body>")
response.writer.println("Hello " + userInput + "!")
response.writer.println("</body>")
response.writer.println("</html>")

This code is vulnerable to cross-site scripting attacks as it is directly displaying user input into the HTML response without any sanitization. An attacker can inject malicious code into the userInput variable which could be executed on the user's browser.
```

### Remediation

```kotlin
One way to remediate CWE-079 is to use an input validation library such as OWASP ESAPI (Enterprise Security API). This library provides a set of functions that can be used to validate user input and perform proper encoding to prevent cross-site scripting attacks.

For example, the following code will validate an input string:

// Validate the input string
val validatedString = ESAPI.validator().getValidInput("inputString", inputString, "SafeString", 200, false);

// Encode the validated string
val encodedString = ESAPI.encoder().encodeForHTML(validatedString);

// Output the encoded string
println(encodedString);
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: `
        /<.*?(?:(?:on(?:[a-z]+)\\s*?=\\s*?\\"(?:[^\\"]*?(?:\\${sep}|\\\")[^\\"]*?)*?\\")/
      `,
      message: "Possible Cross-site Scripting (CWE-079) vulnerability detected.",
      severity: "CRITICAL",
    },
  ],
  sep: "\\s*?(?:;|&|\\?|#)?\\s*?",
}
```

### CodeQL Rule

```ql
import cwe79

class CWE079CrossSiteScriptingRule extends Rule {
  // Query looking for strings being inserted directly into the response
  // without passing through any kind of sanitation
  query unsafeStringInsertion() {
    // Find all calls to Response.outputStream.write()
    CallExpr writeCall | Response.outputStream.write(_) => writeCall

    // Find any parameters passed to the write call that are strings
    PatternArgument stringArg <- writeCall.arguments
    Literal stringLiteral <- stringArg.value
    string literalType = typeOf(stringLiteral)
    string literalValue = valueOf(stringLiteral)
    string literalText = textOf(stringLiteral)
    string literalKind = kindOf(stringLiteral)
   
    // Check that the string is not a sanitized input
    //
```

## CWE-020: Improper Input Validation

### Description

CWE-020, Improper Input Validation, occurs when an application fails to properly validate user input. This can lead to malicious code injection, buffer overflows, and other security issues. In Kotlin, improper input validation can be caused by accepting untrusted data without validation, or allowing malicious code to be executed on the user's machine. To prevent this vulnerability from occurring, user input should be checked for malicious code and any suspicious behavior should be blocked.

### Vulnerable Code

```kotlin
fun validateInput(input: String): Boolean {
    if (input.length > 10) {
        return true
    }
    return false
}
```

### Remediation

```kotlin
A simple way to remediate a CWE-020 vulnerability is to use input validation. An example of this in Kotlin would be to check the user's input against a set of valid strings before allowing it to be used:

// Define a set of valid strings
val validStrings = setOf("valid1", "valid2", "valid3")

// Get the user's input
val userInput = readLine()

// Validate the input
if (userInput in validStrings) {
    // Do something with the valid input
} else {
    // Throw an error if the input is not valid
    throw IllegalArgumentException("Input is not valid")
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Improper Input Validation" 
    author = "MyName"
    date = "2020-09-30"
    severity = "WARNING"
    id = "RULE1"
  strings:
    $ = "*"
  condition:
    all of them
}
```

### CodeQL Rule

```ql
import cwe020

class Vulnerability_CWE_020 : SecurityFeature{
	
	// Rule to detect improper input validation
	// This rule is triggered when a function takes in user input without any validation
	
	predicate isUserInputFunc(Func func) {
		exists(Parameter param, Expr userInput | 
			param.getFunction() == func &&
			userInput instanceof Variable &&
			userInput.getOrigin() == Origin.USER_INPUT
		)
	}
	
	// This rule is triggered when a function takes in user input without any sanitization
	
	predicate isUserInputSanitizedFunc(Func func) {
		exists(Sanitize sanitize, Expr userInput | 
			sanitize.getFunction() == func &&
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of vulnerability that occurs when user-supplied data is not correctly sanitized before being used in an OS command. This allows attackers to inject malicious commands into the system, allowing them to execute arbitrary code and potentially gain access to sensitive data. This vulnerability can be exploited by malicious actors to gain control of a system, compromise data, or execute malicious code. An example of this vulnerability in Kotlin might be a web application that allows users to input a command line argument into a form, the application then uses this user input to execute the command without properly sanitizing the input, thus allowing attackers to inject malicious code into the system.

### Vulnerable Code

```kotlin
fun executeCommand(command: String) {
    val process = Runtime.getRuntime().exec(command)
    process.waitFor()
    println("Command executed!")
}

// Vulnerable code
executeCommand(request.queryParams("command"))
```

### Remediation

```kotlin
// Sanitize user input to ensure it is safe to use in a system command 
fun sanitizeInput(input: String): String {
    // Replace any characters that could be used to execute system commands with an empty string
    return input.replace(Regex("[;&|<>()$\\\"' ]"), "")
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects when vulnerable parameters are passed to the underlying OS command"
    authors = ["Your Name Here"]
  source:
    include = ["**/*.kt"]
  detection:
    patterns:
      - pattern: |
          Runtime.getRuntime().exec("$PARAMETER")
        message: "Possible OS command injection vulnerability detected"
        severity: WARNING
        identifiers:
          PARAMETER:
            type: parameter
            encodings: [base64, hex]
            locations: [arguments]
}
```

### CodeQL Rule

```ql
import cwe078

class CWE078_Rule extends Rule {
 
  // Finds functions that execute OS commands
  // where the command is formed using user-provided data
  query commandExecution() {
    ExecuteCommand | ExecuteProgram
    // Finds commands where user-provided data is used to form the command
    where exists (DataFlow::DataSource ds | ds.hasOrigin("USER_INPUT"))
  }
 
  // Finds functions that execute OS commands
  // where the command is formed using user-provided data
  // and does not properly neutralize the user-provided data
  query vulnerableCommandExecution() {
    ExecuteCommand | ExecuteProgram vulnCommand
    where exists(DataFlow::DataSource ds | 
		ds.hasOrigin("USER_INPUT") and
		not cwe07
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') is a vulnerability which occurs when user input is not properly sanitized before it is used in an SQL query. This can allow attackers to inject malicious code into the query, which can be used to access and modify the underlying data, or even execute arbitrary commands on the system. Additionally, this vulnerability can be used to bypass authentication mechanisms, gain access to sensitive data, and even allow attackers to gain full control of the system.

### Vulnerable Code

```kotlin
val query = "SELECT * FROM users WHERE name='$userName' AND password='$password'"
val result = statement.executeQuery(query)
```

### Remediation

```kotlin
// Before
val queryString = "SELECT * FROM table WHERE id = $userId"

// After
val queryString = "SELECT * FROM table WHERE id = ?"
val statement = connection.prepareStatement(queryString)
statement.setInt(1, userId)
val result = statement.executeQuery()
```

### Semgrep Rule

```yaml
rule = {
  id      : "CWE-089-SQL-Injection",
  pattern : "\"$SQL_COMMAND$\"",
  message : "Possible SQL Injection detected.",
  mark    : true
  references : ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

### CodeQL Rule

```ql
import cwe089

class CWE089Rule extends SecurityRule {
  // Rule to detect injection of user-controlled data into an SQL query
  // without proper sanitization
  override fun getCweId() = cwe089.CWE_089

  override fun getDescription() =
      "Detects injection of user-controlled data into an SQL query without proper sanitization"

  override fun getInterestingNodes() = listOf(
    Query.pattern(
      // Match an SQL query with user-controlled data
      // without proper sanitization
      // e.g. query("SELECT * FROM users WHERE name = '$name'")
      pattern {
        Query(
          stringLiteral(
            anyOf(
              // Match unescaped single quotes
              containsString("'"),
              // Match interpolated variables
              containsString("$")
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal is a type of security vulnerability that occurs when an attacker is able to access files and directories that are outside the intended directory through manipulating the path variables. This can be done by using relative path traversal such as "../../../../etc/password" or absolute path traversal such as "/etc/password". With this vulnerability, attackers can gain access to sensitive information or perform malicious activities.

### Vulnerable Code

```kotlin
val fileName = request.getParameter("file")
val file = File("./files/$fileName")
// ...
try {
    file.readText()
} catch (e: FileNotFoundException) {
    // Handle error
}
```

### Remediation

```kotlin
// Before
val directoryPath = request.param("path")
val file = File(directoryPath)

// After
val directoryPath = request.param("path")
val file = File(directoryPath.replace("..", "")) // replace any occurrences of ".." with blank string, so no directory can be traversed outside of the allowed directory
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: "File(.*?)\.get(.*?)\(.*?(?:'|\")(.*?)(?:'|\")",
      message: "Potential path traversal vulnerability detected",
      metadata: {
        severity: "CRITICAL"
      }
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe022
import kotlin

class CWE022Detector : Rule {
  // Get all function calls that take a file path as a parameter
  // and check if the parameter is a constant string
  // (which is a security risk)
  getFunctionCalls(pattern:
    kotlin.FunctionCall(
      pattern: "java.io.File.<init>",
      parameters: kotlin.StringLiteral(_) 
    )
  ) {
    // Report the vulnerability
    report(CWE022, functionCall)
  }
}
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site request forgery (CSRF) is a type of attack that occurs when a malicious website, email, or blog causes a user’s web browser to perform an unwanted action on a trusted website for which the user is currently authenticated. This vulnerability can be exploited by a malicious attacker to perform any type of action that the user is allowed to perform on the website, such as transferring funds, changing passwords, and other sensitive activities.

Explain how the vulnerability can be prevented:

To prevent cross-site request forgery (CSRF) attacks, developers should implement a server-side protection mechanism that verifies the origin of the request. This can be done by generating a unique token for each request, and ensuring that the token is sent back with the response to validate the request's origin. Additionally, developers should use secure HTTP headers, such as X-Frame-Options and Content-Security-Policy, to prevent the browser from sending malicious requests.

### Vulnerable Code

```kotlin
fun handleRequest(request: HttpServletRequest) {
    val userId = request.getParameter("userId")
    val action = request.getParameter("action")

    // If the userId and action are not provided, the request is invalid
    if (userId == null || action == null) {
        return
    }

    // Perform the requested action
    performAction(userId, action)
}

// This function performs the action requested in the handleRequest() function
fun performAction(userId: String, action: String) {
    when (action) {
        "deleteAccount" -> deleteAccount(userId)
        "changePassword" -> changePassword(userId)
        "postMessage" -> postMessage(userId)
    }
}

The code above is vulnerable to CSRF because it does not check if the request is a valid
```

### Remediation

```kotlin
// Create a CSRF token
val csrfToken = UUID.randomUUID().toString()

// Store the token in the user session
request.session.setAttribute("csrfToken", csrfToken)

// Add the token as a request header
request.addHeader("X-CSRF-Token", csrfToken)

// Validate the token on the server-side for every POST request
if (request.getMethod() == "POST" && 
    request.getHeader("X-CSRF-Token") != request.session.getAttribute("csrfToken")) {
    response.status = 403
    response.sendError(403, "Invalid CSRF Token")
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      author = "MyName"
      description = "Detects Cross-Site Request Forgery (CSRF) vulnerabilities"
      risk = "high"
    source:
      lang = "kotlin"
    strings:
      $form = "POST"
      $token = /\*CSRF TOKEN\*/
    condition:
      $form @[-3] and $token @[-2]
}
```

### CodeQL Rule

```ql
import cwe352

class CSRFVulnerability(Vulnerability):
    let description = "Cross-Site Request Forgery (CSRF) Vulnerability"
    let severity = "High"

    // Find calls to methods that can cause CSRF
    // such as those that modify state
    vuln_methods = method.select(m |
        m.name in ["PUT", "POST", "DELETE", 
                   "UPDATE", "INSERT"]
    )

    // Look for calls to these methods that lack appropriate
    // CSRF protection
    vuln_sites = vuln_methods.select(m |
        not m.ancestorOrSelf().hasDescendant(
            cwe352.antiCSRF()
        )
    )

    // Report any calls to vulnerable methods
    // without CSRF protection
    vuln_sites.report()
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability which occurs when an application allows unrestricted upload of files with dangerous types. This vulnerability can be exploited by an attacker to upload malicious files to the server, which can then be used to execute arbitrary code and compromise the system. These dangerous file types can include executables, scripts, and other malicious payloads. By allowing unrestricted upload of these types of files, the application may be vulnerable to a wide range of attacks.

### Vulnerable Code

```kotlin
val file = File("/uploads/user.php")
val filePath = file.absolutePath
val name = filePath.substringAfterLast("/")
val uploadDir = File("/uploads")

// Unrestricted upload of file with potential dangerous type
if (!uploadDir.exists()) {
    uploadDir.mkdirs()
}

file.copyTo(File(uploadDir, name), true)
```

### Remediation

```kotlin
// Validate the file type before accepting the upload
val allowedTypes = arrayOf("jpg", "png", "gif", "pdf", "txt")

fun validateFileType(fileName: String): Boolean {
    val fileExtension = fileName.substringAfterLast(".") 
    return allowedTypes.contains(fileExtension)
}

// If file type is not valid, reject the upload
if (!validateFileType(fileName)) {
    throw IllegalArgumentException("Unsupported file type")
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
	    description = "Detects unrestricted uploads of file with dangerous types"
	    author = "Semgrep"
    strings:
	    $input = /.*\.(bat|exe|sh|js|vbs|cmd)/
    condition:
	    $input
}
```

### CodeQL Rule

```ql
import cwe434

class UnrestrictedUploadWithDangerousType extends Rule {
    // Rule to detect Unrestricted Upload of File with Dangerous Type
    // (CWE-434)

    // Query to detect direct access to a file upload API without any
    // restrictions on the type of file being uploaded
    @QlObservation(
        name="Unrestricted file upload API"
    )
    // Find calls to file-upload API functions that do not restrict
    // the type of file being uploaded
    def vulnerableAPI =
        Call.target("*FileUploadAPI*").
        hasAncestor(Method.named("*"));

  @Cwe434
  // Report a CWE-434 vulnerability if the vulnerable API is called
  // without any restrictions on the type of file being uploaded
  def vulnerableCode = 
    vulnerableAPI.select(c =>
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306: Missing Authentication for Critical Function is a vulnerability that occurs when an application does not properly authenticate a user before allowing them to access a critical function. This can lead to unauthorized access to sensitive data or other malicious activity. In order for an application to protect critical functions, it must ensure that only authenticated users can access them. Failing to do so can lead to a severe security breach.

### Vulnerable Code

```kotlin
fun sendMessage(message: String, recipient: String) {
    // code to send message
}

This code is vulnerable to CWE-306 because it does not require any authentication before it sends a message. Any user can call this function to send a message to any recipient without any verification of their identity or authorization.
```

### Remediation

```kotlin
// Create a function to authenticate a user
fun authenticateUser(username: String, password: String): Boolean {
    // Get the user details from the database
    val userInfo = getUserInfoFromDB(username)
    
    // Compare the provided credentials against the database
    if (userInfo.username == username && userInfo.password == password) {
        return true
    } else {
        return false
    }
}

// Create a function to check if user is authenticated before allowing access to a critical function
fun checkAuthentication(username: String): Boolean {
    // Call the authentication function
    if (authenticateUser(username)) {
        return true
    } else {
        return false
    }
}

// Use the authentication check before allowing access to a critical function
fun criticalFunction(username: String) {
    // Check if user is authenticated
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "CWE-306: Missing Authentication for Critical Function"
      severity = "CRITICAL"
      
    strings:
      $func1 = "functionName"

    condition:
      $func1 and not ( /.*if.*authenticated.*/ )
}
```

### CodeQL Rule

```ql
import cwe/CWE306

class MissingAuthForCriticalFunction extends Rule {
  // Get all the functions that are marked as critical
  // and don't have authentication
  query criticalFuncWithoutAuth(){
    // Finds functions marked as critical
    Function func
    where exists(Annotation ann |ann.type = "Critical" 
    and annotates(ann, func))

    // Finds functions without authentication
    and not exists(FunctionCall call |
    call.callee.name = "authenticate"
    and call.target.matches(func))
  }

  // Report any functions that match the query
  // as a vulnerability
  vulnerability when criticalFuncWithoutAuth(){
    description("This function does not have authentication for its critical function")
    cwe = CWE306
  }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability related to the deserialization of untrusted data. It occurs when an application deserializes data from an untrusted source without validating or sanitizing the input, resulting in a malicious attack vector. This vulnerability can potentially lead to remote code execution, data manipulation, privilege escalation, and other security issues. By exploiting the vulnerability, an attacker can gain access to the system and compromise its security.

### Vulnerable Code

```kotlin
// Deserialize untrusted data from a malicious user
val inputStream = ByteArrayInputStream(userInput.toByteArray())
val obj = ObjectInputStream(inputStream).readObject()
```

### Remediation

```kotlin
Remediating CWE-502 can be achieved by verifying any data that is received from an untrusted source before deserializing it. A simple example in Kotlin could look something like this:

// Deserialize the data from the untrusted source
val data = deserialize(untrustedSource)

// Sanity check the data
if (data.isValid()) {
    // Deserialize the data
    val obj = deserialize(data)
} else {
    // Handle the invalid data
    handleInvalidData()
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    id = "CWE-502"
    description = "Deserialization of untrusted data"
    tags = ["security", "cwe-502", "kotlin"]
  source:
    language = "kotlin"
  detection:
    input:
      // Detect when an object is deserialized with an untrusted source
      var serializedData = ObjectInputStream("<some untrusted source>")
      // This will detect the vulnerability
      val deserializedObject = serializedData.readObject()
}
```

### CodeQL Rule

```ql
import cwe502
import kotlin

class DeserializationVulnerabilityRule extends Rule {
  // Override the query method to define the query
  override query(): string {
    // Find all deserialization of untrusted data
    DeserializationUntrustedData[] = cwe502.findDeserializationUntrustedData()
    
    // Find all calls to deserialization methods in Kotlin
    DeserializationCall[] = kotlin.findKotlinObjectInputStreamReadObject() +
                            kotlin.findKotlinObjectInputStreamReadUnshared() +
                            kotlin.findKotlinObjectInputStreamResolveObject()
    
    // Find all deserialization calls of untrusted data
    return DeserializationUntrustedData[].hasCallers(DeserializationCall[])
  }

  // Over
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability related to authentication for applications or systems. It occurs when authentication controls, such as usernames and passwords, are not properly configured or enforced. This allows attackers to gain access to restricted resources or data without authorization. This vulnerability can result in data breaches or other malicious activities from unauthorized access.

### Vulnerable Code

```kotlin
fun authenticateUser(username: String, password: String): Boolean {
    // assume username and password are entered by the user
    if (username == "admin" && password == "admin") {
        return true
    }
    return false
}

// This code does not adequately authenticate the user, as it only checks for a specific username and password (in this case "admin"). This leaves the system vulnerable to brute-force attacks.
```

### Remediation

```kotlin
The following code can be used to remediate CWE-287: Improper Authentication:

// Use a secure hashing algorithm for password storage
fun hashPassword(password: String): String {
    return MessageDigest.getInstance("SHA-256")
        .digest(password.toByteArray())
        .fold("", { str, it -> str + "%02x".format(it) })
}

// Use a unique salt for each user
class User {
    private val salt = SecureRandom.getInstanceStrong().nextBytes(16)
    private val hashedPassword: String

    constructor(password: String) {
        this.hashedPassword = hashPassword(password + salt.toString())
    }

    fun authenticate(password: String): Boolean {
        return hashPassword(password + salt.toString()) == hashedPassword
    }
}
```

### Semgrep Rule

```yaml
rule = {
  source: "**/*.kt"
  meta:
    description = "Detects improper authentication implementations in Kotlin code"
    author = "MyName"
    id = "CWE-287"
  patterns: 
   - pattern: "if \((?P<user_input>.*)\) == (?P<static_value>.*)"
     message: "Improper authentication found: Authentication is based on static value and user input"
     severity: WARNING
}
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthenticationRule extends Rule {
    // Query to find all instances of improper authentication
    query improperAuthenticationChecks() {
        // Find all authentication attempts
        AuthenticationAttempt[] authAttempts

        // Find all authentication checks
        AuthenticationCheck[] authChecks

        // Check that all authentication attempts are matched with an authentication check
        authAttempts 
            // Check that the authentication attempts are not matched with authentication checks
            where exists(authChecks, c | !cwe287.matches(authAttempts, c))
    }

    // Reports the findings of the query
    private void report(AuthenticationAttempt authAttempt) {
        // Report the improper authentication
        report(authAttempt, "Improper authentication detected");
    }

    // Executes the query and reports the findings
    override def getQueries() {
        query improperAuthenticationChecks
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability that occurs when an application or system uses hard-coded credentials, such as usernames, passwords, or cryptographic keys, instead of using dynamically-generated credentials. This can allow malicious actors to gain access to the system or application by simply knowing the hard-coded credentials, bypassing any authentication process.

### Vulnerable Code

```kotlin
val username = "admin"
val password = "admin123"

// authenticate user
if (username == "admin" && password == "admin123") {
    println("User authenticated!")
} else {
    println("Unauthorized access")
}
```

### Remediation

```kotlin
To fix this vulnerability, a secure authentication mechanism should be used instead of hard-coded credentials. This could be done by implementing OAuth2 or OpenID Connect for authentication and authorization, or by using an API key or token. Additionally, any credentials stored in the application code should be encrypted and stored separately from the application code.
```

### Semgrep Rule

```yaml
rule = {
  strings:
    // hard-coded credentials
    $cred = /username[^\S\n]*:[^\S\n]*[^\S\n]*password/
 
  patterns:
    // look for credentials used in function calls
    // or stored in variables
    $func_call = /([a-zA-Z_]*)\s*\(\s*$cred\s*\)/
    $var_assign = /\$[a-zA-Z_]*\s*=\s*$cred/

  metadata:
    author = "Semgrep team"
    description = "Detects the use of hard-coded credentials"
    severity = "MEDIUM"

  control-flow:
    // look for uses of credentials in function calls or
    // assignments to
```

### CodeQL Rule

```ql
import cwe
import java

class HardCodedCredentials extends Rule {
  // Finds hard-coded credentials
  String getCweId() {
    return cwe`CWE-798`
  }

  Boolean[] getLanguages() {
    return [java]
  }

  Query getQuery() {
    return let hardCreds =
      // Finds string literals that contain "username" or "password"
      // Ignores strings that contain the word "logging"
      // These are potential hard-coded credentials
      (StringLiteral c | exists (Method m, MethodInvocation mc, c.matches(".*(username|password).*") && !c.matches(".*logging.*"))
    in hardCreds
  }
}
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276: Incorrect Default Permissions occurs when a software developer sets incorrect default permissions for a file, directory, or other resource. These incorrect permissions can allow unauthorized users access to sensitive information, or allow them to make modifications to the resource without the owner’s knowledge or permission. These incorrect permissions can also be exploited to elevate the privileges of the user, allowing them to gain access to further resources or modify system settings.

### Vulnerable Code

```kotlin
// Vulnerable code
val file = File("data.txt")
file.createNewFile() // Creates a new file with default permissions

// Non-vulnerable code
val file = File("data.txt")
val permissions = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
val filePath = FileSystems.getDefault().getPath("data.txt")
Files.createFile(filePath, permissions) // Creates a new file with specified permissions
```

### Remediation

```kotlin
// Remediate CWE-276: Incorrect Default Permissions

// Set default permissions to proper values
val filePermissions = 0600 // Owner read and write, others no access
val folderPermissions = 0700 // Owner read, write, and execute, others no access

// Get all files and folders in the current directory
val files = File(".").listFiles()

// Set the permissions for each file and folder
files?.forEach {
    if (it.isFile) {
        it.setPermissions(filePermissions)
    } else if (it.isDirectory) {
        it.setPermissions(folderPermissions)
    }
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects incorrect default permissions"
    id = "CWE-276"
    tags = ["security", "vulnerability", "CWE-276"]
  source:
    lang = "kotlin"
  detection:
    any_of:
      - patterns:
          - pattern: "chmod\(.*, 0666\)"
          message: "Incorrect default permissions detected"
      - patterns:
          - pattern: "chmod\(.*, 0644\)"
          message: "Incorrect default permissions detected"
      - patterns:
          - pattern: "chmod\(.*, 0755\)"
          message: "Incorrect default permissions detected"
}
```

### CodeQL Rule

```ql
import java
import security

class IncorrectDefaultPermissions extends SecurityCodeScanRule {
    /**
    * Checks whether the default permissions of a class are incorrect
    */
    getCweId(): string {
        return "CWE-276"
    }

    getDescription(): string {
        return "Checks whether the declared default permissions of a class are incorrect"
    }

    getName(): string {
        return "Incorrect Default Permissions"
    }

    getRisk(): Risk {
        return Risk.High
    }

    // Find classes with incorrect default permissions
    query incDefPermissions {
        Class c
        Permission p
        c.defaultPermission = p
        // Check for incorrect default permissions
        not p.isCorrect()
    }
}
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that occurs when sensitive information, such as passwords, credit card numbers, or personal data, is exposed to an unauthorized actor. This can occur through insecure data storage, unencrypted communications, or a lack of proper access control. This vulnerability can lead to identity theft, data breaches, and other forms of malicious activity.

### Vulnerable Code

```kotlin
// This code exposes a user's password to anyone who can call the function
fun getUserPassword(username: String): String {
    val password = getPasswordFromDatabase(username)
    return password
}
```

### Remediation

```kotlin
// The following code implements an encryption layer to protect sensitive data from unauthorized actors

val encryptionKey = generateEncryptionKey()

fun encryptData(data: String): String {
    val encryptedData = encrypt(data, encryptionKey)
    return encryptedData
}

fun decryptData(encryptedData: String): String {
    val decryptedData = decrypt(encryptedData, encryptionKey)
    return decryptedData
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        id = "CWE-200-Exposure-of-Sensitive-Information-to-an-Unauthorized-Actor"
        description = "This rule detects potential exposure of sensitive information to an unauthorized actor"
        authors = "Semgrep"
        references = "https://cwe.mitre.org/data/definitions/200.html"
        tags = ["security", "kotlin"]
    strings:
        $sensitive_info = /.*(password|username|api-key|token).*/i
    condition:
        $sensitive_info
}
```

### CodeQL Rule

```ql
import cwe200

class CWE200_Unprotected_Information {

  // Defines a query to detect exposure of sensitive information to an unauthorized actor
  // that can be used to identify potential CWE-200 vulnerabilities
  query CWE200_Unprotected_Information() {
    // Finds methods that can potentially access sensitive information
    MethodAccess sensitiveInfoAccess = {
      Method.accesses(sensitiveData)
      | Method.accesses(sensitiveResource)
    }
    
    // Finds methods that can potentially be accessed by an unauthorized actor
    MethodAccess unauthorizedActorAccess = {
      Method.accesses(unauthorizedActor)
    }
    
    // Finds methods that can potentially expose sensitive information
    // to an unauthorized actor
    sensitiveInfoAccess.refs() * unauthorizedActorAccess.refs()
    // Checks if the sensitive information is not adequately protected
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a vulnerability that occurs when credentials, such as passwords, are stored in a way that does not provide sufficient protection. This means that the credentials are not encrypted, hashed, or otherwise safeguarded from potential attackers who could access the credentials and use them for malicious purposes. Without proper protection, attackers may be able to gain access to accounts, systems, and sensitive data that the credentials are meant to protect.

### Vulnerable Code

```kotlin
fun authenticateUser(username: String, password: String): Boolean {
    val credentials = loadCredentialsFromFile() // load username/password pairs from a file
    return credentials.contains(username to password)
}

This code is vulnerable to CWE-522 because it is storing credentials in plain text in a file and then checking if the provided username and password match the stored credentials. This means that the credentials are not sufficiently protected, and could be compromised if the file is accessed by an unauthorized user.
```

### Remediation

```kotlin
// Remediation:

// Create a secure credentials storage system
val credentialsDataStore = HashMap<String, String>()

// Encrypt the credentials using a strong encryption algorithm
val encryptedCredentials = encryptCredentials(credentialsDataStore)

// Store the encrypted credentials in a secure location
storeEncryptedCredentials(encryptedCredentials)

// Access the stored encrypted credentials only when needed
val retrievedCredentials = retrieveEncryptedCredentials()

// Decrypt the credentials securely
val decryptedCredentials = decryptCredentials(retrievedCredentials)
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects insufficiently-protected credentials"
        author = "Your Name Here"
        references = ["https://cwe.mitre.org/data/definitions/522.html"]
    strings:
        $username = /[A-Za-z0-9_]+/
        $password = /[A-Za-z0-9_]+/
    condition:
        ($username and $password) and (
            # strings.password used without any encryption
            "password" contains $password
            or
            # strings.username used without any encryption
            "username" contains $username
        )
}
```

### CodeQL Rule

```ql
import security

class InsufficientlyProtectedCredentials: SecurityCodeQL {
    
    //CWE-522: Insufficiently Protected Credentials
    predicate vulnerableExpression(){
        credential = VariableRef( TypeRef( "java.lang.String" ) )
        return ExprStmt( AssignExpr( credential, MethodCallExpr( _, "getPassword" ) ) )
    }
    
    predicate isVulnerable(){
        return ExprStmt( AssignExpr( _, credential ) )
        and not ExprStmt( MethodCallExpr( _, "encrypt" ) )
    }
    
    //Trigger the alert when vulnerableExpression() and isVulnerable() both hold
    //in the same method
    from vulnerableExpression() as vuln, isVulnerable() as isVuln,
        Method m
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability that can occur when XML parsers are used to process user-supplied input. It occurs when an XML document references an external entity, such as a remote file or web service, and the parser does not properly restrict or sanitize the external entity. This can lead to the potential for the malicious user to gain access to sensitive data, launch a denial of service attack, or even execute arbitrary code.

### Vulnerable Code

```kotlin
val factory = DocumentBuilderFactory.newInstance()
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
val builder = factory.newDocumentBuilder()
val document = builder.parse(inputStream) // Vulnerable code - InputStream can reference external entity
```

### Remediation

```kotlin
Remediation could involve disabling external entity processing entirely and rejecting any XML documents that contain an entity reference. This can be done by setting the property 'FEATURE_SECURE_PROCESSING' to true on the XML parser:

val factory = DocumentBuilderFactory.newInstance()
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
```

### Semgrep Rule

```yaml
rule = {
  meta:
    severity = "medium"
    description = "Detects possible XML External Entity (XXE) injection vulnerabilities"
  source:
    lang = "kotlin"
  patterns:
    - pattern: |
        newInputSource(
          FileInputStream(
            ("?<file>.*")
          )
        )
  experiments:
    - pattern-match
  issued_warnings:
    - message: "Possible XXE injection vulnerability detected."
    locations:
      - pattern: "file"
}
```

### CodeQL Rule

```ql
import cwe
import java

class CWE611_ImproperRestrictionOfXMLExternalEntityReference extends Rule {
  // Query to detect code that is vulnerable to CWE-611
  CWE611_ImproperRestrictionOfXMLExternalEntityReference() {
    when {
      // Find any XML parsing method
      call < java.xml.XMLReader : Constructor() >()
    }

    then {
      // Find any external entity reference
      def ref = find_entity_reference(result);
      // Find any external entity references that don't use an absolute path
      if (!ref.isAbsolutePath()) {
        // Report the vulnerability
        reportFlaw(cwe.CWE611_Improper_Restriction_Of_XML_External_Entity_Reference())
      }
    }
  }
}
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server Side Request Forgery (SSRF) is a type of vulnerability where an attacker is able to send malicious requests from a vulnerable server to another server. This type of attack can be used to access restricted services, such as those requiring authentication, on the server. Additionally, the attacker can use SSRF to access internal networks, potentially leading to an escalated attack.

### Vulnerable Code

```kotlin
fun fetchData(url: String) {
    // fetch data from the URL
    val response = URL(url).readText()

    // parse the response
    // ...
}

// Call the function with a user-supplied URL
val userUrl = request.getParameter("url")
fetchData(userUrl)
```

### Remediation

```kotlin
// Before

fun doRequest(url: String) {
    val request = Request.Builder().url(url).build()
    val response = client.newCall(request).execute()
}

// After

fun doRequest(url: String) {
    val url = URL(url)
    val host = url.host
    if (!isAllowedHost(host)) {
        throw SecurityException("Host is not whitelisted")
    }
    val request = Request.Builder().url(url).build()
    val response = client.newCall(request).execute()
}

fun isAllowedHost(host: String): Boolean {
    val allowedHosts = listOf("example.com", "example2.com")
    return allowedHosts.contains(host)
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Server-Side Request Forgery (SSRF) vulnerability"
    id = "RULE_ID"
    severity = "CRITICAL"
    author = "AUTHOR_NAME"
  strings:
    $s_1 = "java.net.URL"
    $s_2 = "openConnection"
    $s_3 = "connect"
    $s_4 = "setDoOutput"
    $s_5 = "getInputStream"
  condition:
    all of them
}
```

### CodeQL Rule

```ql
import cwe918

class CWE918_ServerSideRequestForgery : CodeQL
{
    // Declare a predicate to detect functions that make HTTP requests
    // (e.g. curl, http.get, axios.get)
    predicate isHttpRequest(Function func) {
        func.nameMatches("curl") or
        func.nameMatches("http.get") or
        func.nameMatches("axios.get")
    }

    // Declare a predicate to detect functions that accept user-controlled
    // parameters
    predicate isUserControlled (Parameter param) {
        param.hasAnnotation("userControlled")
    }

    // Declare a query to detect CWE-918
    query cwe_918_detection() {
        // Find functions that make HTTP requests
        Function httpRequestFunc =
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of security vulnerability that occurs when a user is able to inject malicious commands into an application. This vulnerability allows attackers to gain access to systems and execute malicious code. The vulnerability occurs when an application doesn't properly sanitize user input, allowing attackers to inject malicious commands into the application. This can result in the application executing malicious code, which can be used to gain access to the system or to gain control of the application. Attackers can also use this vulnerability to modify or delete data and files on the application or system.

### Vulnerable Code

```kotlin
fun executeCommand(command: String) {
    val process = Runtime.getRuntime().exec(command)
    process.waitFor()
    println("Command executed successfully")
}

// Vulnerable call
executeCommand(request.getParameter("command"))
```

### Remediation

```kotlin
// Before
val cmd = "curl $userInput"
Runtime.getRuntime().exec(cmd)

// After
val sanitizedUserInput = userInput.replace(";", "")
val cmd = "curl $sanitizedUserInput"
Runtime.getRuntime().exec(cmd)
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Command Injection"
    severity = "CRITICAL"
    author = "Your Name"
    references = ["https://cwe.mitre.org/data/definitions/77.html"]
  strings:
    $cmd_injection = "Runtime.getRuntime()"
  condition:
    $cmd_injection
}
```

### CodeQL Rule

```ql
import cwe
import java

class CWE077CommandInjection extends SecurityCodeQL {
  /**
  * Detects command injection by analyzing unsafe string concatenation
  * in Java programs
  */
  def vulnerable_pattern(String cmd, String userInput) {
    // Get the method containing the command
    Method m <- findMethod(anywhere) {
      m.getName() == cmd
    }
    // Find the user input parameter and concatenate it with the command
    Expr userInputExpr <- m.getParam(userInput)
    Expr cmdExpr <- m.getBody()
    Expr concatExpr <- concat(userInputExpr, cmdExpr)
    // Check if the result of the concatenation is executed
    Expr execExpr <- containsExec(concatExpr)
    m.getCall
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295: Improper Certificate Validation occurs when an application fails to properly validate an SSL/TLS certificate. This can happen in a number of ways, such as not validating the certificate chain, not verifying the hostname, or not verifying the certificate's expiration date. This leaves the application vulnerable to man-in-the-middle attacks, where an attacker can intercept and alter data being transmitted between the application and the server. To prevent this vulnerability, applications should ensure that certificates are properly validated before establishing any SSL/TLS connections.

### Vulnerable Code

```kotlin
val url: URL = URL("https://example.com")
val connection: HttpsURLConnection = url.openConnection() as HttpsURLConnection
connection.sslSocketFactory = TrustAllSocketFactory()
connection.hostnameVerifier = TrustAllHostnameVerifier()
connection.connect()
```

### Remediation

```kotlin
// Function to validate a certificate
fun validateCertificate(certificate: X509Certificate): Boolean {
    try {
        // Validate the certificate
        certificate.checkValidity()
        // Verify the certificate is signed by a trusted Certificate Authority
        val trustManager = X509TrustManagerImpl()
        trustManager.checkServerTrusted(arrayOf(certificate), "RSA")
        return true
    } catch (e: Exception) {
        return false
    }
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    id = "CWE-295"
    description = "Detects improper certificate validation"
    severity = "CRITICAL"
    author = "Semgrep"
    reference = "https://cwe.mitre.org/data/definitions/295.html"
  strings:
    $cert_validation = /validateCertificate\(/
  condition:
    $cert_validation
}
```

### CodeQL Rule

```ql
import cwe
import java

class CWE295ImproperCertificateValidation:
	
	// Find calls to X509TrustManager.checkServerTrusted which do not check the chain of certificates
	// for validity
	
    X509TrustManager.checkServerTrusted(chain, authType) as checkServerTrusted
    {
    	not exists (
    		chain.forEach(certificate => certificate.checkValidity())
    	)
    }
    
    // Report issue
    vulnerableTo(checkServerTrusted, cwe.ImproperCertificateValidation)
    
    // Suggest fixing it
    suggestFix(checkServerTrusted,
    	"Ensure that each certificate in the chain is checked for validity before calling X509TrustManager.checkServerTrusted"
    )
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094, Improper Control of Generation of Code ('Code Injection'), is a type of vulnerability that happens when an application dynamically generates code without properly validating or sanitizing user input. This can allow an attacker to inject malicious code into the application, which can be executed and cause unexpected behavior or damage. Attackers can use this vulnerability to gain access to sensitive information, modify data, and execute malicious code on the system.

### Vulnerable Code

```kotlin
fun maliciousFunction(input: String) {
    val codeToRun = input // input is not sanitized
    eval(codeToRun) // eval() is used to run the code
}

This code can be used to inject malicious code into the system, potentially causing security issues.
```

### Remediation

```kotlin
// Remediation
// Sanitize all user input before using it as an argument for any system calls
fun exec(command: String) {
    val sanitizedCommand = command.replace(";", "")
    Runtime.getRuntime().exec(sanitizedCommand)
}
```

### Semgrep Rule

```yaml
rule = {
  strings:
  $inj_str = /.*eval.*/
 
  condition:
  $inj_str
}
```

### CodeQL Rule

```ql
import cwe_check

class ImproperControlOfGenerationOfCode implements CweCheck {
  override fun getCweId() = "CWE-094"

  override fun check(node: AstNode): List<Issue> {
    val issues = mutableListOf<Issue>()
    
    // Check for usage of eval(), exec(), execfile() and other functions that can generate code
    if (node is FunctionCall &&
        node.name in setOf("eval", "exec", "execfile")) {
      issues += Issue(node, "Improper control of generation of code", "Potential code injection vulnerability")
    }
    
    // Check for command injection in shell scripts
    if (node is AssignmentExpr &&
        node.right is BinaryExpr &&
        node.right.operator.kind == BinaryOperator.Kind.Concat) {
```

## CWE-269: Improper Privilege Management

### Description

CWE-269: Improper Privilege Management is a vulnerability that can occur when an application fails to properly manage user privileges. This type of vulnerability can allow an attacker to gain access to privileged functions and features that they should not have access to. These privileges can include access to sensitive data, the ability to modify system configurations, and the ability to execute malicious code. Failure to properly manage user privileges can leave an application open to attack and can lead to a number of security issues.

### Vulnerable Code

```kotlin
fun main(args: Array<String>) {
    val user = getUser()
    val admin = getAdmin()

    // Vulnerable code
    admin.updateData(user.data)
}

fun getUser(): User {
    return User("Bob")
}

fun getAdmin(): Admin {
    return Admin("Alice")
}

class User(val name: String) {
    var data: String = ""
}

class Admin(val name: String) {
    fun updateData(data: String) {
        this.data = data
    }
    var data: String = ""
}
```

### Remediation

```kotlin
Remediation for CWE-269 can involve implementing appropriate access control measures to ensure that users are only given privileges in accordance with their role and clearance level. For example, a privilege management system can be implemented which assigns users different levels of privileges depending on their role and clearance. Furthermore, all privileges should be reviewed on a regular basis and revoked when no longer necessary. Additionally, the system should be configured to log any privilege changes, so that any unauthorised changes can be detected and investigated.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-269-Improper-Privilege-Management"
  patterns: [
    {
      pattern: "$var_name := set_privilege($privilege_level)"
      message: "Improper privilege management detected"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe269

class CWE269ImproperPriviledgeManagement:
  // Set of functions that are used to gain access to resources.
  // For example: open, chown, setuid, etc.
  // These functions are used to change the permissions of a resource
  // and should be used with caution.
  private let privilegedFunctions = ["open", "chown", "setuid", ...]

  // Finds calls to privileged functions
  predicate isPrivilegedFunctionCall(CallExpr e) {
    e.callee.name in privilegedFunctions
  }

  // Rule to detect privilege misuse
  // A potential security issue can occur if the function is called
  // without the appropriate permissions.
  //
  // For example:
  // setuid(0)
  //
  // The above invocation of setuid would grant the calling process full
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is a type of injection attack where an attacker can inject malicious code into an expression language statement to gain access to unauthorized information or to modify the application's behavior without authorization. This vulnerability occurs when an application fails to properly sanitize user input, allowing an attacker to inject malicious code into an expression language statement. This can be done by using malicious code in a query string, form input, or cookie value. If the application fails to properly sanitize the user input, the attacker can inject malicious code which can be used to modify the application's behavior or gain access to unauthorized information.

### Vulnerable Code

```kotlin
In the following code snippet, an attacker can inject malicious code into the expression language statement, which can be used to execute arbitrary code in the application:

val expression = "${request.getParameter("expression")}"
val result = Expression.evaluate(expression)
```

### Remediation

```kotlin
// Before
val userInput: String? = ...
val query = "SELECT * FROM users WHERE name = '$userInput'"

// After
val userInput: String? = ...
val safeInput = userInput?.replace("'", "''")
val query = "SELECT * FROM users WHERE name = '$safeInput'"
```

### Semgrep Rule

```yaml
rule = {
	meta:
	  description = "Detects Expression Language Injection vulnerability"
	  severity = "CRITICAL"
	  author = "Author"
	  date = "2020-12-14"
	source:
	  lang = "kotlin"
	  code = """
		// code here
	  """
	pattern:
	  expression = "\\$\\{.*\\}"
	  message = "Expression Language Injection vulnerability detected."
}
```

### CodeQL Rule

```ql
import cwe
import java

class ExpressionLanguageInjection extends Vulnerability {
  ExpressionLanguageInjection() {
    super(cwe:CWE-917)
  }

  // Matches usage of vulnerable expression language statements
  predicate vulnerableStatement() {
    exists(MethodCall exprLang)
    // Checks for vulnerable expression language statements
    exprLang.getTarget().toString() = "getExpressionEvaluator"
  }
  
  // Matches usage of vulnerable data as input
  predicate vulnerableInput() {
    // Checks for vulnerable data being passed as input
    exists(StringLiteral userInput)
  }

  // Checks for vulnerable statement and vulnerable input in the same method
  @Override
  predicate isVulnerable() {
    vulnerableStatement() and vulnerableInput()
  }
}
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability that occurs when a program does not properly resolve linked files before attempting to access them. This can lead to unintended files being accessed which could potentially lead to the disclosure of sensitive information. The vulnerability usually occurs when the application is trying to access a file, but the wrong file is being accessed due to an incorrect link being followed. This could be due to a lack of input validation or incorrect assumptions about the path of the file.

### Vulnerable Code

```kotlin
val path = "path/to/my/file.txt"
val file = File(path)

// Vulnerable code
if (file.exists()) {
    // Do something with the file
}
```

### Remediation

```kotlin
// Remediation

// First, check if the file path is valid before attempting to access it
fun checkFilePath(filePath: String): Boolean {
    return File(filePath).exists()
}

// Second, check if the file is located within an allowed directory
fun checkFileDirectory(filePath: String): Boolean {
    return File(filePath).absolutePath.startsWith("/allowed/directories/")
}

// Third, if necessary, sanitize the file path to prevent malicious input
fun sanitizeFilePath(filePath: String): String {
    return filePath.replace("..", "")
}

// Finally, use the sanitized file path for all file system operations
fun readFile(filePath: String) {
    val sanitizedFilePath = sanitizeFilePath(filePath)
    if (checkFilePath(
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: "File.create(file:$f)",
      operands: [
        {
          name: "f",
          kind: "expr_ref"
        }
      ]
    },
    {
      pattern: "File.exists(file:$f)",
      operands: [
        {
          name: "f",
          kind: "expr_ref"
        }
      ]
    }
  ],
  message: "Improper link resolution before file access detected",
  severity: "error"
}
```

### CodeQL Rule

```ql
import cwe059

class CWE059LinkFollowingVulnerability(Trace t):
    // Check if the trace t is of a vulnerable file operation type
    FileOperation vulnerableFileOp = FileOperation.FileRead
        or FileOperation.FileWrite
        or FileOperation.FileExecute
    if vulnerableFileOp.matches(t) then
        // Check if the trace t is a link followed file operation
        if t.isLinkFollowed() then
            cwe059.report()
        endif
    endif
end
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information is transmitted over a network in plain text, without encryption. This type of transmission can be intercepted and read by malicious actors, exposing the sensitive information in an insecure way. Attackers can use this vulnerability to gain access to confidential data such as passwords, financial information, and other sensitive information. This vulnerability can be prevented by using secure protocols such as TLS/SSL for communication, and encrypting sensitive information before it is sent over the network.

### Vulnerable Code

```kotlin
val url = "http://example.com/data"
val connection = URL(url).openConnection()
val response = connection.inputStream.bufferedReader().readText()
```

### Remediation

```kotlin
The remediation for CWE-319 is to encrypt the sensitive information before transmitting it. This can be done in Kotlin using the Java Cryptography Architecture (JCA). 

Example code for encrypting and decrypting data with JCA: 

//Encrypting data 
val cipher = Cipher.getInstance("AES")
val secretKeySpec = SecretKeySpec(key, "AES")
cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
val encryptedBytes = cipher.doFinal(dataToEncrypt)

//Decrypting data
val cipher = Cipher.getInstance("AES")
val secretKeySpec = SecretKeySpec(key, "AES")
cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)
val decryptedBytes = cipher.doFinal(encryptedBytes)
```

### Semgrep Rule

```yaml
rule = {
  strings:
    $HTTP_METHOD = "GET"
    $SENSITIVE_INFO = /.*/
  condition:
    $HTTP_METHOD @rx /^GET$/ and
    $SENSITIVE_INFO @rx /^[a-zA-Z0-9]+$/ and
    $HTTP_METHOD and $SENSITIVE_INFO
  message: "CWE-319: Cleartext Transmission of Sensitive Information"
}
```

### CodeQL Rule

```ql
import cwe319

class CWE319_Cleartext_Transmission_Sensitive_Info:
	// Rule to detect cleartext transmission of sensitive information
	// using functions that do not use encryption
	
	// Get all functions that are defined in the code
	query functionDefinition
	
	// Get all functions that are used to transmit data
	// without using encryption
	query transmissionWithoutEncryption {
		// Find functions that are used to transmit data
		transmissionFunc = some(functionDefinition) such that
			exists(CallExpr c, ClassInstanceCreationExpr e |
				c.getTarget().getName() == transmissionFunc.getName()
				and e.getType().matches("java.net.URL")
				and c.getArgument(0).matches("
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 (Open Redirection) is a vulnerability that occurs when an application, such as a web application, allows a user to be redirected to an untrusted external domain. This can be exploited by a malicious user to redirect a user to an untrusted website, allowing the malicious user to steal the user's credentials or perform other malicious actions. In an application written in Kotlin, this vulnerability could be exploited by using the URL class to allow a user to enter a URL which is then used to redirect the user to an untrusted website.

### Vulnerable Code

```kotlin
fun redirectToUntrustedSite(url: String) {
    val untrustedUrl = request.getParameter("url")
    
    // Redirect to untrusted URL without any validation
    response.sendRedirect(untrustedUrl)
}
```

### Remediation

```kotlin
// Before
val redirectUrl: String = request.getParameter("redirect")
response.sendRedirect(redirectUrl)

// After
val redirectUrl: String = request.getParameter("redirect")
// Validate the URL
if (redirectUrl.startsWith("https://example.com")) {
    response.sendRedirect(redirectUrl)
} else {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST)
}
```

### Semgrep Rule

```yaml
rule = {
  pattern = "HttpURLConnection.setFollowRedirects(true)"
  message = "Potential CWE-601: URL Redirection to Untrusted Site ('Open Redirect') vulnerability detected"
  severity = "WARNING"
}
```

### CodeQL Rule

```ql
import cwe601

class CWE601OpenRedirectVulnerability {
    // Finds instances of URL redirection that are not trusted
    vulnerable_function = Entity.function("java.net.HttpURLConnection.setInstanceFollowRedirects")

    // Finds instances of URL redirection that are not trusted
    untrusted_redirection = Vulnerability.cwe601.UntrustedRedirection

    // Set the query
    query CWE601OpenRedirectVulnerability {
        // Finds functions that set URL redirection to an untrusted site
        if (vulnerable_function.exists() && untrusted_redirection.exists()) {
            vulnerable_function.where(untrusted_redirection.getCallee())
        }
    }
}
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability related to the insertion of sensitive information into log files. This vulnerability occurs when an application or system logs sensitive user data, such as passwords, financial information, or other confidential information, to a log file without masking or encrypting it. As a result, any unauthorized user with access to the log file can view the sensitive data, potentially leading to data theft or misuse.

### Vulnerable Code

```kotlin
fun logData(data: String) {
    val logFile = File("/var/log/log.txt")
    logFile.writeText("User data: $data")
}

This code is vulnerable to CWE-532 because it inserts sensitive data, such as user data, into a log file. This allows the data to be accessed by anyone who has access to the log file.
```

### Remediation

```kotlin
// Remediate CWE-532: Insertion of Sensitive Information into Log File

// Disable logging of sensitive information
Logger.getLogger("myLogger").setFilter { record ->
    if (record.message.contains("sensitiveInfo")) {
        return@setFilter false
    }
    true
}
```

### Semgrep Rule

```yaml
rule = {
        meta:
          author = "Your Name"
          description = "Detects the insertion of sensitive information into log files"
          severity = "high"
        source:
          patterns:
            - pattern: 'log\.info\([\s]*"[\w\s\d!-*_@#$%&.,;:(){}\[\]\'/+\\]*\b(password|key|credential|token)\b[\w\s\d!-*_@#$%&.,;:(){}\[\]\'/+\\]*"'
              message: "Found sensitive information in log file"
        }
```

### CodeQL Rule

```ql
import cwe
import java

class InsertionOfSensitiveInformationIntoLogFile extends Rule {
  // detect any logging of sensitive information
  when {
    call = cwe.LoggingOfSensitiveInformation() 
  } then {
    // alert if the call is found
    report(call.method, "This call logs sensitive information. (CWE-532)")
  }
}
```


# PHP

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of web application vulnerability that occurs when an attacker injects malicious code into a web page. This malicious code can be executed by a user's web browser and can be used to steal information, manipulate user interface elements, or redirect the user to malicious website. XSS exploits occur when an application does not properly neutralize user input before including it in output that is sent to a web browser. This can lead to the malicious code being interpreted and executed by the browser.

### Vulnerable Code

```php
<?php
$userInput = $_GET['input'];
echo "<h1>Hello $userInput</h1>";
?>

In the above code, if a user provides malicious input through the "input" parameter, such as <script>alert('XSS')</script>, the code will execute the malicious JavaScript code in the user's browser. This can be used to steal user data or modify the page content.
```

### Remediation

```php
// Before
echo $_GET['input'];

// After
echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper neutralization of input during web page generation"
    severity = "MEDIUM"
    author = "Your Name"
 
  source:
    language = "php"
 
  detection:
    input: 
      // Finds any input that is echoed to the page without proper escaping
      pattern = 'echo $_[GET|POST|REQUEST|COOKIE]\['{0,1}[^\]^\[]+\]{0,1}'
    condition: input
}
```

### CodeQL Rule

```ql
import cwe080

class VulnerabilityDetected extends Audit {
  /**
  * @description This rule detects if any user-supplied input is used in a web page without proper neutralization.
  */
 
  // The query will search for code blocks that take input from the user,
  // and generate web page output without proper neutralization.
 
  // Find code blocks that take user input and generate web page output
  @Cwe080
  def vulnerableCode(Input: Expr, Output: Expr): Bool {
    
    // Check if the Input is of a type that could contain malicious code
    (Input.isKind(Expr.LiteralString) or 
    Input.isKind(Expr.LiteralNumber) or 
    Input.isKind(Expr.LiteralBoolean) or 
    Input.isKind(
```

## CWE-020: Improper Input Validation

### Description

CWE-020 is a vulnerability related to improper input validation. This vulnerability occurs when user input is not properly validated and may allow malicious code to be executed. This can lead to a variety of security issues, including injection attacks, buffer overflow, and other attacks. Additionally, it can allow attackers to gain access to sensitive information or take control of system resources.

### Vulnerable Code

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

if($username == "admin" && $password == "password") {
    echo "Welcome, Admin!";
} else {
    echo "Invalid credentials";
}
?>

This code is vulnerable to CWE-020 because it does not perform any validation on the input provided by the user. An attacker could easily provide malicious input, such as a SQL injection attack, to gain access to the system.
```

### Remediation

```php
//Preventing CWE-020
$input = filter_input(INPUT_POST, 'input', FILTER_SANITIZE_STRING);
if(!empty($input)) {
    //Perform operations here
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper input validation"
    severity = "CRITICAL"
  source:
    languages = ["PHP"]
  patterns:
  - pattern: "!preg_match($_GET[.*], .*)"
    message: "Improper input validation detected"
}
```

### CodeQL Rule

```ql
import php

class ImproperInputValidation extends Query {
 
  // Finds any instances of an insecure input validation
  predicate isVulnerableInputValidation() {
    exists(FuncCall fc, Parameter p |
      fc.getFunction() = "filter_input" and 
      p.hasDefaultValue() and
      not p.hasSecurityConstraint()
    )
  }
  
  // Finds any instances of an insecure input validation
  predicate isVulnerableInputValidation2() {
    exists(FuncCall fc, Parameter p |
      fc.getFunction() = "filter_var" and 
      p.hasDefaultValue() and
      not p.hasSecurityConstraint()
    )
  }
  
  // Main query
  query ImproperInputValidation() {
    // Finds
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of vulnerability which occurs when an application does not properly sanitize user input before executing an operating system command. This allows an attacker to inject malicious commands that could be used to access sensitive data, modify the system, or execute arbitrary code on the system. The vulnerability can be exploited by sending specially crafted inputs to the application, which are then executed as commands on the underlying operating system.

### Vulnerable Code

```php
$userInput = $_GET['input'];
$command = 'dir ' . $userInput;
system($command);

This code is vulnerable to OS command injection, as it takes user input directly and passes it to the system() function, without any sanitization. An attacker could craft a malicious input that would execute malicious code on the system.
```

### Remediation

```php
To remediate this vulnerability, it is important to ensure that any user input is properly sanitized before being used in an OS command. This can be done by using a whitelisting approach that only allows specific known-safe characters or strings to be used in the command. For example, the following code snippet would ensure that only alphanumeric characters are used in the OS command:

$user_input = preg_replace('/[^A-Za-z0-9]/', '', $user_input);
$command = 'some_command ' . $user_input;
system($command);
```

### Semgrep Rule

```yaml
rule = {
  strings:
    $cmd = "$_GET['cmd']"
  condition: $cmd
}
```

### CodeQL Rule

```ql
import cwe078

class CWE078CommandInjection extends Rule {
  // Finds uses of functions vulnerable to command injection
  // from https://cwe.mitre.org/data/definitions/78.html
  //
  // Note: This rule is not comprehensive.
  //
  // Examples:
  //   system()
  //   exec()
  //   shell_exec()
  //   passthru()
  //   pcntl_exec()
  //   popen()
  //   proc_open()
  //   backticks operator
  //
  // References:
  // https://www.owasp.org/index.php/Command_Injection

  // Find the vulnerable functions
  predicate vulnerableFunctions(Expr e) {
    e.hasAncestor(
      call {
        cal
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089 is a type of vulnerability which occurs when an attacker is able to inject malicious SQL commands into a web application. This can lead to data leakage, data manipulation, or other malicious activities. Attackers are able to exploit this vulnerability by inputting malicious data into an application and exploiting the lack of input validation. By manipulating the application, they can gain access to sensitive information, manipulate data, or cause other malicious activities.

### Vulnerable Code

```php
$username = $_GET['username'];
$password = $_GET['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";

mysqli_query($conn, $query);
```

### Remediation

```php
// Remediation

$search_term = filter_var($_GET['search_term'], FILTER_SANITIZE_STRING);
$query = "SELECT * FROM products WHERE name LIKE '%".$search_term."%'";

// Prepared statement

$stmt = $db->prepare('SELECT * FROM products WHERE name LIKE ?');
$stmt->bind_param('s', $search_term);
$stmt->execute();
```

### Semgrep Rule

```yaml
rule = {
	id: "cwe-089-sql-injection-detection"
	pattern: $x := /(select|delete|update).*(from|into|where)/
	message: "Possible SQL Injection detected at {{$x.start}}"
	level: WARNING
}
```

### CodeQL Rule

```ql
import cwe089

class Vuln_CWE089_SQL_Injection extends Rule {
    // Checks for improper neutralization of special elements in an SQL command
    // used in an SQL query (SQL Injection).
    //
    // References:
    // CWE-089: https://cwe.mitre.org/data/definitions/89.html
    //
    // Example of vulnerable code:
    //
    // $sql = "SELECT * FROM users WHERE id = " . $_GET['user_id'];
    //
    // Example of secure code:
    //
    // $user_id = mysqli_real_escape_string($_GET['user_id']);
    // $sql = "SELECT * FROM users WHERE id = " . $user_id;
    //
    getInfo() {
        return {
            "
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path Traversal is a type of vulnerability that occurs when an application does not properly restrict paths used for file operations. An attacker can use this vulnerability to gain access to sensitive files and data beyond the intended access privileges by supplying a maliciously crafted path, such as "../" or "../../", in a file operation, such as a file upload, file download, or include/require statement in PHP. This vulnerability allows an attacker to access files and directories outside of the intended directory structure, potentially leading to the exposure of sensitive data or system compromise.

### Vulnerable Code

```php
$file = $_GET['file'];
$path = '/var/www/html/'.$file;
if (file_exists($path)) {
    include $path;
}

In this example, if a user passes a malicious value for the 'file' parameter in the URL, they can potentially access any file on the server. For example, if a malicious user passes in '../../../../etc/passwd', the application will include the contents of the system's passwd file.
```

### Remediation

```php
The following example shows a PHP function which can be used to prevent path traversal attacks. This function takes a user-supplied path and uses realpath() to ensure the path is within an expected directory:

<?php 
function is_valid_path($user_input)
{
    // Set the expected directory
    $expected_dir = "/var/www/uploads/";

    // Resolve the path
    $path = realpath($user_input);

    // Check if the path is within the expected directory
    if (strpos($path, $expected_dir) === 0) {
        // Path is valid
        return true;
    }
    else {
        // Path is invalid
        return false;
    }
}
?>
```

### Semgrep Rule

```yaml
rule = {
  meta:
    severity = "WARNING"
    author = "security@example.com"
    description = "Detects the improper limitation of a pathname to a restricted directory"
  patterns:
    - pattern: '$_GET\[.*\]\|\|.*\.\.\/'
      message: "Potential Path Traversal vulnerability detected."
}
```

### CodeQL Rule

```ql
import cwe022

class PathTraversalVulnerability : SecurityBug {
  CWE022 c;

  // Create a predicate to detect user-controlled inputs
  predicate isUserControlled(string f) {
    exists(string s; f == s)
  }
  
  // Create a predicate to detect output locations
  predicate isOutputLocation(string f) {
    exists(string s; f == s)
  }
  
  // Create a predicate to detect file functions
  predicate isFileFn(Expr e) {
    exists(CallExpr c; c.callee.matches("fopen")
      and isUserControlled(c.getArg(0).value)
      and isOutputLocation(c.getArg(1).value))
  }
  
  // Check if a function has a malicious user-controlled input
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site request forgery (CSRF) is a type of vulnerability that occurs when an attacker tricks a user into performing an undesired action on a web application that the user is currently authenticated to. This type of attack is commonly seen in PHP applications, where an attacker can craft a malicious request that masquerades as a legitimate request from the user. The malicious request can then be used to access or modify data on the web application, such as deleting or changing user accounts or making unauthorized purchases. In order to protect against this vulnerability, applications must implement measures to verify that the requests are coming from trusted sources and that the user's session is still active.

### Vulnerable Code

```php
The following code example is vulnerable to a CSRF attack:

<?php
if (isset($_POST['action'])) {
    if ($_POST['action'] == 'deleteUser') {
        deleteUser($_POST['userId']);
    }
}
?>

In this example, the deleteUser() function is called without any input validation or authentication. An attacker could craft a malicious link or form that would cause this code to be executed, resulting in the deletion of a user account even if the user was not logged in.
```

### Remediation

```php
The most effective way to remediate a Cross-Site Request Forgery (CSRF) vulnerability is to implement a CSRF token. This is a unique identifier that is associated with each valid request and is used to verify that a request is legitimate. The token should be unpredictable and generated randomly on the server-side.

The following is an example of how to implement a CSRF token in a web application written in PHP:

1. Generate a random token on the server-side (e.g. using the generate_random_string() function).

2. Store the token in the user's session data.

3. Add the token to all forms as a hidden field.

4. Validate the token on the server-side before processing the request.

5. Regenerate the token after each valid request.
```

### Semgrep Rule

```yaml
rule = {
    meta: 
        description = "Detects Cross-Site Request Forgery (CSRF) vulnerability"
        severity = "WARNING"
    source: 
        lang = "php"
    patterns: 
        - pattern: '$_POST'
        - pattern: '$_GET'
        - pattern: '$_REQUEST'
    filters: 
        - not: 
            pattern: 'token'
}
```

### CodeQL Rule

```ql
import cwe352

class CWE352CSRFVulnerability : Vulnerability{
  CWE352CSRFVulnerability() {
      super("CWE-352: Cross-Site Request Forgery (CSRF)");
  }
  
  // SQL query to detect an HTTP request method of POST
  @Override
  predicate isCandidate(){
      HttpRequestMethod.matches("POST")
  }
  
  // SQL query to identify the lack of a CSRF token
  @Override
  predicate isVulnerable(){
      exists(VariableDecl v |
        v.hasName("CSRF_token") and
        not exists(Assignment a |
          a.getLeft().getVariable() == v and
          a.getRight().getType().matches("string")
        )
      )
  }
  
  @Override
  vulnerableClasses
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability that occurs when an application allows an attacker to upload a file of a dangerous type, such as an executable. This type of vulnerability can be used to upload malicious code to a server, potentially allowing an attacker access to the system and data stored within. In addition, an attacker may be able to execute the uploaded file and cause damage to the system.

### Vulnerable Code

```php
<?php 
 
// Get the filename and make sure it is valid
$filename = basename($_FILES['uploaded_file']['name']);

// Check if the file type is allowed
$allowed = array('jpg','jpeg','gif','png');
if(!in_array(substr($filename, strrpos($filename, '.') + 1), $allowed)){
    die('Error: File type not allowed');
}

// Move the file to the uploads folder
$destination = 'uploads/' . $filename;
if(move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $destination)){
    echo "File successfully uploaded";
}
?>

The code above is vulnerable to CWE-434 because it does not properly check the file type of the uploaded file and
```

### Remediation

```php
//Perform checks on the file being uploaded to ensure it is of an accepted file type.
//Check that the file is not a .php, .js, .htaccess, .sh, .asp, .cgi, .pl, .py, .exe, .bat, .cmd, .vbs, .reg, .bin, .scr, .com, .inf, .sys, .msi, .htm, .html, .js, .jsp, .swf, .jar, .cab, .jar, .msc, or .dll.
if (in_array($file_extension, array('.php', '.js', '.htaccess', '.sh', '.asp', '.cgi', '.pl', '.py', '.exe', '.bat', '.cmd', '.vbs', '.reg', '.bin', '.scr', '.com', '.inf', '.sys', '.msi
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects CWE-434: Unrestricted Upload of File with Dangerous Type"
        severity = "CRITICAL"
        tags = ["cwe-434", "file-upload"]
    strings:
        $dangerous_type = /\.(php|asp|aspx|jsp|cgi|pl)$/
    files:
        $dangerous_file = /.*\.$dangerous_type/
    conditions:
        $dangerous_file
}
```

### CodeQL Rule

```ql
import cwe434

class UnrestrictedUploadFileDangerousType : CodeQL.Vulnerability {
  predicate isFileUpload() {
    exists(FunctionCall fc | fc.getTarget().getName() = "move_uploaded_file")
  }

  predicate isDangerousType(string type) {
    type matches "php"
  }

  // Check that the destination directory is outside of web root
  predicate isOutsideWebRoot(Expr dir) {
    exists(FileSystemReceiver fs | fs.getReceiver() = dir and not fs.isWithinWebRoot())
  }

  // Check if the uploaded file is of a dangerous type
  predicate isDangerousUpload(Expr file, Expr dir) {
    exists(StringLiteral s | s.getValue() = file and isDangerousType(s.getValue
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306 is a vulnerability that occurs when a critical function of an application, such as a financial transaction or a system configuration, does not have proper authentication measures in place. This means that any user, regardless of their level of authorization, is able to access and execute the critical function. This can lead to unauthorized access to data or resources, or even the complete compromise of the system.

### Vulnerable Code

```php
<?php
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);

if(mysqli_num_rows($result) > 0){
	// process data
}
?>

In this code example, there is no authentication check to make sure the user is authorized to access the user information. As a result, anyone who knows the URL can access the user data without proper authorization.
```

### Remediation

```php
A remediation for CWE-306 would be to implement an authentication system that requires users to authenticate before they can access any critical functions. This can be done using a combination of password and user authentication, such as requiring a username and password, or using a two-factor authentication system. Additionally, the system should require users to re-authenticate after a certain period of time, or after performing any critical functions. Finally, access control measures should be put in place to ensure that only authorized users can access the critical functions.
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-306-Missing-Authentication-For-Critical-Function",
    patterns: [
        {
            pattern: "if ( $AUTHENTICATED != true ) {",
            message: "Missing Authentication for Critical Function"
        }
    ],
    language: "php",
    severity: "warning"
}
```

### CodeQL Rule

```ql
import php

class MissingAuthForCriticalFunctionRule extends SecurityRule {
 
  // Finds instances of a critical function that is not properly authenticated
  @Override
  getCweId() {
    return 306;
  }
 
  @Override
  getDescription() {
    return "Detects instances of a critical function that is not properly authenticated";
  }
  
  @Override
  getRiskLevel() {
    return RiskLevel.HIGH;
  }
  
  @Override
  getDetectableIssues() {
    return [DetectableIssue.VULNERABILITY];
  }
  
  @Override
  getHint() {
    return "Ensure that all critical functions are properly authenticated";
  }
  
  @Override
  getName() {
    return "Missing authentication for critical function";
  }
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability that occurs when untrusted data is deserialized by an application. Deserialization is the process of reconstructing an object from its serialized form. When an application deserializes untrusted data, it can be manipulated by an attacker to execute malicious code or access sensitive information. This can lead to remote code execution, information disclosure, and other security issues.

### Vulnerable Code

```php
//Example of vulnerable code
$unserializedData = unserialize($_GET['data']);
echo $unserializedData;
```

### Remediation

```php
The following code example shows how to remediate the CWE-502 vulnerability by using PHP's built-in unserialize() function with the allowed_classes parameter. This parameter allows us to specify which classes are allowed to be unserialized, preventing any malicious classes from being deserialized. 

$serialized_data = '...'; 
$allowed_classes = array('MyClass'); 
$unserialized_data = unserialize($serialized_data, array('allowed_classes' => $allowed_classes));
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects deserialization of untrusted data"
        id = "CWE-502"
        author = "@example"
    source:
        language = "php"
    strings:
        $untrusted_data = "*"
    condition:
        $untrusted_data and any
}
```

### CodeQL Rule

```ql
import cwe502

class DeserializationVulnerability extends Rule {
  Boolean isUntrustedDataType(Type type) {
    return type.isSubtypeOf("untrusted data type")
  }
  
  query isVuln() {
    Deserialization | 
    Deserialization.objectType(type) & 
    isUntrustedDataType(type)
  }

  vulnerable(Deserialization vuln) {
    cwe502.report(vuln)
  }
}
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability in which an application does not adequately verify the identity of a user before allowing them access to certain functions or resources. This can leave the application vulnerable to attacks by malicious users, who can gain access to sensitive information or resources without the proper authentication. This vulnerability can be caused by a number of factors, such as weak or nonexistent password policies, lack of two-factor authentication, or improper access control configurations.

### Vulnerable Code

```php
//Incorrect authentication code 
if(isset($_POST['username']) && isset($_POST['password']))
{
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $sql = "SELECT * FROM user WHERE username = '".$username."'";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    
    if($row['password'] == $password)
    {
        //Successful authentication
    }
    else
    {
        //Authentication failed
    }
}
```

### Remediation

```php
// Before 
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    //authentication logic
    if ($username == 'admin' && $password == 'password') {
        //user is authenticated
    }
}

// After 
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    //authentication logic
    $hashed_password = hash('sha256', $password);
    if ($username == 'admin' && $hashed_password == 'HashedPasswordGoesHere') {
        //user is authenticated
    }
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects improper authentication vulnerabilities"
      author = "Semgrep"
    source:
      languages = ["PHP"]
    detection:
      condition: all of them
        - pattern: "if\s*\(\s*\$_POST\s*\['username'\]\s*==\s*\$username\s*\&\&\s*\$_POST\s*\['password'\]\s*==\s*\$password\s*\)"
          message: "Improper authentication vulnerability detected"
          severity: "CRITICAL"
}
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthenticationChecker extends Checker {
  // Override the check method to detect the presence of this vulnerability
  // in the given code
  override check(Cwe287Query cwe287Query, Symbol sym) {
    if (sym.hasAnnotation("cwe287")) {
      // Find any authentication checks in the code
      foreach (Statement stmt in cwe287Query.findAuthenticationChecks(sym)) {
        // Check if the authentication check is properly implemented
        if (!cwe287Query.isAuthenticationCheckProperlyImplemented(stmt)) {
          // Flag the code as vulnerable
          reportIssue(stmt, "Improper authentication detected")
        }
      }
    }
  }
}
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a type of vulnerability that occurs when an application stores credentials (such as usernames and passwords) in hard-coded form within the source code. This makes it easy for malicious actors to gain access to the application and its sensitive data, as the credentials are not protected or encrypted. This vulnerability can be especially dangerous if the application is exposed to the public, as anyone with access to the source code can view the credentials.

### Vulnerable Code

```php
$username = "admin";
$password = "password";

if(isset($_POST['username']) && isset($_POST['password'])){
	if($_POST['username'] == $username && $_POST['password'] == $password){
		//allow user to log in
	}
	else{
		echo "Invalid login credentials";
	}
}
```

### Remediation

```php
The best way to remediate a vulnerability related to hard-coded credentials is to remove the credentials from the code and store them in an external, secure location. This way, the credentials can be accessed only by authorized personnel and the code remains free from hard-coded credentials.

For example, an application could store its credentials in an encrypted configuration file and use a library to access the credentials. This way, the application can authenticate with the credentials without having to hard-code them in the source code.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects hardcoded credentials"
        severity = "CRITICAL"
        author = "Security Team"
    strings:
        $credential1 = /[a-zA-Z0-9]{3,20}/
        $credential2 = /[a-zA-Z0-9]{3,20}/
    condition:
        (all of them) and (
            $credential1@$credential2
            or
            $credential1:$credential2
            or
            $credential1 = $credential2
        )
}
```

### CodeQL Rule

```ql
import cwe

class HardcodedCredential : CodeSmell {
  // Finds hardcoded credentials in PHP code
  // by looking for strings of the form `username:password`
  // and `password`
 
  @Override
  predicate isSmell(TextNode text) {
    text.hasString("[A-Za-z0-9]+:[A-Za-z0-9]+") or
    text.hasString("[A-Za-z0-9]+")
  }
 
  @Override
  void report(TextNode text) {
    report ("Hard-coded credentials found at: ", cwe`CWE-798`, text);
  }
}
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276: Incorrect Default Permissions is a vulnerability in which a web application or server is configured with default settings that grant access to resources or files that should be kept secure. This can be done by setting overly permissive file permissions, such as granting read and write access to all users on a file or directory. An attacker can exploit this vulnerability by accessing sensitive files or resources without proper authentication or authorization. In addition, if default accounts and passwords are not changed, an attacker can also gain access to the system using these accounts.

### Vulnerable Code

```php
<?php
// vulnerable code with incorrect default permissions
$file = fopen("sensitive_file.txt", "r");
// the file is readable by anyone
?>
```

### Remediation

```php
To remediate this vulnerability, the code should check the permissions of each file and directory, and ensure that they are set to the most secure setting. This can be done using the chmod() function in PHP, which allows you to set the permissions of a file or directory. For example, to set the permissions of a file to '755', the following code could be used:

$file = '/path/to/file.txt';
chmod($file, 0755);
```

### Semgrep Rule

```yaml
rule = {
    id: "cwe-276-incorrect-default-permissions",
    pattern: "chmod($file, $mode) and $mode != 0600 and $mode != 0400",
    message: "File permissions should not be set to 0600 or 0400 by default.",
    severity: "warning"
}
```

### CodeQL Rule

```ql
import php

class IncorrectDefaultPermissions implements Rule {
  // Query to detect incorrect file/directory permissions
  // that allow unauthorized access
  //
  // Finds all calls to chmod, chown, and chgrp
  // that are used to set incorrect default permissions
  // on files/directories
  //
  // @return  true if the call is setting incorrect permissions
  //          false otherwise
  private predicate isIncorrectPermissions(Expr callee, Expr fileName) {
    exists(FuncCall call |
      call.getCallee() = callee and
      call.getArgument(0) = fileName and
      call.getArgumentCount() > 1 and
      (call.getArgument(1).isLiteral() and
        call.getArgument(1).asLiteral().asInteger()
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that occurs when sensitive information is exposed to an actor that is not authorized to view or access it. This can occur through a variety of ways, such as an insecure configuration of a web application that allows unauthorized access to confidential data, or an application that does not properly sanitize user input. Sensitive information can include passwords, financial data, and other personally identifiable information. This vulnerability can have serious consequences for the organization and individuals affected, as their confidential data can be used for malicious purposes.

### Vulnerable Code

```php
<?php
$password = $_POST['password'];
echo "Your password is " . $password;
?>

In this code example, the user-provided password is echoed out in plaintext. This exposes sensitive information to an unauthorized actor and is therefore vulnerable to the CWE-200 vulnerability.
```

### Remediation

```php
The remediation for this vulnerability is to ensure that sensitive information is encrypted and stored securely. This could be done by implementing a secure encryption algorithm and storing the encrypted data in a secure database. Additionally, access to sensitive information should be limited and monitored, and access should only be granted to authorized actors. Finally, users should be provided with adequate training on how to protect sensitive information.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detecting CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        id = "CWE-200"
        severity = "high"
    strings:
        $sensitive_info = /password|credit card/
    condition:
        $sensitive_info
}
```

### CodeQL Rule

```ql
import cwe

class CWE200Vuln : Vuln {
  // Rule to detect exposure of sensitive information
  // to an unauthorized actor
  when CWE.VulnerableFunctionCall(name:"sensitive_function", parameters:params, vulnerableParameter:vulnerableParam) 
  and CWE.UnauthorizedActor(actor:unauthorizedActor, vulnerableParameter:vulnerableParam)
  then 
    report("Sensitive information is being exposed to an unauthorized actor at " + 
           sourceLocation.toString())
}
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a vulnerability that occurs when a web application or service stores sensitive credentials in plaintext or using an easily reversible encryption method. This makes it easy for an attacker to gain access to the credentials, often without the need for authentication or authorization. This can allow an attacker to access sensitive data or take control of the system.

### Vulnerable Code

```php
// This code stores an unencrypted password in the database
$password = $_POST['password'];
$sql = "INSERT INTO users (password) VALUES ('$password')";
mysql_query($sql);
```

### Remediation

```php
Remediation for this vulnerability would be to ensure that all credentials are stored in an encrypted format, and that access to those credentials is restricted to only the most trusted users. Additionally, any stored passwords should use a strong hash algorithm with a unique salt value. Additionally, regularly audit and rotate the credentials to ensure they are not exposed and are up-to-date.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      id = "CWE-522"
      desc = "Detects insufficiently protected credentials"
      author = "SecureCodeBox"
      reference = "https://cwe.mitre.org/data/definitions/522.html"
    strings:
       $cred_1 = "username"
       $cred_2 = "password"
       $cred_3 = "access_token"
    condition:
       any of ($cred_*) and not in_file("*.php")
}
```

### CodeQL Rule

```ql
import cwe522

class InsufficientlyProtectedCredentials : CodeQL.Vulnerability {
 
  // Finds any calls to functions that store credentials
  // without sufficient protection
  private predicate isStoringCredentials(Call c) {
    exists(Function f,
      c.getTarget() == f and
      f.hasAnnotation("cwe522")
    )
  }
 
  // Finds any calls to functions that store credentials
  // without sufficient protection
  private predicate isStoringCredentials() {
    exists(Call c, isStoringCredentials(c))
  }
 
  // Finds any calls to functions that store credentials
  // without sufficient protection
  private predicate isRetrievingCredentials(Call c) {
    exists (Function f,
      c.getTarget() == f and
      f
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability that occurs when an application parses XML input and allows XML external entity references. This vulnerability allows an attacker to reference external resources, such as files or network services, within the XML document which can lead to information leakage, denial of service and potential remote code execution. This vulnerability can be especially dangerous if the application is not configured to use a secure XML parser that blocks all external entities.

### Vulnerable Code

```php
<?php 
    $xml = simplexml_load_file("http://example.com/data.xml");
    $name = $xml->name;
?>

The code above is vulnerable to CWE-611 because it does not properly restrict the XML external entity reference. If the data.xml file contains a malicious entity reference, it could potentially lead to server-side request forgery or other malicious behavior.
```

### Remediation

```php
Remediation for CWE-611: Improper Restriction of XML External Entity Reference can be achieved by disabling external entity references in an XML processor. This can be done by setting the "disable-external-entities" option. In PHP, this can be done using the libxml_disable_entity_loader function, which disables the loading of external entities.

Example: 

libxml_disable_entity_loader(true);
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-611-detection",
    patterns: [
        {
            pattern: "libxml_set_external_entity_loader($_);",
            message: "Improper Restriction of XML External Entity Reference detected",
            languages: ["php"],
            severity: "CRITICAL"
        }
    ]
}
```

### CodeQL Rule

```ql
import cwe
import php

class VulnerableXMLExternalEntityRef extends Query {
  // Finds any XML files that allow external entity references
  @FileName("*.xml")
  file
  
  // Finds any PHP files that parse XML
  @FileName("*.php")
  phpFile
  
  // Finds any calls to the PHP SimpleXML parser
  SimpleXMLParser = php.function("SimpleXMLElement::__construct")
  
  // Finds any calls to the PHP DOM parser
  DOMParser = php.function("DOMDocument::loadXML")
  
  // Finds any calls to the PHP XMLReader parser
  XMLReaderParser = php.function("XMLReader::open")
  
  // Finds any calls to the PHP XML parser
  XMLParser = php.function("xml_parser_create")
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-Side Request Forgery (SSRF) is a type of vulnerability in which a malicious actor is able to manipulate an application to make a request to any server or service that is accessible from the vulnerable application. This allows an attacker to access and manipulate internal resources, such as databases or file systems, that may not normally be accessible. Additionally, attackers may be able to access sensitive data such as passwords or other private information stored on the internal server. In some cases, attackers may even be able to execute arbitrary code on the internal server.

### Vulnerable Code

```php
$url = $_GET['url'];
$response = file_get_contents($url);
echo $response;
```

### Remediation

```php
Remediating a Server-Side Request Forgery (SSRF) vulnerability in PHP involves validating user-supplied input to make sure it is not maliciously crafted to send a request to an external domain. This can be done by using a blacklist of domains to restrict requests to a specific set of approved domains.

For example, the following code validates user-supplied input to make sure it only sends requests to an approved list of domains:

$url = $_GET['url'];
$approved_domains = array('example.com', 'example2.com');

if (in_array(parse_url($url, PHP_URL_HOST), $approved_domains)) {
    // Send request
} else {
    // Error message
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-918-SSRF-detection",
  patterns: [
    {
      pattern: "preg_match($_SERVER['HTTP_HOST'], $url)",
      message: "Potential Server-Side Request Forgery (SSRF) issue detected",
      severity: "warning"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe
import php

class ServerSideRequestForgeryVulnerability extends Rule {
  // Identify the vulnerable code
  Query vulnerableCode = 
    // Find a call to a function that can be used to issue an HTTP request
    MethodCall.find(
      "curl_*", 
      "file_get_contents", 
      "fopen"
    )
    // Ensure that the call is not whitelisted
    .not(
      MethodCall.withReceiver(
        // List of whitelisted functions
        Function.find("parse_url", "filter_var", "parse_str")
    ));

  // Identify the vulnerable function parameters
  Query vulnerableParams = 
    // Find any parameters to the vulnerable functions
    vulnerableCode.params();

  // Identify the risk of SSRF
  Query potentialRisk =
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of vulnerability where an attacker is able to inject arbitrary commands into a system. This type of attack occurs when user input is not properly sanitized and is used as part of a system command. This can be exploited to execute malicious code on the victim's system.

### Vulnerable Code

```php
$userInput = $_GET['command'];
exec($userInput);

This code is vulnerable to command injection as it takes user input which is then executed as a system command without any validation or filtering. An attacker could inject malicious commands which would be executed by the system.
```

### Remediation

```php
// Before
$userInput = $_GET['command'];
system($userInput);

// After
$userInput = escapeshellcmd($_GET['command']);
system($userInput);
```

### Semgrep Rule

```yaml
rule = {
        id: "CWE-077-detection",
        pattern: "$VAR:string <= `.*`",
        message: "Possible Command Injection detected",
        level: "CRITICAL"
}
```

### CodeQL Rule

```ql
import cwe077

class CWE077_Command_Injection extends SecurityCodeScanRule {
  CWE077_Command_Injection() {
    super.description = "Command injection vulnerability";
  }

  // Find all assignment expressions
  @Assignment
  def assignmentExpr(expr) {
    // Find all assignments of user input
    expr.lhs.isUserInput()
  }

  // Find all function calls
  @Call
  def functionCall(call) {
    // Find all function calls with user input in the arguments
    call.hasArgumentUserInput()
  }

  // Warn when user input is used in a command or system call
  @Report
  def report(expr, call):
    expr.isCWE077 || call.isCWE077
}
```

## CWE-295: Improper Certificate Validation

### Description

Improper certificate validation is a vulnerability in which the application does not properly validate SSL/TLS certificates provided by a remote server. This allows attackers to spoof the server’s identity and gain access to sensitive data, or hijack the connection and inject malicious content. This vulnerability can occur if the application does not properly validate the certificate against the server’s expected certificate, or if the application does not check for any revoked certificates.

### Vulnerable Code

```php
<?php
$url = "https://example.com/";
$ch = curl_init();
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_URL, $url);
$result = curl_exec($ch);
curl_close($ch);

?>

The code above is vulnerable to CWE-295, Improper Certificate Validation, because the CURLOPT_SSL_VERIFYPEER option is set to false, which means that the SSL certificate for the server at example.com is not being validated. This leaves the connection open to man-in-the-middle attacks.
```

### Remediation

```php
// Check the validity of a certificate
$certificate = file_get_contents("certificate.crt");
$data = openssl_x509_read($certificate);
if (!$data) {
    throw new Exception('Invalid certificate');
}

// Validate the certificate against a known Certificate Authority
$ca_certificate = file_get_contents("ca_certificate.crt");
$ca_data = openssl_x509_read($ca_certificate);

$valid = openssl_x509_checkpurpose($data, X509_PURPOSE_ANY, array($ca_data));
if (!$valid) {
    throw new Exception('Certificate not issued by a valid Certificate Authority');
}
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-295
    severity: warning
    message: "Improper Certificate Validation"
    patterns:
      - pattern: |
          $certificate = <<<EOD
            ...
          EOD
        filters:
          - not:
              pattern: "verify_peer"
              files:
                - "*.php"
```

### CodeQL Rule

```ql
import cwe

class ImproperCertificateValidationRule extends Rule {
  // Rule metadata
  meta = {
    id = "CWE-295: Improper Certificate Validation",
    author = "MyCompany Security Team",
    description = "Detected checking of certificates without verifying the identity of the remote server."
    status = "experimental"
  }

  // Query to detect the vulnerability
  query verifiesCertificateIdentity(){
    // Query for functions that check for the certificate
    CertificateCheckFunction = FunctionCall[
      callee.name in ["curl_exec", "openssl_verify", "preg_match"]
    ] 

    // Query for functions that don't verify the identity of the remote server
    NonVerifiedCertificateCheckFunction = CertificateCheckFunction 
    and not FunctionCall[
      callee.name in ["openssl_
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability, which occurs when user input is not properly sanitized and is used to generate code or commands. This allows attackers to inject malicious code into a system, which can be used to gain unauthorized access, execute malicious functions, or compromise system security. It is a serious vulnerability as it can be used to gain access to sensitive data, execute malicious functions, or even modify system configurations.

### Vulnerable Code

```php
<?php
    $user_input = $_GET['input'];
    eval($user_input);
?>

This code is vulnerable to code injection attacks, as it takes user input and evaluates it as PHP code, without any kind of input validation or sanitization. This could allow an attacker to execute arbitrary code on the server.
```

### Remediation

```php
A possible remediation for CWE-094 would be to use parameterized queries to prevent malicious input from being executed as code. This means that any user-contributed data is treated as a literal value and not as executable code. To do this in PHP, we can use the PDO library and its prepare() and execute() methods.

Example:

$sql = "SELECT * FROM users WHERE username = :username AND password = :password";

$stmt = $pdo->prepare($sql);
$stmt->execute(array(':username' => $username, ':password' => $password));

This code ensures that the data being passed into the query is treated as a literal value and not as executable code, thus mitigating the risk of code injection.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects code injection vulnerability"
    id = "CWE-094"
    severity = "CRITICAL"
  strings:
    $user_input = /.*/
  condition:
    $user_input in any_function_call
}
```

### CodeQL Rule

```ql
import cwe094

class CodeInjectionVulnerability implements Vulnerability {
  // Define any helper functions you need here
 
  // The following method is called once for each source file
  // in the repository
  predicate isVulnerable(CWE094:CodeInjection vuln) {
    // Check if the file contains vulnerable code
    exists(Method m | vuln.getMethod() = m)
  }
}
```

## CWE-269: Improper Privilege Management

### Description

CWE-269: Improper Privilege Management is a vulnerability that occurs when an application fails to properly manage the privileges of users. This can be done by providing users with unnecessary privileges, not properly enforcing access control, or not properly separating privileged users from non-privileged ones. This vulnerability can lead to privilege escalation, where a user can perform actions not intended for them, as well as unauthorized access to sensitive data. In PHP, this vulnerability can be caused by improper authentication and authorization mechanisms, insecure configuration settings, or the use of insecure functions.

### Vulnerable Code

```php
// Create a user with administrative privileges
$username = $_POST['username'];
$password = $_POST['password'];
$isAdmin = (isset($_POST['isAdmin'])) ? true : false;

// Create a new user
$user = new User($username, $password);

// Grant admin privileges if isAdmin is set
if($isAdmin) {
    $user->grantAdminPrivileges();
}
```

### Remediation

```php
In order to remediate this vulnerability, developers should establish a comprehensive system of privilege management. This includes setting up a system of roles and privileges, assigning privileges to specific users, and setting up access control mechanisms to ensure that only authorized users are granted access to certain resources. Additionally, developers should limit privileges to only the minimum required in order to perform a given task. They should also regularly audit and review privilege levels to ensure that users do not have excessive privileges that could be exploited.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-269-Improper-Privilege-Management",
  patterns: [
    {
      pattern: "preg_match($pattern, $subject, $matches, $flags % 0)",
      message: "Improper privilege management detected. Please ensure that the flags argument for preg_match() is being properly set.",
      severity: "WARNING",
    },
  ],
  meta: {
    author: "Semgrep Team",
    description: "This rule detects improper privilege management in PHP code.",
    references: "https://cwe.mitre.org/data/definitions/269.html",
  },
}
```

### CodeQL Rule

```ql
import cwe269

class CWE269ImproperPrivilegeManagement extends Rule {
  // ...

  // Finds code that assigns privileges to a user
  // without properly validating the user's credentials
  // or identity.
  @Checks({Check.CWE_269})
  getCallsToAssignPrivileges() {
    // Find calls to functions that assign privileges
    // to a user, such as granting user access to a database.
    return MethodCall.find("{ assignPrivileges(...) }");
  }

  // Finds code that grants privileges to a user
  // without properly validating the user's credentials
  // or identity.
  @Checks({Check.CWE_269})
  getCallsToGrantPrivileges() {
    // Find calls to functions that grant privileges
    // to a user, such as granting user
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is an expression language injection vulnerability. An expression language injection vulnerability occurs when user input is not properly neutralized before being used as part of an expression language statement. This can allow an attacker to inject malicious code into a web application, which can then be executed by the web application. In some cases, this malicious code can allow an attacker to gain access to sensitive information or execute arbitrary code.

### Vulnerable Code

```php
// vulnerable code
$query = "SELECT * FROM users WHERE id = {$_GET['user_id']}";
$result = mysqli_query($conn, $query); 

// Exploiting the vulnerability
$_GET['user_id'] = "1 OR 1=1";
$query = "SELECT * FROM users WHERE id = {$_GET['user_id']}";
$result = mysqli_query($conn, $query); 

// Resulting query
SELECT * FROM users WHERE id = 1 OR 1=1;
```

### Remediation

```php
Use the PHP htmlspecialchars() function to escape any user-supplied data before using it in an expression language statement. 

For example:

$name = htmlspecialchars($_POST['name']);
$expression = "$name == 'admin'";

This will ensure that the expression language statement is safe to use, as the user-supplied data has been escaped and is no longer able to execute malicious code.
```

### Semgrep Rule

```yaml
rule = {
	meta:
		description = "Detects improper neutralization of special elements in an Expression Language statement"
		author = "Your Name"
		date = "2020/02/13"
		reference = "https://cwe.mitre.org/data/definitions/917.html"
		owasp = "A4:2017-Insecure Direct Object References"
		tags = ["cwe-917", "expression-language-injection"]
		
	source:
		languages = ["php"]
		
		
	constant:
		special_characters = ["$", "{"]

	pattern:
		expr_injection = special_characters in ".*"
		
		
	def vulnerability:
		expr_injection
		
}
```

### CodeQL Rule

```ql
import cwe

class ExpressionLanguageInjectionDetector extends Rule {
  // ...
 
  // Create a query to detect special elements being used in an expression language statement
  query expressionLanguageInjection() {
    // Find expression language statements
    ExpressionLanguageStatement stmts as ExpressionLanguageStatement[] = 
      find ExpressionLanguageStatement[_]
    
    // Check for special elements in the statements
    stmts.filter(stmt | 
      exists(ExpressionLanguageSpecialElement elem | 
        elem.parent == stmt)
    )
  }

  // ...
 
  // Create a query to detect improper neutralization of special elements
  query improperNeutralization() {
    // Find expression language statements
    ExpressionLanguageStatement stmts as ExpressionLanguageStatement[] = 
      find ExpressionLanguageStatement[_]
    
    // Check for special elements
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability related to improper link resolution before file access, also known as 'Link Following'. This type of vulnerability occurs when a program follows a link or pathname without checking to see that the file or directory actually exists. This can lead to an attacker being able to access files or directories that they shouldn't have access to. A successful attack may allow an attacker to access sensitive information or execute malicious code on the system. It is important to properly validate any links or pathnames before following them, in order to prevent this type of attack.

### Vulnerable Code

```php
$file_name = $_GET['file'];
$file_path = '/var/www/files/' . $file_name;
if (file_exists($file_path)) {
    include($file_path);
}

This code is vulnerable to CWE-059 because it does not properly validate the value of $file_name before attempting to include it. If an attacker is able to modify the value of the 'file' parameter, they can include any file on the server, regardless of its location. This is an example of improper link resolution before file access.
```

### Remediation

```php
The following code uses the realpath() function to ensure that the requested file is within the given directory before attempting to access it:

<?php
// Get the requested file path
$filePath = $_GET['file'];

// Resolve the real path
$realPath = realpath($filePath);

// Check if the requested file is within the given directory
$baseDir = '/var/www/files';
if (strpos($realPath, $baseDir) === 0) {
    // Read the file
    $fileContents = file_get_contents($realPath);
    // Do something with the file
}
?>
```

### Semgrep Rule

```yaml
rule = {
  pattern = "{left:$file, right:$path}",
  message = "Improper Link Resolution Before File Access detected.",
  severity = "CRITICAL"
}
```

### CodeQL Rule

```ql
import cwe059

class CWE059LinkFollowing extends Rule {
  // Initialize the rule
  CWE059LinkFollowing() {
    super.name = "CWE-059: Link Following"
    super.description = "Detects improper link resolution before file access"
  }

  // Match the call expression
  // Look for the vulnerable code pattern
  @Override
  QueryPair getQuery() {
    // Match the call expression
    Expression accessExpression = 
      CallExpr.all(to: Method("java.io.File: java.io.File#<init>(java.lang.String)"))
    
    // Look for the vulnerable code pattern
    Query vulnerablePattern = 
      accessExpression.withAncestor(
        VariableExpr.withName("fileName"),
        AnyOf(
          AssignmentExpr.of(Variable
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a type of security vulnerability that occurs when sensitive information is transmitted over a network in plain text or unencrypted form. This means that anyone on the same network could potentially intercept or access the data being transmitted, leaving it vulnerable to theft or misuse. This type of vulnerability is especially dangerous when it involves the transmission of passwords, credit card numbers, or other sensitive information, as it could lead to identity theft or financial fraud.

### Vulnerable Code

```php
$url = 'http://example.com/api/';
$data = array('username' => 'user', 'password' => 'password');

// Create the context for the request
$context = stream_context_create(array(
    'http' => array(
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($data)
    )
));

// Send the request
$response = file_get_contents($url, FALSE, $context);

// Check for errors
if($response === FALSE){
    die('Error');
}

// Print the response
echo $response;

This code is vulnerable to CWE-319, since it is transmitting sensitive information in cleartext (HTTP) instead
```

### Remediation

```php
// Before
$url = 'http://example.com/login.php';

// After
$url = 'https://example.com/login.php';
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects CWE-319: Cleartext Transmission of Sensitive Information"
    author = "john_doe"
    date = "2020-09-13"
    version = "1.0"
  strings:
    $text = "password"
  condition:
    $text and not regex(r"^[A-Za-z0-9]+$")
}
```

### CodeQL Rule

```ql
import php

class CWE319CleartextTransmissionOfSensitiveInformationRule extends Rule {
  // Query for finding cleartext transmissions of sensitive information
  Query cleartextTransmissionQuery {
    // Find all functions that handle sensitive information
    Function func
    where isSensitiveFunction(func)
    
    // Find all statements that transmit the sensitive information without encrypting it
    Statement transmission
    where
    transmission.getEnclosingFunction() = func
    and exists(TryStatement t | t.getBody() = transmission and isClearTextTransmission(t))
  }
  
  // Override the method to return the query for this rule
  override predicate getEvaluationPredicate() {
    cleartextTransmissionQuery
  }
  
  // Helper function to detect functions that handle sensitive information
  predicate isSensitiveFunction(Function f) {
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601, or URL Redirection to Untrusted Site ('Open Redirect'), is a vulnerability that occurs when an application redirects a user to an external URL without validating or verifying the destination. This can be exploited by an attacker to redirect a user to a malicious website, allowing the attacker to gain access to sensitive information or perform malicious actions. If a vulnerable URL is accessed, attackers can craft a URL with a malicious destination and redirect a user to that malicious site.

### Vulnerable Code

```php
<?php
$redirect_url = $_GET['url'];
header('Location: ' . $redirect_url);
?>

The code above allows an attacker to send a malicious URL as a GET request parameter, which is then used in the redirect. This can be used to redirect the user to a malicious website.
```

### Remediation

```php
// Before
header("Location: $url");

// After
$url = filter_var($url, FILTER_VALIDATE_URL);
if ($url) {
   header("Location: $url");
} else {
   exit;
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-601-open-redirect",
  pattern: "preg_replace($_SERVER['HTTP_HOST'], $vulnerable_url, $_SERVER['QUERY_STRING'])",
  message: "preg_replace() is used to redirect to an untrusted URL. This may lead to open redirect vulnerability.",
  severity: "WARNING"
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.dataflow.TaintTracking

class OpenRedirect extends TaintTracking::TrackingDomain {
  OpenRedirect() {
    super("OpenRedirect")
  }
}

class UrlRedirect extends cwe::WeaknessType {
  UrlRedirect() {
    super("CWE-601")
  }
  
  override predicate isTracked(DataFlow::Node source) {
    source.getAnAccess().hasOrigin(UrlOrigin)
  }
  
  override predicate isVulnerable(DataFlow::Node sink, DataFlow::Node source) {
    exists(AccessPath sourcePath,
      source.asExpr() |
      source.asAccessPath() => sourcePath 
    ) 
    &&
    exists(AccessPath sinkPath,
      sink.
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability where sensitive information is inserted into a log file. This can happen if the logging system is not configured correctly, and sensitive information is written to the log file without first being sanitized. This can allow an attacker to gain access to confidential information, such as passwords, financial data, or other sensitive information. It can also allow an attacker to gain access to the system by leveraging the information in the log file.

### Vulnerable Code

```php
<?php
$userInput = $_POST["input"];

// Log user input
error_log($userInput);

?>
```

### Remediation

```php
The remediation for this vulnerability is to ensure that any sensitive information is not added to log files. This can be done by using a logging library such as Monolog to filter out any sensitive information before it is written to the log file.

The following is an example of this remediation in PHP:

<?php

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('myLogger');
$logger->pushHandler(new StreamHandler('./logs/mylog.log', Logger::WARNING));

// Add the sensitive information to a variable
$sensitiveInfo = '123456';

// Filter the sensitive information from the log
$logger->addFilter(function ($record) use ($sensitiveInfo) {
    if ($record['message'] === $sensitiveInfo) {
        return false;
    }

    return
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects insertion of sensitive information into log files"
        author = "Author name"
    strings:
        $sensitive_info = /(password|username|token|key)/
    condition:
        any of ($sensitive_info) in log
}
```

### CodeQL Rule

```ql
import php

class SensitiveLogInsertion extends SecurityAudit.Check {
  // Checks for the insertion of sensitive info into log files
  // by searching for calls to PHP functions that write to log files
  // such as error_log and log_error
 
  // Allowed functions
  // @var string[]
  let allowed_functions = ["error_log", "log_error"]
  
  // Sensitive functions
  // @var string[]
  let sensitive_functions = ["get_password", "get_secret", "get_token"]
  
  // Main query
  // @return Query
  @Override
  predicate audit() {
    // Find calls to log functions
    Expr log_functionCall = 
      CallExpr.forMethodName(allowed_functions);
    
    // Find calls to sensitive functions
    Expr
```


# Rust

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of vulnerability that allows an attacker to inject malicious code into a web page through user input. This code is then executed in the user’s browser, potentially allowing the attacker to access information and resources that the user may have access to. In Rust, this vulnerability can occur when user input is not properly sanitized before being generated into a web page. If the input is not correctly filtered, malicious code can be injected into the page, allowing an attacker to gain access to the user’s resources.

### Vulnerable Code

```rust
```rust
let input_str = req.param("name").unwrap_or("Guest");

let output_str = format!("<h1>Welcome, {}!</h1>", input_str);

resp.send(output_str);
```

This code is vulnerable to Cross-site Scripting as it does not properly sanitize the input before using it in the generated HTML. An attacker could provide a malicious input, such as `<script>alert('XSS')</script>`, which would cause arbitrary JavaScript to be executed when the page is loaded.

To prevent this, the code should sanitize the user input using a library such as the `html-escape` crate.

```rust
let input_str = req.param("name").unwrap_or("Guest");

let output_str = format!("<h1>Welcome, {}
```

### Remediation

```rust
Solution:

By using Rust's built-in HTML escaping functions, such as html::escape, it is possible to neutralize any malicious input before it is used to generate a web page. This can be achieved by calling the html::escape function on any user input before using it to generate a web page.

For example, consider the following code that takes input from a user and generates a web page with it:

let input = get_user_input();
let page_content = format!("<h1>{}</h1>", input);

This code is vulnerable to cross-site scripting attacks. To remediate this issue, the html::escape function should be used to neutralize any malicious input before it is used to generate the web page:

let input = get_user_input();
let escaped_input = html::escape(input);
let page_content = format!("<h1
```

### Semgrep Rule

```yaml
rule = {
	strings: $input = /(<script\s+[^>]*>|<\/script>)/
	condition: $input
}
```

### CodeQL Rule

```ql
import cwe079

class CWE079Rule extends Rule {
    // Rule body
    // Query body
    // Helper functions
    
    getQuery(){
        return 
            // Query to detect potential XSS vulnerability
            CWE079.query
    }
    
    // Helper function to detect user-supplied data being used as part of an HTML page
    detectPotentialXSSVulnerability(Class htmlClass){
        //TODO
    }
    
    // Helper function to detect user-supplied data being used for a URL redirect
    detectPotentialURLRedirectVulnerability(Class urlClass){
        //TODO
    }
    
    // Helper function to detect user-supplied data being used for a cookie value
    detectPotentialCookieVulnerability(Class cookieClass){
        //TODO
```

## CWE-020: Improper Input Validation

### Description

CWE-020, also known as Improper Input Validation, is a vulnerability in which a program does not properly validate user input, allowing attackers to supply malicious inputs that could lead to a variety of issues, such as buffer overflows, SQL injections, and command execution. In Rust, improper input validation is often caused by using functions such as `str::from_utf8`, `str::from_utf16`, `str::from_utf32` without validating the input beforehand, which can lead to a buffer overflow.

### Vulnerable Code

```rust
fn main() {
    let mut input = String::new();
    println!("Please enter your username:");
    std::io::stdin().read_line(&mut input).expect("Failed to read line");

    // Vulnerable code below
    let username = input.trim();
    println!("Welcome, {}!", username);
}

The code is vulnerable because the input is not properly validated. It can be used to inject malicious code into the program.
```

### Remediation

```rust
Example code before remediation:

fn get_user_input() -> String {
    let user_input = stdin().read_line().expect("Error reading input");
    return user_input;
}

Example code after remediation:

fn get_user_input() -> String {
    let user_input = stdin().read_line().expect("Error reading input");
    let sanitized_input = user_input.trim().to_string(); // Add input validation
    return sanitized_input;
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detect Improper Input Validation"
        id = "CWE-020"
    strings:
        $input_var = /.*/
    condition:
        all of them
}

@rulerange[start]
// Check for input validation specific functions
$input_var = /.*/
&& (
    // Check for input sanitization
    /sanitize_input\(.*?$input_var.*?\)/
    || /validate_input\(.*?$input_var.*?\)/
    || /escape_input\(.*?$input_var.*?\)/
    || /filter_input\(.*?$input_var.*?\)/

    // Check for input validation
    || /validate_length\(.*?$input_var.*?\)/
```

### CodeQL Rule

```ql
import cwe020

class CWE020_Vulnerability_Detector extends Query {
  // Finds functions that do not validate user input
  predicate isVulnerableFunction(func f) {
    exists(Stmt s, Expr e | 
      f.hasStmt(s) and s.hasExpr(e) and cwe020.isVulnerable(e)
    )
  }
  
  query vulnerableFunctions() {
    find isVulnerableFunction(_)
  }
}
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078 is a type of injection attack that occurs when an attacker is able to inject malicious code or commands into an operating system. This can be done by exploiting weaknesses in input validation and sanitization processes, or by exploiting other vulnerabilities such as insecure file permissions. When successful, the attacker can gain access to or modify files on the target system, or execute malicious code with elevated privileges. In Rust specifically, this vulnerability can be caused by unsafe code or functions such as exec, system, or popen that can be used to execute external commands. To prevent this vulnerability, input validation should be performed on all user-supplied data and any external calls should be properly sanitized.

### Vulnerable Code

```rust
fn execute_command(command: &str) {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("failed to execute command");
    println!("status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
}

// This code is vulnerable to OS Command Injection because the `command` parameter is not sanitized before being passed to the shell. An attacker could inject malicious commands by passing them as part of the `command` parameter.
```

### Remediation

```rust
The best way to prevent command injection attacks is to properly validate and sanitize user input. In Rust, this can be achieved by using the static analysis tool cargo-audit, which can detect and alert developers to unsafe usage of user input.

Additionally, developers should use the standard process::Command API to safely execute external commands. This API provides a safe wrapper around the underlying system command, allowing developers to safely pass user input to external commands. The API also provides a safe way to capture the output of the command and handle it as needed.
```

### Semgrep Rule

```yaml
rule = {
    strings:
        $cmd = /.*/
    condition:
        $cmd
}
```

### CodeQL Rule

```ql
import cwe_078
import semmle.code.cpp.dataflow::DataFlow

class OsCommandInjection extends Cwe_078
{
	// Entry point for the rule
	predicate vulnerable(DataFlow::Node src)
	{
		// Checks if the source node is an OS command
		src.hasStringLiteral() and
			// Checks if the command is not properly escaped
			not src.sanitized()
	}
}
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') is a vulnerability that occurs when user-supplied input is not properly sanitized before being used as part of an SQL query. This can allow an attacker to inject malicious SQL code into a query, giving them the ability to access, modify, or delete data from the underlying database.

### Vulnerable Code

```rust
fn fetch_data_from_database(username: &str) -> String {
    let query_string = format!("SELECT * FROM users WHERE username='{}'", username); 
    let result = db.query(&query_string); 
    return result; 
}

This code is vulnerable to SQL injection attacks because it does not properly neutralize user-supplied input before inserting it into the SQL query string. An attacker could exploit this by supplying malicious input to the username parameter that would cause the database to execute unintended commands.
```

### Remediation

```rust
The remediation for this vulnerability is to use parameterized queries instead of plaintext SQL queries. This can be done by using a database library that supports parameterized queries, such as the Rusqlite library. 

For example, instead of writing:

let query = "SELECT * FROM users WHERE username = '$username'";

Write:

let query = "SELECT * FROM users WHERE username = ?";
let username = "admin";
let params = &[username];
let result = conn.query_row(query, params, |row| {
    // Do something with the row
});
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects potential SQL injection vulnerabilities"
        severity = "WARNING"
    strings:
        $sql_injection = "SELECT * FROM"
    condition:
        $sql_injection at 0
}
```

### CodeQL Rule

```ql
import cwe089

class VulnerableSQLQuery:
    // Checks for the presence of an SQL query
    // with potential injection vulnerabilities
    // using the cwe089.SqlQuery pattern.
    // The pattern matches a query string,
    // and its parameters.
    vulnerabilityPattern = cwe089.SqlQuery

    // Checks if any of the parameters passed to the query
    // can be used to inject malicious content.
    // The query must be of type Select or Insert.
    // The parameter must be of type Literal.
    // The parameter must be placed within the query string.
    @Filter(VulnerableSQLQuery.vulnerabilityPattern)
    def vulnerableQuery(query: Query, param: Parameter):
        query.kind == QueryKind.Select or
        query.kind == QueryKind.Insert and
        param.kind == ParameterKind.Lit
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal is a type of vulnerability that occurs when an application or system allows an attacker to access files and directories outside of the intended directory. This type of vulnerability can allow an attacker to view, modify, or delete files, as well as gain access to the system. It can also be used to gain access to sensitive data and other system resources. Path traversal vulnerabilities can be caused by improper input validation, insecure system configurations, and other security flaws. To prevent this vulnerability in Rust, developers should use the Path::canonicalize() and Path::strip_prefix() functions to ensure that paths are limited to the intended directory. Additionally, developers should ensure that input validation is in place to reject any malicious input that may lead to a path traversal attack.

### Vulnerable Code

```rust
fn read_file(path: &str) -> Result<String, std::io::Error> {
    let mut buffer = String::new();
    let mut file = std::fs::File::open(path)?;
    file.read_to_string(&mut buffer)?;
    Ok(buffer)
}

// The vulnerability occurs when the path argument is not properly validated before passing it to the File::open() function.
// An attacker could inject "../../../etc/passwd" as the path argument to read the contents of the system's password file.

fn read_file(path: &str) -> Result<String, std::io::Error> {
    // Validate the path argument
    if !path.starts_with("/safe/") {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied
```

### Remediation

```rust
// Before
let filename = fs::canonicalize(req.query("file")).expect("Error resolving filename");

// After
let filename = fs::canonicalize(req.query("file"))
    .expect("Error resolving filename")
    .strip_prefix("/restricted/directory")
    .expect("Error: File outside of restricted directory");
```

### Semgrep Rule

```yaml
rule = {
    meta:
        severity = "medium"
        description = "Detects potential Path Traversal vulnerability"
    strings:
        $file_op_call = /\b(file|open|read|write)\(.*\)$/
        $path_component = /\.{2,}/
    condition:
        $file_op_call and $path_component
    }
```

### CodeQL Rule

```ql
import cwe022

class CWE022Rule extends Rule {
  // Checks for path traversal vulnerability
  // by looking for improper limiting of pathname
  // to a restricted directory.
  def predicate(): Predicate {
    cwe022.PathTraversal()
  }
}
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-Site Request Forgery (CSRF) is a type of attack that allows an attacker to send malicious requests to a website from a different domain, without the user’s knowledge or consent. This type of attack allows an attacker to gain control over a user’s session on the website, which can lead to unauthorized access to the user’s data, account, and other sensitive information. In Rust, CSRF vulnerabilities can be introduced through the use of unsanitized user input, allowing an attacker to send malicious requests and gain access to the user’s data.

### Vulnerable Code

```rust
fn process_form(req: &mut Request) -> Result<(), Error> {
    let params = req.params();
    let username = params.get("username").unwrap();
    let password = params.get("password").unwrap();
 
    // ... 
    
    // vulnerable code
    if username == "admin" && password == "password" {
        // perform privileged action
    }
 
    Ok(())
}
```

### Remediation

```rust
The following example shows how to use a unique, unpredictable token to prevent CSRF attacks:

1. Generate a unique, unpredictable token for each user session, known as a CSRF token.

2. Include the token in the form as a hidden field.

3. When the form is submitted, check that the token sent in the request matches the one stored in the user's session.

4. If the token does not match, reject the request and display an error message.
```

### Semgrep Rule

```yaml
rule: 

//Detects potential Cross-Site Request Forgery

@csrf_attack

// look for any network request

network-request: *

// if the request is a POST request

if request.method == "POST"

// and the request contains a Referer header value that doesn't match the host

and request.headers['referer'] != request.host

// alert

alert
```

### CodeQL Rule

```ql
// Vulnerability: CWE-352: Cross-Site Request Forgery (CSRF)

import http

class Request {
  Request request;
  String method;
  String url;
  String origin;
}

class CsrfVulnerability {
  Request request;
}

from Request req, CsrfVulnerability vuln
where vuln.request = req and req.method != "GET"
and not http.isSameOrigin(req.origin, req.url)
select vuln
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability that occurs when an application allows a user to upload a file of any type without adequate restrictions or validations. This can result in malicious files being uploaded which can then be used to compromise the application or the system it is running on. This vulnerability can occur in web applications, desktop applications, or any other type of application that allows users to upload files. In order to mitigate this vulnerability, file types should be restricted to only those that are known to be safe, and any uploaded files should be scanned for malicious content.

### Vulnerable Code

```rust
fn main() {
    let file_name = "/var/www/uploads/sample.pdf";
    let f = File::create(file_name).expect("Unable to create file");
    let mut data = Vec::new();

    // Read in the file data
    f.read_to_end(&mut data).expect("Unable to read file");
 
    // Write the file to the server
    let _ = fs::write(file_name, &data).expect("Unable to write file");
}

The code above is vulnerable to CWE-434. It allows a user to upload any type of file, including potentially dangerous file types such as scripts, executable files, etc. without any restriction. This could lead to malicious code being uploaded to the server and executed.
```

### Remediation

```rust
The most effective way to remediate this vulnerability is to restrict the types of file uploads that are allowed. This can be done by implementing a whitelist of accepted file types, only allowing specific types of files to be uploaded. Additionally, it is important to check the file for any malicious content before allowing it to be uploaded. This can be done by running a virus scanner or other malware detection software on the file.
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-434-unrestricted-upload-of-file-with-dangerous-type
    message: "Unrestricted Upload of File with Dangerous Type detected"
    severity: "WARNING"
    pattern: |
      |
        let _ = std::fs::OpenOptions::new().write(true).open(
            &"$FILE$"
        )
    metadata:
      example: "let _ = std::fs::OpenOptions::new().write(true).open(&<file>)"
      cwe: 434
      cwe_name: Unrestricted Upload of File with Dangerous Type
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.dataflow.TaintTracking

class UnrestrictedUploadOfFileWithDangerousType extends TaintTracking::Sink {
  UnrestrictedUploadOfFileWithDangerousType() {
    super(cwe`CWE-434`)
  }

  override predicate isVulnerable(DataFlow::PathState s) {
    exists(DataFlow::Node source | source.hasSource() and
    source.getTaint().hasExplicitTaint(Taint::UPLOADED_FILE)
  )
}
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306 is a vulnerability that occurs when a critical function does not have any authentication or authorization mechanisms in place. This means that anyone can access the function without any authentication or authorization, which can lead to security issues such as privilege escalation, data leakage, and more. In the context of Rust, this vulnerability can manifest itself in a variety of ways. For example, Rust applications might expose a function that requires a certain level of privilege, but without any authentication or authorization, anyone can access and use that function. Additionally, Rust programs might have functions that require user input but do not properly validate that input, allowing malicious actors to inject malicious payloads or otherwise manipulate the program to their advantage.

### Vulnerable Code

```rust
fn critical_function() -> bool {
    // Do some critical action
    return true;
}

fn main() {
    let result = critical_function();
    if result {
        // Do some other action
    }
}

// Vulnerable code: There is no authentication check before the critical function is executed. This means that anyone who can access the main() function can execute the critical_function without any authentication.

fn critical_function() -> bool {
    // Do some critical action
    return true;
}

fn main() {
    //Authentication check
    if authorized() {
        let result = critical_function();
        if result {
            // Do some other action
        }
    }
}

// Fixed code: The code now contains an authentication check before the critical_function is executed, thus ensuring only authorized users can execute the critical_function.
```

### Remediation

```rust
To remediate this vulnerability, the application should implement a system of authentication and authorization checks. Before allowing a user to perform any critical function, the application should first check that the user is authenticated, and then check the user's authorization level to make sure they have the necessary privileges to perform the action.

For example, a web application might use an authentication system such as OAuth2 to check the user's identity before allowing them to take certain actions. Additionally, the application should check that the user has the necessary privileges to perform the action. This can be done by assigning users to different roles, and then checking those roles when a user attempts to take an action. If the user does not have the necessary privileges, then the action should be denied.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects critical functions missing authentication"
        author = "Author Name"
    source:
        language = "Rust"
    detection:
        condition:
            any of them:
                - pattern: 
                    regexp: 'fn [\w_]+\(\)\s*\{.*?\}'
                    message: "Function is missing authentication"
                - pattern:
                    regexp: 'fn [\w_]+\(.*?\)\s*\{.*?\}'
                    message: "Function is missing authentication"
}
```

### CodeQL Rule

```ql
import cwe
import semantic

class MissingAuthenticationForCriticalFunction extends Rule {
    // Rule definition
   
    // Get all the functions that are marked with the critical annotation
    // and check that each of these functions is preceded by an authentication check
    getCriticalFunctions() {
        let criticalFunctions = 
            find{
                fun | 
                fun.hasAnnotation("critical")
            }else{
                collect(Annotatable)
            }
        return criticalFunctions
    }

    getAuthenticationChecks(criticalFunctions: Annotatable[]) {
        let authenticationChecks = 
            find{
                check | 
                criticalFunctions.some(fun | 
                    check.encloses(fun) && 
                    check.hasAnnotation("authentication"))
            }else{
                collect(Expr)
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability related to deserialization of untrusted data, a process which can result in potentially malicious code being executed. When an application deserializes untrusted data, it is possible for attackers to craft malicious code that can be executed on the system. This could lead to an attacker gaining access to sensitive data or executing arbitrary code on the system. To mitigate this vulnerability, organizations should practice secure deserialization techniques and ensure that all data deserialized is validated and sanitized before execution.

### Vulnerable Code

```rust
fn main() {
    let data = b"{\"name\": \"John Doe\",  \"age\": \"25\"}";
    let value: Value = serde_json::from_slice(data).unwrap();
    println!("{}", value.name);
}

In this example, the code is deserializing untrusted data from a byte array without any validation. As a result, malicious code could be injected into the data, which could lead to an arbitrary code execution vulnerability.
```

### Remediation

```rust
The best way to prevent deserialization of untrusted data is to limit the types of data that can be deserialized. A good way to do this in Rust is to use the serde crate. This crate provides a number of macros and functions that can be used to restrict the deserialization of data to certain types. For example, the following code defines a struct that can only be deserialized from JSON if it contains a valid integer: 

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Struct {
    #[serde(deserialize_with = "validate_integer")]
    value: i32,
}

fn validate_integer<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de
```

### Semgrep Rule

```yaml
rule = {
    "id": "CWE-502",
    "severity": "warning",
    "pattern": [
        {
            "regexp": ".*deserialize.*",
            "includes": [
                {
                    "regexp": ".*\\s+(untrusted|unverified)\\s+.*"
                }
            ]
        }
    ]
}
```

### CodeQL Rule

```ql
import cwe502

class CWE_502_Deserialization_Vulnerability {
  // Vulnerability Pattern
  // 'Deserialize' is a function that takes untrusted data as an argument
  // and deserializes it
  private static prop deserialize_func: CodeTree;

  // Function calls that use 'deserialize_func'
  private static prop deserialize_call: Call;

  // Functions that are called with untrusted data
  private static prop untrusted_data_func: Call;

  // Argument of the function call that is untrusted data
  private static prop untrusted_data_arg: Argument;

  // Initializing the CodeQL query
  CWE_502_Deserialization_Vulnerability() {
    deserialize_func :=
      this.deserialize_func :=
        (function (name
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability that can arise when an application fails to properly authenticate users before allowing them to access sensitive data or resources. This can lead to unauthorized access to the system and data, resulting in the disclosure of sensitive information or the modification of data without permission. Examples of this vulnerability include weak or nonexistent password policies, lack of multi-factor authentication, and inadequate logging of user activity.

### Vulnerable Code

```rust
fn authenticate_user(username: String, password: String) -> Result<(), String> {
    if username == "admin" && password == "password" {
        // Successfully authenticated
        Ok(())
    } else {
        Err("Invalid username or password.")
    }
}

The above code is vulnerable to CWE-287 as it uses a hard-coded username and password for authentication. A malicious user can easily guess the username and password to gain access to the system. A more secure approach would be to use a secure hashing algorithm to store user passwords and compare the hashed passwords during authentication.
```

### Remediation

```rust
The best way to remediate CWE-287: Improper Authentication is to ensure that authentication is properly implemented and enforced in your application. This means verifying that users are who they claim to be, and that they are only granted access to data and resources that are appropriate for their level of authority.

Specific steps to remediate CWE-287: Improper Authentication in Rust include:

1. Implementing a secure authentication system such as OAuth2.0
2. Using secure hashes and salts when storing passwords in the database.
3. Limiting the number of failed login attempts allowed.
4. Enforcing strong password requirements.
5. Implementing two-factor authentication.
6. Regularly monitoring authentication logs.
7. Using secure transport protocols such as TLS/SSL.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects improper authentication"
        severity = "WARNING"
    strings:
        $login = /login\(.*\)/
        $authenticate = /authenticate\(.*\)/
    condition:
        $login and not $authenticate
}
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthenticationCheck extends Cwe287
{
    /**
     * Finds calls to authentication functions that do not perform proper authentication
     */
    predicate isAuthenticationCall(Callable callee) {
        exists(CallExpr ce | ce.getCallee().getCanonicalDecl() == callee)
    }
    
    /**
     * Checks whether the call to an authentication function is properly authenticated
     */
    predicate isProperlyAuthenticated(CallExpr ce, Callable callee) {
        ce.hasArgument(0, _) and
        isAuthenticationCall(callee) and
        ce.hasArgument(1, _) and
        (ce.hasArgument(2, _) or 
        ce.argumentCount() == 3)
    }
    
    /**
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability that occurs when an application or system uses hard-coded credentials, such as usernames and passwords, for authentication. This means that the credentials are stored in the source code of the application or system in plain text, making them easy for an attacker to retrieve. This type of vulnerability can allow an attacker to gain access to privileged accounts or data, and can be used to compromise an entire system.

### Vulnerable Code

```rust
fn main() {
    let username = "admin";
    let password = "password";
    
    // Authenticate user
    if (username == "admin" && password == "password") {
        println!("User authenticated!");
    } else {
        println!("Authentication failed!");
    }
}

In the above example, the username and password are hard-coded into the program, meaning that anyone with access to the code can easily discover the credentials and use them to gain access to the application. This is a security vulnerability because it means that the application is not verifying the identity of the user in a secure way.
```

### Remediation

```rust
The remediation for this vulnerability is to ensure that all credentials are stored securely, preferably not in the source code. This can be done by storing credentials in environment variables or in an encrypted credential store. For example, in Rust, the dotenv crate can be used to create a .env file with environment variables that are accessible in code. Additionally, the encrypt crate can be used to store and encrypt credentials in an encrypted file.
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-798-detection",
  patterns: [
    pattern: "username = \"*\"",
    pattern: "password = \"*\""
  ],
  message: "Potential use of hard-coded credentials detected"
}
```

### CodeQL Rule

```ql
import cwe798

class HardcodedCredentialVulnerability {
    // Detects the usage of hardcoded credentials
    // in variable declarations
    predicate isHardcodedCredential(credential: Expr) {
        exists(Expr value | value.isConstant() && credential.hasDescendants(value))
    }

    // Detects the usage of hardcoded credentials
    // in function calls
    predicate isHardcodedCredentialArgument(arg: Expr, index: int) {
        exists(Expr value | value.isConstant() && arg.hasDescendants(value) && arg.getArgumentIndex() == index)
    }

    // Detects the usage of hardcoded credentials
    // in data structures
    predicate isHardcodedCredentialElement(element: Expr) {
        exists(Expr value | value.isCon
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 is a type of software vulnerability that occurs when a system is installed with incorrect default permissions, allowing users or groups access to sensitive data or resources that they should not have. This can result in unauthorized access to private data, or the ability to modify or delete important files or resources. In the case of Rust, this vulnerability can occur if the code is written without proper permissions in place, or if the default permissions are not correctly configured.

### Vulnerable Code

```rust
fn create_file() {
    let mut f = File::create("test.txt").expect("Failed to create file");
    f.write_all(b"Hello World").expect("Failed to write to file");
}

// The file is created with the default permissions of the user, which may not be secure.
fn create_file_securely() {
    let mut f = OpenOptions::new()
        .write(true)
        .mode(0o600)
        .create(true)
        .open("test.txt")
        .expect("Failed to create file");
    f.write_all(b"Hello World").expect("Failed to write to file");
}
```

### Remediation

```rust
A remediation for CWE-276: Incorrect Default Permissions would be to ensure that all files and directories created by the application have the correct permissions set. This can be accomplished by setting the umask of the application’s environment before creating any files or directories. The following example shows how to set the umask to 022 in Rust:

// Set the umask to 022
let umask = 0o022;
unsafe { libc::umask(umask as _) };
```

### Semgrep Rule

```yaml
rule = {
  id: "cwe-276-incorrect-default-permissions",
  patterns: [
    {
      pattern: "File::open(path, _, Permissions::Mode::all(_))",
      message: "Incorrect default permissions set on the file opened at 'path'."
    }
  ],
  severity: "WARNING"
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.security.InsecurePermissions

class CWE276IncorrectDefaultPermissions extends InsecurePermissions {
    CWE276IncorrectDefaultPermissions() {
        super(cwe `CWE-276`)
    }
}
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a type of security vulnerability that occurs when sensitive information is exposed to an unauthorized actor. This vulnerability can occur when data is not securely stored, an attacker gains access to a system, or when there is a lack of access control. If a malicious actor is able to access confidential information such as passwords, credit card numbers, or other sensitive data, they can use this information to gain access to accounts and commit fraud. This vulnerability can also lead to identity theft and other forms of financial fraud.

### Vulnerable Code

```rust
fn main() {
    let sensitive_data: String = "my_password".to_string();
    let public_data: String = "public_data".to_string();

    let mut data = sensitive_data + &public_data;

    println!("Data: {}", data);
}

In the above code, sensitive data (e.g. a password) is stored in a variable and then concatenated with public data to form a single string. This string is then printed to the console, thus exposing the sensitive data to an unauthorized actor.
```

### Remediation

```rust
The most effective way to remediate CWE-200 would be to ensure that only authorized users have access to sensitive information. This can be done by implementing access control measures such as authentication, authorization, and encryption. 

For authentication, use of multi-factor authentication can be used to verify the identity of users before granting access to sensitive information. Authorization can be used to ensure that only certain users have access to certain information, and encryption can be used to protect the data from unauthorized access.

Additionally, implementing monitoring and logging systems can help to detect and alert administrators of any suspicious activities related to access of sensitive information.
```

### Semgrep Rule

```yaml
rule = {
    strings:
        $sensitive_info = /.*/
    condition:
        $sensitive_info != ""
    message: "Sensitive information is exposed to an unauthorized actor"
}
```

### CodeQL Rule

```ql
import cwe200

class CWE200_ExposureOfSensitiveInformationToUnauthorizedActorRule extends Rule {
  // Declare rule meta data
  meta:
    author = "Your Name"
    description = "This rule detects when sensitive information is exposed to an unauthorized actor."
    severity = "High"

  // Declare the query pattern
  query anyAccessToSensitiveInformation {
    // Find code that accesses sensitive information
    AccessToSensitiveInformation = cwe200.AccessToSensitiveInformation()
    // Find code that is executed by an unauthorized actor
    ExecutedByUnauthorizedActor = cwe200.ExecutedByUnauthorizedActor()

    // Check that both the access and the unauthorized actor are present
    AccessToSensitiveInformation and ExecutedByUnauthorizedActor
  }

  // Declare the alert message
  //
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522: Insufficiently Protected Credentials is a vulnerability that occurs when an application fails to protect user credentials, such as passwords and usernames, against unauthorized access or manipulation. This vulnerability allows an attacker to gain access to a user's account or sensitive data stored in the application. It is important to ensure that credentials are stored securely and properly encrypted to mitigate this vulnerability. In the case of Rust, developers should use a library such as bcrypt to securely store and validate user passwords.

### Vulnerable Code

```rust
fn main() {
    let mut username = String::from("admin");
    let mut password = String::from("password");
    // ...
    // Some code
    // ...
    let user_input = get_user_input();
    if user_input == username && user_input == password {
        // Access granted!
    }
}

In the code above, the user is able to gain access to the application by entering both the username and password as the same string. This is vulnerable to CWE-522: Insufficiently Protected Credentials because there is no check to ensure that the user input is not the same as the credentials stored in the username and password variables.
```

### Remediation

```rust
The most effective way to remediate this vulnerability is to use a secure credential storage system. This could be anything from a dedicated password manager to an encrypted file system, such as a virtual private network (VPN). This storage system should ensure that all credentials are encrypted, and the encryption key is kept safe and secure. Additionally, multi-factor authentication should be used whenever possible to mitigate the risk of credentials being compromised.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects the use of insufficiently protected credentials"
    severity = "MEDIUM"
    tags = ["security"]
  strings:
    $creds = /(username|password):\s*\S+/
    $salt = /salt:\s*\S+/
    $hash = /hash:\s*\S+/
  condition:
    $creds and not $salt and not $hash
}
```

### CodeQL Rule

```ql
import cwe522

class InsufficientlyProtectedCredentials:
  // Find all the functions, methods or classes that are used for handling user credentials
  query credential_handlers {
    // Identify all the variables of type String, File, or IO
    let credential_types = type("std::string") + type("std::ofstream") + type("std::ifstream") + type("std::fstream") + type("std::iostream")
    // Find all functions, methods, or classes that take such variables as parameters
    let credential_handlers = 
      // Functions
      function 
        param.type anyof(credential_types)
    + 
      // Methods
      method
        param.type anyof(credential_types)
    +
      // Constructors
      ctor
        param.type anyof(c
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a type of XML injection vulnerability where malicious XML code is able to access resources outside of the application’s control. It occurs when an application processes XML input without properly restricting or disabling external entity references within the document. By exploiting this vulnerability, an attacker can gain access to sensitive data, cause denial of service, or even execute malicious code on the system. In Rust, this can be caused by the use of unsafe code when working with XML, which can allow a malicious user to inject external entity references and gain access to resources outside the application’s control.

### Vulnerable Code

```rust
fn main() {
    let parser = sax::Parser::new();
    let mut reader = File::open("data.xml").unwrap();
    parser.parse(&mut reader).unwrap();
}

The above code is vulnerable to CWE-611, as it does not validate or restrict the external entity references in the XML file (data.xml) before parsing it. This could allow an attacker to inject malicious code into the XML file, which could then be executed when the parser attempts to parse it.
```

### Remediation

```rust
An example of remediation for CWE-611 could be to disable external entity expansion when parsing XML documents. This can be done by setting the "resolve_entities" option to false when configuring the XML parser. For example, if you are using the Rust XML-rs library, you would configure your parser like this:

let parser = ParserConfig {
    resolve_entities: false,
    ..Default::default()
};
let reader = EventReader::new_with_config(file, parser);
```

### Semgrep Rule

```yaml
rules:
  - id: CWE-611
    patterns:
      - pattern: '<!ENTITY\s+[^>]*\s+SYSTEM\s+["\'][^>]*>'
    message: 'Improper Restriction of XML External Entity Reference (CWE-611) detected'
    severity: WARNING
```

### CodeQL Rule

```ql
import cwe611
import semmle.code.cpp.dataflow.TaintTracking

class CWE611Vulnerability extends Vulnerability {
	CWE611Vulnerability() {
		this.id = "CWE-611";
		this.name = "Improper Restriction of XML External Entity Reference";
		this.description = "An application improperly processes XML files containing references to external resources and fails to properly restrict the access of those external entities.";
		this.vulnerableSystem = "XML processing";
		this.severity = Severity.HIGH;
		this.likelihoodOfExploit = LikelihoodOfExploit.HIGH;
		this.cwe = cwe611;
	}

	@Override
	boolean isVulnerable(TaintTracking.TaintPath path) {
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-Side Request Forgery (SSRF) is a security vulnerability that occurs when an attacker tricks a server into sending a malicious request to an arbitrary external system. This can allow attackers to gain access to sensitive information, send malicious requests to internal systems, and perform other malicious activities. In Rust, SSRF is typically caused by an application failing to properly validate user input before using it to construct a request. This can allow an attacker to craft a malicious request that targets a different server or port than the intended destination.

### Vulnerable Code

```rust
fn fetch_data_from_url(url: &str) {
    let client = reqwest::blocking::Client::new();
    let mut res = client.get(url).send().unwrap();

    // ... process response
}

fn main() {
    let url = "http://example.com/data.txt";

    // Vulnerable code:
    // Fetch data from URL without validating that it's safe
    fetch_data_from_url(url);
}

In this example, the code is vulnerable to SSRF because it does not validate that the URL provided is safe. An attacker can use this vulnerability to make requests to internal services or cause unintended side effects.
```

### Remediation

```rust
Remediation of this vulnerability involves checking the validity of any URLs received from a client before attempting to access them. This can be accomplished by ensuring that all URLs are validated against a whitelist of approved sites.

For example, a Rust program to validate URLs against a whitelist might look like this:

// Create a whitelist of approved URLs
let approved_urls = [
    "https://example.com/",
    "https://example.org/",
];
 
// Parse the URL from the client
let url_from_client = url::Url::parse(&client_url).unwrap();

// Check if the URL is in the approved list
if approved_urls.contains(&url_from_client.as_str()) {
    // If it is, proceed with the request
    // ...
} else {
    // Otherwise, respond with an error
    //
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects Server-Side Request Forgery (SSRF) vulnerability"
        severity = "CRITICAL"
        author = "Your Name"
    source:
        // Patterns that indicate SSRF vulnerability
        patterns: [
            'http.get(', 
            'http.post(',
            'http.request(',
            'curl(',
            'fetch('
        ]
    detection:
        // Detects if the patterns were used in a suspicious context
        condition: patterns
}
```

### CodeQL Rule

```ql
import cwe918

class CWE918Rule extends Rule {
  // Query to detect code that makes a network request using
  // user-supplied data without proper validation
  query non_validated_network_request {
    let url: Expr
    let client: Expr
    
    // Find a call to a function that creates a network request using
    // user-supplied data
    call_expression = {
      // Find a function call
      let callee: Expr
      callee = CallExpr.callee
      
      // Check if the function is a network request
      callee.matches("http::request") or
      callee.matches("http::client::request") or
      callee.matches("reqwest::get") or
      callee.matches("reqwest::post") or
      callee
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of vulnerability that occurs when an attacker is able to execute arbitrary commands on a system by sending malicious input through a vulnerable application. In Rust, this vulnerability can occur when user input is not properly sanitized before being used in a command. This can allow an attacker to inject malicious code into the application, which can be used to gain access to sensitive information or to perform malicious activities.

### Vulnerable Code

```rust
fn exec_command(command: &str) {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("output: {}", stdout);
}

fn main() {
    let user_input = std::env::args().nth(1).expect("Missing user input");
    exec_command(&user_input);
}

The code above is vulnerable to command injection because it takes user input and passes it directly to the operating system without any validation or sanitization. This means an attacker could enter malicious input that would be executed as a command on the system, potentially leading to a variety of security issues.
```

### Remediation

```rust
The best way to prevent this type of vulnerability is to use proper input sanitization. This can be done by validating any user input against a whitelist of acceptable characters, and rejecting any input that does not match the whitelist. For example, a function for sanitizing user input in Rust might look like this:

fn sanitize_input(input: &str) -> Option<String> {
    let whitelist = "abcdefghijklmnopqrstuvwxyz0123456789".to_string();
    if input.chars().all(|x| whitelist.contains(x)) {
        Some(input.to_string())
    } else {
        None
    }
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects improper neutralization of special elements used in a command"
      severity = "high"
    strings:
      $func1 = /system|popen|exec|fork|execv/
      $func2 = /system|popen|exec|fork|execv/
      $cmd = /.*/
    condition:
      $func1 and $func2 and ($cmd)
}
```

### CodeQL Rule

```ql
import cwe077

class CWE_077_Vuln extends Rule {
  // Match calls to functions that are vulnerable to command injection
  // (e.g. system, popen, exec)
  // without proper sanitization
 
  // A call chain that contains at least one call to a vulnerable function
  // and does not contain a call to a sanitizing function
  vulnerableCallChain() {
    VulnerableFunctionCall ->
      !SanitizingFunctionCall
      *
  }
 
  // Match any combination of vulnerable call chain and assignment to a
  // user-controlled value
  vulnerableCallChainAssignment() {
    AssignmentExpr ->
        Expr.asLeft
        vulnerableCallChain()
        Expr.asRight
  }
 
  // Match any vulnerable call chain
  vulnerableCallChainStatement() {
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295: Improper Certificate Validation occurs when a program or system fails to adequately validate a certificate that is presented from a remote host. This can lead to a malicious user being able to spoof the identity of the remote host, potentially allowing them to gain access to sensitive information or resources. In the case of Rust, this vulnerability can be particularly dangerous as Rust's memory safety guarantees make it easier for an attacker to exploit the vulnerability.

### Vulnerable Code

```rust
fn verify_certificate(certificate: &Certificate) -> bool {
    // This code does not validate the supplied certificate.
    true
}
```

### Remediation

```rust
// Validate the certificate chain
let certificate_chain = &mut root_certificate_chain;
let valid = validate_chain(certificate_chain, true);
if !valid {
    return Err(Error::InvalidCertificate);
}
```

### Semgrep Rule

```yaml
rule CWE_295_Improper_Certificate_Validation {
    meta:
        description = "Detects improper certificate validation"
        author = "Semgrep"
        severity = "CRITICAL"
    strings:
        $a1 = /TLSContext.*set_verify/
        $a2 = /TLSContext.*set_verify_depth/
        $a3 = /TLSContext.*set_verify_hostname/
        $a4 = /TLSContext.*set_verify_mode/
    condition:
        all of them
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.security.CertificateValidation

class ImproperCertificateValidationVulnerability extends SecurityBug
{
    // Need to use this constructor to indicate a CWE
    constructor() {
        super(cwe`CWE-295`)
    }

    // Check if the application fails to properly validate a certificate
    predicate isVulnerable(CertValidationRoutine cvr) 
    {
        exists(Call c | cvr.getCaller() = c and CertificateValidation.failsValidation(c))
    }
}
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is an improper control of code injection vulnerability. Code injection is when an attacker is able to inject code into an application, often through user input, that can be executed without the application's authorization. This can allow an attacker to gain access to the application and its data, or to execute malicious code on the system. In Rust, this can occur when user input is not properly sanitized or validated, and is used as part of a dynamic string or code generation process. This can allow an attacker to inject malicious code into a dynamic string or code that is executed by the application.

### Vulnerable Code

```rust
fn main() {
    let user_input = std::env::args().nth(1).unwrap_or_default();
    let command = format!("echo {}", user_input);
    std::process::Command::new("sh").arg("-c").arg(&command).spawn().unwrap();
}

This code is vulnerable to code injection because it takes user input and executes it as a shell command without any filtering or sanitization. This means that an attacker could input malicious code into the program which would be executed with elevated privileges.
```

### Remediation

```rust
Remediation of code injection vulnerabilities can be achieved by using a whitelisting approach. Specifically, any user input should be checked against an allowed list of characters and strings. If the input does not match any of the allowed values, it should be discarded. In addition, any user input should be escaped properly to ensure that malicious code does not get executed. 

For example, in Rust, user input should be sanitized using the `.sanitize()` method in the `std::string` library. This method will escape any characters that could potentially be used in code injection attacks.
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: '{var} = os.exec({str})',
      message: 'Improper control of generation of code detected',
      metadata: {
        type: 'CWE-094',
        description: 'Improper Control of Generation of Code',
      },
    },
  ],
}
```

### CodeQL Rule

```ql
import cwe094

class CWE094_Improper_Control_of_Generation_of_Code_Injection:
    def vulnerable_functions():
        // Find functions that are vulnerable to code injection
        return cwe094.vulnerableFunctions()
    
    def get_sink_calls(func):
        // Get all calls to the vulnerable functions
        return func.calls(vulnerable_functions())
    
    def get_tainted_data():
        // Find all data sources that could be used for code injection
        return cwe094.taintedData()
    
    def is_tainted_parameter(call, parameter):
        // Check if the given parameter for the given call is tainted
        return call.getArg(parameter).sources().intersects(get_tainted_data())
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 is a vulnerability related to improper privilege management. It occurs when an application or system fails to properly manage user privileges, leading to a situation where an unauthorized user is granted access to sensitive data, functions, or resources. This can include the granting of privileged access to a user who should not be allowed such access, or the granting of privileges to a user that are not appropriate for their level of authorization. CWE-269 can lead to data breaches and other malicious activities, such as stealing credentials and performing unauthorized activities.

### Vulnerable Code

```rust
fn main() {
    let user_name = "administrator";
    let admin_level = 3;

    // Get the user input
    let user_input = get_input();

    // Check if the user is an admin
    if user_name == user_input && admin_level > 0 {
        // Grant the user admin privileges
        grant_admin_privileges();
    }
}

fn grant_admin_privileges() {
    // Grant access to all system resources including files, databases, etc.
    // without checking the user's access level.
}
```

### Remediation

```rust
Using Rust's Access Control feature, one can enforce proper privilege management. For example, the following code can be used to restrict access to a resource to only certain users:

// Declare a new type to represent a user
struct User {
    username: String
}

// Declare a new resource type that requires a user to access
struct Resource {
    owner: User
}

// Create a function that checks if a user has access to a resource
fn has_access(user: &User, resource: &Resource) -> bool {
    user == &resource.owner
}

fn main() {
    // Create a new user
    let user = User {
        username: "John".to_string(),
    };

    // Create a new resource that is owned by the user
    let resource = Resource {
        owner: user,
    };

    // Check if the user
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detect improper privilege management"
    severity = "WARNING"
    tags = ["security", "privilege-management", "rust"]

  source: 
    languages = ["Rust"]

  patterns:
    - pattern: |
        unsafe {
            |
            .*
            |
            libc::setuid(
              $args:expr
        )
      message: "Improper privilege management detected"
}
```

### CodeQL Rule

```ql
import cwe269

class ImproperPrivilegeManagementVulnerability {
    // find functions that are granting privileges
    // to a user or group
    // without proper checks
    predicate grantPrivilege(funcName: string, user: string, privilege: string) {
        // find function calls that grant privileges
        // to a user
        exists(Call c |
            c.getTarget().getName() == funcName &&
            c.hasArgument(user) &&
            c.hasArgument(privilege)
        )
    }

    // find functions that are revoking privileges
    // from a user or group
    // without proper checks
    predicate revokePrivilege(funcName: string, user: string, privilege: string) {
        // find function calls that revoke privileges
        // from a user
        exists(Call c |
            c.getTarget().get
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is an expression language injection vulnerability in which an attacker is able to inject malicious code into a web application through its use of an expression language statement. This attack is dangerous as it can be used to manipulate program execution and access sensitive data. The vulnerability occurs when an application fails to properly neutralize special elements used in an expression language statement, such as user-controlled input. This can allow an attacker to inject malicious code into the application, potentially allowing access to sensitive data or allowing manipulation of program execution.

### Vulnerable Code

```rust
fn process_input(user_input: &str) {
    let query = format!("SELECT * FROM users WHERE name='{}'", &user_input);
    // Query the database using the user-provided input
    // ...
}

This code is vulnerable to expression language injection as it does not sanitize the user-provided input before using it in a query. An attacker could use this vulnerability to inject malicious code into the query, which could allow them to gain access to sensitive information or modify the database.
```

### Remediation

```rust
One way to remediate an expression language injection vulnerability is to validate user input against a whitelist of valid characters. This can be done by using the Rust standard library’s regex library to create a regular expression that matches only the valid characters, and then validating user input against that expression. For example, if we wanted to validate a username, we could use the following regular expression:

let username_regex = Regex::new(r"^[A-Za-z0-9_]{1,20}$").unwrap();

This regular expression matches only upper and lowercase letters, numbers, and underscores, and also has a character limit of 20 characters. To validate a username, we could use the regex::is_match() method as follows:

if !username_regex.is_match(&username) {
    // username is invalid
}

This method allows us to validate user input
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects potential CWE-917 vulnerability - Improper Neutralization of Special Elements used in an Expression Language Statement"
    author = "VulnDetect"
    maturity = "stable"
  strings:
    $expr = /[\$#]{1,2}\{.*\}/
  condition:
    $expr
}
```

### CodeQL Rule

```ql
import cwe917

class ExpressionLanguageInjection_CWE917 extends SecurityCodeScannerRule {
  MetaData getInfo() {
    return MetaData.builder()
      .id("CWE-917")
      .title("Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')")
      .description("This rule detects code that does not properly neutralize special elements used in an expression language statement, which can lead to expression language injection.")
      .kind(Kind.VULNERABILITY)
      .cwe(cwe917)
      .leaveNoTrace(true)
      .build();
  }

  // Matches any code that does not properly neutralize special elements used in expression language statements
  // such as SQL queries, JavaScript, etc.
  pattern exprInjection() {
    ExpressionStatement.allInst
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability related to improper link resolution before file access. This vulnerability occurs when a program follows a link that is provided by an untrusted source, without first verifying the validity of the link. This can lead to an attacker gaining access to files or resources that they should not have access to. In the Rust language, this vulnerability can occur if links are provided to the open() function in the standard library without first being checked for validity.

### Vulnerable Code

```rust
fn open_file(file_path: &str) -> Result<(), std::io::Error> {
    let mut file_path = std::path::PathBuf::from(file_path);
    if !file_path.is_absolute() {
        // This line is vulnerable, as it allows a malicious user to
        // manipulate the relative path to open files outside of the
        // intended directory.
        file_path = std::env::current_dir()?.join(file_path);
    }

    let file = std::fs::File::open(file_path)?;
    // Do something with the file

    Ok(())
}
```

### Remediation

```rust
The simplest way to remediate this vulnerability is to ensure that all links are fully resolved before accessing the file. This can be accomplished by using the canonicalize() function in Rust. This function will take a path as an argument and return the fully resolved path that points to the file. For example:

let path = Path::new("../some/path/file.txt");
let resolved_path = canonicalize(path).unwrap();

This code will take the path "../some/path/file.txt" and return the fully resolved path to the file, which can then be used to access the file.
```

### Semgrep Rule

```yaml
rule = {
    meta:
        severity = "medium"
        description = "Detects improper link resolution before file access"
    strings:
        $link_follow = /[^\s]+\.[^\s]+/
    condition:
        any of (
            $link_follow
        )
}
```

### CodeQL Rule

```ql
import cpp
import semmle.code.cpp.security

class ImproperLinkResolution extends SecurityFeature {

  CWE059_LinkFollowing() {
    // Vulnerability occurs when a program follows a link to a file
    // without first checking if the link points to a valid location.
    when File.followLink() as link
    where link.isValid() == false
    then report("Improper link resolution before file access detected")
  }

}
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability which occurs when sensitive information such as passwords, credit card numbers, or other confidential data is transmitted over an unencrypted connection. This means that any hacker with access to the network can intercept the data in plaintext and use it for malicious purposes. This vulnerability is especially dangerous if the data is transmitted over a public network such as the internet, or a mobile network, as these networks are not secure. In Rust, this vulnerability can be prevented by using secure protocols such as TLS or SSL. Additionally, authentication and encryption techniques can also be used to protect data while it is being transmitted.

### Vulnerable Code

```rust
fn main() {
    let message = "This is a very sensitive message!";
    let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();

    // This is the vulnerable code, as it transmits the message in cleartext.
    stream.write(message.as_bytes()).unwrap();
}
```

### Remediation

```rust
Example:

// Before
let username = "JohnDoe";
let password = "1234";

// After
let username = "JohnDoe";
let password = encrypt(key, "1234");
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects cleartext transmission of sensitive information"
        severity = "CRITICAL"
        authors = ["Your Name"]
    strings:
        $s1 = /http:\/\//
        $s2 = /https:\/\//
    condition:
        all of them
}
```

### CodeQL Rule

```ql
import cwe319
import semmle.code.cpp.security.taint

class CleartextTransmissionOfSensitiveInfo extends SecurityFlow {
    CleartextTransmissionOfSensitiveInfo() {
        super(cwe319.CleartextTransmissionOfSensitiveInfo)
    }

    override predicate getDataFlowPredicate() {
        // data flow from a tainted source to an untainted sink
        return this.TaintedSource() && this.UntaintedSink()
    }
}

from CleartextTransmissionOfSensitiveInfo ctsosf, DataFlow df
where ctsosf.getDataFlowPredicate() and df.taintFlow(ctsosf)
select ctsosf, "Cleartext transmission of sensitive information detected"
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 is a vulnerability that occurs when an attacker is able to redirect a user from a trusted website to an untrusted website. This vulnerability can be exploited by an attacker to take advantage of the trust relationship between the user and the trusted website. This can be done by providing a malicious URL in the form of a redirect link which, when clicked, will redirect the user to an untrusted website. The untrusted website may contain malicious content or code that can be used to steal sensitive information or launch other attacks.

### Vulnerable Code

```rust
// This function takes a URL and redirects the user to the given URL.
fn redirect(url: &str) {
    println!("Redirecting...");
    println!("Location: {}", url);
}

// This function takes user input, which is a URL, and attempts to redirect the user to that URL.
fn vulnerable_redirect() {
    let input_url = std::env::var("URL").expect("URL must be set");
    redirect(&input_url);
}
```

### Remediation

```rust
Before:

fn redirect(url: &str) -> Redirect {
    Redirect::to(url)
}

After:

fn redirect(url: &str) -> Redirect {
    if is_valid_url(url) {
        Redirect::to(url)
    } else {
        Redirect::to("/")
    }
}

fn is_valid_url(url: &str) -> bool {
    let parsed_url = Url::parse(url);
    parsed_url.is_ok() && parsed_url.unwrap().host_str().is_some()
}
```

### Semgrep Rule

```yaml
rule = {
  strings:
    $url_redirect = /(?P<url>.*?)/
  condition:
    $url_redirect
}
```

### CodeQL Rule

```ql
import cwe601

class OpenRedirectVulnerability extends Vulnerability {
  OpenRedirectVulnerability() {
    super.name = "Open Redirect Vulnerability";
  }

  predicate isVulnerable() {
    exists(Call c, Method m |
      c.getTarget().getName() = "redirect" and
      c.getArgument(0)?.getValue() != null and
      cwe601.isOpenRedirect(m, c)
    )
  }
}
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability that occurs when sensitive information is inserted into a log file. This can happen if a user input is unintentionally logged, or if a log file is configured to store sensitive data. If an attacker is able to access the log file, they can view the sensitive data and use it to gain access to other parts of the system. This can lead to data theft, identity theft, or other malicious activities. Additionally, the sensitive information may be used to create a false sense of security, allowing the attacker to bypass authentication mechanisms or other security measures.

### Vulnerable Code

```rust
fn log_user_information(user_info: String) {
    // Create a log file
    let mut log_file = File::create("app.log").expect("Unable to create log file");

    // Write the user information to the log file
    log_file.write_all(user_info.as_bytes()).expect("Unable to write to log file");
}

// Invoke the function with sensitive data
log_user_information("username=admin&password=123456");

// The log file now contains the user's sensitive information
// CWE-532: Sensitive information has been inserted into a log file without proper protection
```

### Remediation

```rust
The following code example shows one way of remediating the vulnerability of inserting sensitive information into log files. The code uses the log crate to create loggers with different levels of security. For example, a secure logger is created with the log::LevelFilter::Off level filter, which will prevent any sensitive information from being logged.

```rust
extern crate log;

use log::{LogRecord, LogLevelFilter, LogMetadata};

struct SecureLogger;

impl log::Log for SecureLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevelFilter::Off
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
        description = "Detects insertion of sensitive information into log files"
        author = "Your name"
        id = "CWE-532"
        severity = "high"
    strings:
        $sensitive_info = /(credit_card_number|social_security_number|login_credential|password)/
    condition:
        // checks for log functions with sensitive information as parameter
        $sensitive_info and (
            (func("log::*") and parameter.contains($sensitive_info))
            or
            // checks for logging of sensitive information
            (expr and expr.contains($sensitive_info))
        )
}
```

### CodeQL Rule

```ql
import cwe532

class LogInsertionVulnerability extends Rule {
  // Look for calls to logging functions
  predicate isLoggingFunction(Expr e) {
    e.match(
      // Detect calls to logging functions
      fn: FunctionCall { callee.hasName("log") }
    )
  }
  
  // Find the arguments being passed to the logging functions
  predicate isLoggingArgument(Expr e) {
    e.match(
      // Find calls to logging functions
      fn: FunctionCall { callee.hasName("log") },
      // Check the arguments being passed to the logging functions
      arg: Expr { parent: fn }
    )
  }

  // Check if sensitive information is being passed as argument
  predicate isSensitiveInformation(Expr e) {
    e.match(
      // Look for references
```


# Go

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of vulnerability that occurs when malicious code is injected into a web page or application. This code can be used to execute malicious scripts on the user's web browser, potentially allowing the attacker to steal information, hijack sessions, or even take control of the user’s computer. XSS is a type of injection attack, where the attacker injects malicious code into an input field. The code is then executed when the user visits the webpage, allowing the attacker to access information stored on the user’s computer.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable code:
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
	})
	http.ListenAndServe(":8080", nil)
}

The code above is vulnerable to Cross-site Scripting (CWE-079) because it does not properly sanitize the user input from the URL query parameter "name". In this case, if a malicious user sets the "name" parameter to a malicious script, then the script would be executed when the code generates the web page.
```

### Remediation

```go
// Before
func writePage(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(r.FormValue("input")))
}

// After
func writePage(w http.ResponseWriter, r *http.Request) {
    input := html.EscapeString(r.FormValue("input"))
    w.Write([]byte(input))
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-079",
  patterns: [
    {pattern: "echo $1 | %{word} | html.EscapeString()", message: "Potential Cross-site Scripting (XSS) vulnerability detected!"}
  ],
  severity: "medium"
}
```

### CodeQL Rule

```ql
import cwe
import go

class CrossSiteScriptingVulnerability(cwe.Vulnerability):
 
  // Detects a Cross-site Scripting (XSS) vulnerability in Go code
 
  // Finds uses of the 'html/template' package
  GoTemplateTemplatePackageCall = go.Call("html/template.Template")
  
  // Finds uses of the 'html/template' Execute method
  GoTemplateExecuteMethodCall = GoTemplateTemplatePackageCall.member("Execute")
  
  // Finds usage of a variable in the Execute method call
  GoTemplateExecuteMethodCallWithVariable = GoTemplateExecuteMethodCall.withArgs(go.Variable)
  
  // Raises an issue when the Execute method is called with a variable
  // as an argument
  def rule():
    cwe.Vulnerability.register(Cross
```

## CWE-020: Improper Input Validation

### Description

Improper input validation is a vulnerability that occurs when an application fails to properly validate user input. This can lead to the application being exposed to malicious code or unexpected behavior, which can potentially allow an attacker to gain control of the application or lead to data breaches. Improper input validation can occur when user input is not checked for correctness, accuracy, completeness, or consistency with other inputs, or when any input is accepted without proper validation. This vulnerability can also occur if the application fails to validate input from external sources, such as a web API, or data from a database.

### Vulnerable Code

```go
package main

import "fmt"

func main() {
	//Get user input
	userInput := 0
	fmt.Print("Please enter a number: ")
	fmt.Scan(&userInput)

	//Do something with user input
	fmt.Println("You entered: ", userInput)
}

//This code is vulnerable to CWE-020, because it does not validate the input of the user. A malicious user may enter a string instead of a number, which can cause unexpected behavior in the program.
```

### Remediation

```go
// Remediation example

func validateInput(input string) bool {
	if input == "" || len(input) > 256 {
		return false
	}

	// Use a whitelist of accepted characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	for _, char := range input {
		if !strings.Contains(validChars, string(char)) {
			return false
		}
	}

	// Perform additional checks, if necessary
	// ...

	return true
}
```

### Semgrep Rule

```yaml
rule = {
	meta:
   		severity = "CRITICAL"
   		description = "Improper input validation vulnerability detected"
	source:
    		lang = "go"
	pattern: |
    		$param := param("*")
    		!validate($param)
}
```

### CodeQL Rule

```ql
import cwe020
import Go

class VulnerableInputValidation extends Go.Expr {
    Go.CallExpr callExpr
    Go.BasicLit basicLit
}

class Vulnerability extends VulnerableInputValidation  {
    // CodeQL does not yet support building string literals,
    // so we cannot check for the exact strings that indicate
    // unsafe input validation.
    // Instead, this rule will raise an alarm if input validation is 
    // not present in a function call.
    exists(Go.CallExpr call) {
        callExpr = call
        not exists(Go.BasicLit basic)
        // We don't want to raise an alarm for this type of basic literal
        not basic.val == "nil"
    }
}

from Vulnerability vuln, Go.CallExpr call, Go.Func
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

CWE-078, also known as OS Command Injection, is a vulnerability that occurs when an attacker is able to inject malicious commands into an application. This vulnerability is often exploited to gain access to a system or network, allowing an attacker to execute remote code or even modify system files. The vulnerability arises when the application does not properly validate or sanitize user input, allowing malicious code to be executed without the user's knowledge. This can be done via malicious scripts, command-line arguments, environment variables, and other methods. If successful, the attack can allow the attacker to gain access to sensitive data, control the application, or even take control of the system.

### Vulnerable Code

```go
package main

import (
  "fmt"
  "os"
)

func main() {
  // Get the user input
  userInput := os.Args[1]
  
  // Run the command with the user input
  result, err := exec.Command("/bin/bash", "-c", userInput).Output()
  if err != nil {
    fmt.Println(err)
  }
  
  fmt.Println(string(result))
}
```

### Remediation

```go
// Remediation example
func executeCommand(command string) (string, error) {
	// Use cmd.StrictQuote to sanitize the command string
	args := cmd.StrictQuote(command)

	// Use exec.Command to execute the command
	cmd := exec.Command(args[0], args[1:]...)

	// Use StdoutPipe to capture the output
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", err
	}

	// Read the output
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, out); err != nil {
		return "", err
	}

	// Wait for
```

### Semgrep Rule

```yaml
rule = {
    id: "CWE-078-OS-Command-Injection",
    patterns: [{
        pattern: "exec(\"{{$CMD}}\")",
        message: "Potential OS Command Injection vulnerability detected",
        languages: ["Go"],
    }],
}
```

### CodeQL Rule

```ql
import os

from BaseQuery import BaseQuery

class CWE078_OSCommandInjection(BaseQuery):
	def __init__(self):
		self.description = "Detects OS command injection"
		self.query = """import Go

let cmd := __OS_Command__
let inputs := __Data_Flow__.dataFlowsTo(cmd)

inputs.hasAny(inp | inp.hasValueOfType(Go.String) and
    cmd.contains(inp.asExpr()))"""

	def validate(self, query_result):
		return len(query_result) > 0
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089 is an SQL injection vulnerability that occurs when a malicious user is able to execute arbitrary SQL code on a vulnerable system. This type of attack can be used to gain access to sensitive data, modify existing data, or even delete data from the system. This can be accomplished by inserting special characters or keywords into a web form, URL parameter, or other user input field. If the application fails to properly sanitize and neutralize this input, the malicious user can gain access to the system's SQL database and run arbitrary code.

### Vulnerable Code

```go
import "database/sql"

func main() {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	defer db.Close()

	// Vulnerable code
	var username string
	err := db.QueryRow("SELECT user FROM users WHERE id = " + username).Scan(&username)
	if err != nil {
		// Handle error
	}
}

The code above is vulnerable to SQL injection as the value of the username variable is directly concatenated to the SQL query without being properly escaped or parameterized. This can allow an attacker to craft a malicious input that modifies the intended query and, as a result, access or modify data in the database.
```

### Remediation

```go
// Before Remediation
query := "SELECT * FROM products WHERE productID = " + id

// After Remediation
// Use prepared statement
query := "SELECT * FROM products WHERE productID = ?"
stmt, err := db.Prepare(query)
if err != nil {
    return err
}
defer stmt.Close()

// Execute query with id as parameter
rows, err := stmt.Query(id)
if err != nil {
    return err
}
defer rows.Close()
```

### Semgrep Rule

```yaml
rule = {
    strings:
      $sqlQuery = /.*/
    condition:
      $sqlQuery
}
```

### CodeQL Rule

```ql
import cwe089

class CWE089SQLInjectionRule extends Rule {
  CWE089SQLInjectionRule() {
    super("CWE-089-SQL-Injection-Rule");
  }

  @Override
  Query query() {
    // Finds functions that accept user input as a parameter and are used to create an SQL query
    MethodCall[] mcs =
      MethodInvocation.all()
      .withReceiver()
      .select(mci => mci.getMethodName().matches("execute|query|prepare|open"))
      .where(mci =>
        // Checks that user input is used as a parameter
        mci.getArgument(0).any(f => UserInput.matches(f))
        // Checks that the return type of the method is a query
        && Query.matches(mci.getMethod
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path traversal is a type of security vulnerability which occurs when an attacker is able to use directory traversal characters such as "../" to access files and directories that are outside of the intended directory. This can allow the attacker to gain access to sensitive files and data, execute malicious code, or even delete files. In Go, a path traversal vulnerability can occur when an application does not properly restrict access to files and directories, allowing the attacker to access files and directories outside of the intended application directory.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fileName := r.URL.Query().Get("file")
		data, err := ioutil.ReadFile(fileName)
		if err != nil {
			fmt.Fprintf(w, "Unable to read file: %s", fileName)
			return
		}
		fmt.Fprintf(w, string(data))
	})
	http.ListenAndServe(":8080", nil)
}

This code is vulnerable to Path Traversal because it does not check to see if the fileName
```

### Remediation

```go
In Go, path traversal can be prevented by properly sanitizing user input.

For example, if a user is allowed to provide a file path, one can use the filepath.Clean() function to ensure that the file path is within the specific directory that the application allows.

For example:

func sanitizePath(userPath string) string {
	return filepath.Clean(userPath)
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-022-detection",
  patterns: [
    {
      pattern: "os.Chdir(`$DIR`)",
      message: "Potential Path Traversal vulnerability detected!",
      severity: "WARNING",
    },
  ],
  languages: ["Go"],
}
```

### CodeQL Rule

```ql
import cwe022

class PathTraversalVulnerability(cwe022.Vulnerability):
    // Rule to detect improper limitation of a pathname to a restricted directory
    // (CWE-022)

    // Find file operations that take user input as a parameter
    private FileOperation readFileOperation
    private FileOperation writeFileOperation

    // Find user input that is used as a parameter for file operations
    private Expression userInput

    // Find folders that are restricted for file operations
    private Expression restrictedFolder

    // Find function calls that have user input parameters
    FileOperation.call(userInput) => readFileOperation, writeFileOperation {
        
        // Find file operations with restricted folder as a parameter
        FileOperation.call(restrictedFolder) => readFileOperation, writeFileOperation {
            // Flag if user input is used as a parameter for a file operation in a restricted folder
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site Request Forgery (CSRF) is a type of vulnerability in which an attacker can send a malicious request to a web application on behalf of a user. The malicious request could be used to perform an action that the user did not intend to perform, such as transferring money or changing a password. This vulnerability can be exploited by an attacker who tricks a user into clicking on a malicious link or opening a malicious attachment. The malicious request will then be sent to the web application, and the application will execute the request without the user's knowledge or consent. In Go, CSRF vulnerabilities can be mitigated by using anti-CSRF tokens, which are randomly generated strings that are sent to the client and used to verify the validity of the request.

### Vulnerable Code

```go
package main

import (
	"net/http"
	"fmt"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Process the POST request
			// Here is the vulnerability
			fmt.Fprintln(w, "POST request processed")
		}
	})

	http.ListenAndServe(":8080", nil)
}

This code is vulnerable to CSRF because it does not check for a valid CSRF token before processing the POST request.
```

### Remediation

```go
One way to remediate Cross-Site Request Forgery (CSRF) vulnerabilities in Go is to use CSRF tokens. These tokens are generated randomly and are stored in the server’s session. When the client sends a request to the server, the server validates the CSRF token before processing the request. 

// Generate a CSRF token
func generateCsrfToken() string {
	// Generate a random string
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Store the CSRF token in the server’s session
func setCsrfToken(r *http.Request) {
	csrfToken := generateCsrfToken()
	session, _ := store.Get(r, "session")
	session.Values["csrf_token
```

### Semgrep Rule

```yaml
rule = 
    forall $req, $resp:
        http.request($req) and
        http.response($resp) and
        $req.method == "POST" and
        not $resp.header["X-CSRF-Token"]
       
    =>
        message = "Possible Cross-Site Request Forgery (CSRF) vulnerability detected. Missing X-CSRF-Token header in response."
        severity = "WARNING"
```

### CodeQL Rule

```ql
import cwe352

class CWE352_CSRF_Vulnerability:
    def __init__(self):
        self.vuln_functions = [
            "http.PostForm",
            "http.Get",
            "http.Post",
            "http.Put"
        ]
        self.anti_csrf_headers = ["X-CSRF-Token","X-XSRF-Token","X-Requested-With"]
   
    def vulnerable(self, call):
        if call.getFunctionName() in self.vuln_functions:
            for header in self.anti_csrf_headers:
                if not call.hasArgument(header):
                    return True
        return False

from CWE352_CSRF_Vulnerability import CWE352_CSRF_Vulnerability

class CWE352_CS
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a vulnerability that occurs when a web application allows unrestricted upload of files with dangerous types, such as executable files (.exe), to the server. This allows attackers to upload malicious code that can be used to exploit the system, bypass security measures, and gain unauthorized access. The vulnerability can be exploited by an attacker who is able to upload malicious files to the server, thus bypassing any security measures that may have been put in place.

### Vulnerable Code

```go
package main

import (
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/upload", uploadHandler)
	http.ListenAndServe(":8080", nil)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Unrestricted Upload of File with Dangerous Type
	if r.Method == "POST" {
		f, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer f.Close()

		// Unrestricted File Upload - could be malicious
		fname := "./uploaded_file"
		out, err := os.Create(fname
```

### Remediation

```go
One way to remediate this vulnerability is to limit the types of file uploads that are allowed and validate the files to ensure they are what they claim to be. For example, you could check the file extension and ensure it matches the expected file type. Additionally, you could implement a whitelisting approach to only allow files of certain types. You could also require a review of the file before it is uploaded or impose a maximum file size limit on the uploads.
```

### Semgrep Rule

```yaml
rule = {
	id: "CWE-434-unrestricted-upload-of-file-with-dangerous-type",
	severity: "error",
	metadata: {
		description: "Detects the unrestricted upload of a file with a dangerous type",
		references: ["https://cwe.mitre.org/data/definitions/434.html"]
	},
	pattern: statements: [{
		lhs: {
			// Match a function call to an upload function
			// with a file type that is restricted
			function_calls: [{
				id: /upload/
			}, {
				arguments: [{
					type: /(exe|bat|js|cmd|vbs|sh)/
				}]
```

### CodeQL Rule

```ql
import sys

class CWE_434:
    def __init__(self):
        self.vulnerability_name = "CWE-434: Unrestricted Upload of File with Dangerous Type"

    def vulnerable_file_types(self):
        return [".exe", ".dll", ".bat", ".com", ".vbs", ".js", ".reg", ".cmd"]

    def detect(self, file):
        for vulnerable_file_type in self.vulnerable_file_types():
            if file.endsWith(vulnerable_file_type):
                return True
        return False

class CWE_434_Rule(CodeQL):
    def __init__(self):
        self.vulnerability = CWE_434()
        self.query = """
            import File
            import FileSystem
            import Path

            class FileUpload {
                File file
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306 is a vulnerability that occurs when a critical function, such as access to sensitive data or a critical system process, does not require authentication. This means that anyone can access the function without having to provide any credentials. This can lead to a wide range of security issues, from unauthorized access to data and system processes, to even malicious code being executed on the system.

### Vulnerable Code

```go
package main

import "fmt"

func main() {
	// This function allows a user to delete a file without authentication.
	deleteFile := func(fileName string) {
		fmt.Println("Deleting file", fileName)
		// Delete file code here
	}

	// Call the deleteFile function
	deleteFile("my_file.txt")
}
```

### Remediation

```go
The first step in remediation for CWE-306 is to ensure that all critical functions require authentication. This can be done by implementing an authentication system such as OAuth 2.0, which provides a secure way for users to authenticate their identity. Additionally, any sensitive data should be encrypted and stored in a secure database or file system. Additionally, access control should be implemented to ensure that only authorized personnel can access the data. Finally, a logging system should be implemented to track any access attempts and to detect any possible malicious activities.
```

### Semgrep Rule

```yaml
rule = {
    strings:
    $function1 = /(?i)function\s+\w+\s*\(/
    $function2 = /(?i)function\s+\w+\s*\(\s*[^)]*\s*auth\s*=\s*false/
    condition: all of them
}

impact: critical
message: "Critical function missing authentication"
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.security.Argument

class Vulnerability_CWE_306 extends SecurityHardcoded {
    predicate vulnerable(Argument arg) {
        arg.getFunction() instanceof cwe.MissingAuthenticationForCriticalFunction and
        arg.getValue().isHardcoded()
    }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability relating to the deserialization of untrusted data. This vulnerability occurs when data is deserialized from an untrusted source and can lead to malicious code execution. This is particularly dangerous when the data is deserialized into an executable language such as Go, as the malicious code can be executed directly by the program. To protect against this vulnerability, developers should always validate all data received from untrusted sources before deserializing it.

### Vulnerable Code

```go
package main

import (
	"encoding/json"
	"fmt"
)

func main() {

	//untrusted data
	untrustedData := `{"Name":"Bob","Age":30}`

	// Unmarshal the untrusted data
	var user map[string]interface{}
	json.Unmarshal([]byte(untrustedData), &user)

	fmt.Println(user)
}
```

### Remediation

```go
The following example shows how to use the Go encoding/json package to safely unmarshal JSON data from a trusted source:

package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	// Define a struct to hold the data.
	type Data struct {
		Name string
		Age  int
	}

	// Unmarshal the JSON data into the struct.
	var data Data
	err := json.Unmarshal([]byte(`{"Name":"John Doe","Age":42}`), &data)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the result.
	fmt.Printf("Name: %s, Age: %d", data.Name, data.Age)
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-502-deserialization-of-untrusted-data",
  patterns: [
    {
      pattern: 'encoding/gob.NewDecoder(io.Reader)',
      message: 'Potential deserialization of untrusted data'
    }
  ]
}
```

### CodeQL Rule

```ql
import go

class DeserializationVulnerability extends Vulnerability {
  // Declare the class of the vulnerability
  let kind = "deserialization-vulnerability"
  
  // Construct a query to find vulnerable code
  query vulnerableCode {
    // Find calls to functions or methods which deserialize untrusted data
    deserializeCall as call where deserializeCall.getTarget().matches("*") 
    
    // Find the untrusted data being deserialized
    untrustedData as var where untrustedData.valueOf() = deserializeCall.getArgument(0) 
    
    // Find the source of the untrusted data
    untrustedDataSource as decl where untrustedData.isInitializedBy(untrustedDataSource) 
    
    // Find sources of untrusted data which are not trusted
```

## CWE-287: Improper Authentication

### Description

CWE-287: Improper Authentication is a vulnerability that occurs when authentication controls are not properly implemented in a software application. This can lead to an attacker being able to access the application with unauthorized credentials, or a user being able to access the application without proper authentication. In Go, this can occur if a developer does not properly validate user input or does not enforce secure authentication methods. Attackers can exploit this vulnerability to gain unauthorized access to data or resources.

### Vulnerable Code

```go
package main

import "fmt"

func main() {
	username := "admin"
	password := ""

	if username == "admin" && password == "password" {
		fmt.Println("Welcome Admin!")
	} else {
		fmt.Println("Access Denied")
	}
}

In the above code, the authentication is improper because there is no validation of the password input, meaning any user can gain access by simply providing the username "admin" without a password.
```

### Remediation

```go
The most effective way to remediate CWE-287 is to implement strong authentication methods. This includes using two-factor authentication (2FA) or multi-factor authentication (MFA) when users log in. This means that users will be required to provide at least two pieces of evidence in order to authenticate, such as a username and a password, or a username and a one-time code sent to their phone. Additionally, organizations should implement strong password policies, such as requiring passwords of a certain length and complexity. Finally, organizations should also implement regular checks to ensure that users are not sharing their credentials with others.
```

### Semgrep Rule

```yaml
rule = {
	meta:
		description = "Detects improper authentication"
		author = "Your Name"
		date = "2020-08-10"
	source: 
		language = "Go"
		exclude = ["vendor/*"]
		include = ["*.go"]
		
	constant:
		login = ["authenticate", "log in", "logon", "sign in", "signon"]
		noAuth = ["without authentication", "unauthenticated",]
		
	detection:
		any_call:
			patterns:
				- pattern: "{login}({noAuth})"
				  message: "Improper authentication detected"
				  confidence: high
				  severity: critical
```

### CodeQL Rule

```ql
import cwe287

class ImproperAuthenticationDetector {
    // Checks for insecure authentication mechanisms
    vulnerabilty pattern ImproperAuthentication {
        // Identify calls to authentication functions with weak parameters
        AuthenticationMechanism(p)
        where p.isWeak()
    }

    // Reports instances of weak authentication
    from ImproperAuthentication
    report("Weak authentication mechanism detected at line @{line}")
}
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability where a developer has hard-coded credentials into a program. This means that the credentials are stored in the program's source code, rather than being stored in an external repository where they can be changed or updated. This can leave the system vulnerable to attack, as the credentials could be used to access the system or its data without proper authorization. As well, hard-coded credentials can be difficult to change or update if necessary, making the system even more vulnerable.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome!")
	})

	// Hardcoded credentials
	username := "admin"
	password := "password123"

	http.ListenAndServe(":8080", nil)
}
```

### Remediation

```go
// Before Remediation
username := "admin"
password := "password"

// After Remediation
// Read credentials from environment variables
username := os.Getenv("USERNAME")
password := os.Getenv("PASSWORD")
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-798-hardcoded-credentials",
  patterns: [
    {
      pattern: 'password="(.*?)"',
      message: "Hard-coded credentials detected",
      severity: "WARNING"
    }
  ]
}
```

### CodeQL Rule

```ql
import go

class HardCodedCredentials extends Query {
  predicate isHardCodedCreds(s: string) {
    s contains("username") or
    s contains("password")
  }

  predicate isLiteralString(e: Expr) {
    e instanceof go.StringLiteral
  }

  predicate isHardCodedCredsLiteral(e: Expr) {
    isLiteralString(e) and isHardCodedCreds(e.value)
  }

  predicate isCredsPassedToAPI(f: Function, e: Expr) {
    f.name = "api" and
    f.hasParameter("username") and
    f.hasParameter("password") and
    f.calls(e)
  }

  // Vulnerability detect
  vulnerability as V
```

## CWE-276: Incorrect Default Permissions

### Description

The CWE-276 vulnerability is caused by granting permissions to a file or resource that are too broad. This allows any user to access the resource without the proper credentials or authorization. This can result in unauthorized users having access to files or resources that should be restricted, leading to a potential security breach. Additionally, this could allow malicious users to modify or delete files, or access sensitive data.

### Vulnerable Code

```go
package main 

import "os"

func main() {

  //This is vulnerable code since it creates a file with default permissions of 0666
  f, err := os.Create("test.txt")
  if err != nil {
    panic(err)
  }
  defer f.Close()
}
```

### Remediation

```go
Remediation for this vulnerability would involve setting the appropriate permissions for any files or directories that have been set with incorrect default permissions. This can be accomplished by using the chmod command. For example, if a directory needs to have read, write, and execute permissions for the owner, execute permissions for the group, and no permissions for other users, the command would be:

chmod 750 /path/to/directory
```

### Semgrep Rule

```yaml
rule = {
  strings: $file_create = /open\s*\(.*,\s*os\.O_CREATE/
  condition: $file_create
  message: "Incorrect default permissions on file creation detected"
  severity: "warning"
}
```

### CodeQL Rule

```ql
import go

class BadPermissions extends GoChecker {
  // Rule to detect incorrect default permissions set on files or directories
  predicate isWrongPerm(f File) {
    exists(p : Permission | p.file == f && p.hasPerm != 0644)
  }
  
  // This predicate will detect any files or directories with incorrect permissions
  predicate findBadPermissions() {
    exists(f : File | isWrongPerm(f))
  }
  
  // Check for the wrong permission
  checkers {
    // Check for incorrect default permissions
    check findBadPermissions()
      description("Check if incorrectly set default permissions have been found.")
      hasProblem
  }
}
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that exposes sensitive information to an unauthorized actor. This vulnerability can occur when an application does not have proper authentication and authorization controls in place. An attacker can then gain access to this sensitive information, which can lead to data breaches, identity theft, and more. Sensitive information can include passwords, credit card numbers, and other personal data. To mitigate this vulnerability, organizations should implement strong authentication and authorization controls to ensure that only authorized users can access sensitive information.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username") // Vulnerable code
		password := r.URL.Query().Get("password")
		
		fmt.Fprintf(w, "Username: %s\nPassword: %s", username, password)
	})
	
	http.ListenAndServe(":8080", nil)
}

This code is vulnerable because it is passing the username and password in plaintext in the URL query string. This means that the username and password can be captured by anyone who is monitoring the network traffic, which is an unauthorized actor.
```

### Remediation

```go
The best way to remediate this vulnerability is to ensure that sensitive information is only accessible to authorized users. This can be done by implementing robust authentication protocols, such as two-factor authentication, and enforcing strong passwords. Additionally, data should be encrypted whenever possible, and access to sensitive information should be restricted to only those who need it. Finally, regular audits should be performed to ensure that the access controls are still in place and working correctly.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-200-exposure-of-sensitive-information",
  patterns: [
    {
      pattern: "* := * <- *",
      message: "Access of sensitive information without proper authorization",
      severity: "warning"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe200

class CWE_200_Vulnerability:
	// Matches if a sensitive data is exposed to an unauthorized actor
	// via a function call
	@Cwe200
	predicate isVulnerable(funcName, dataName){
		Expr.call(funcName) and Expr.member(dataName) and 
		!Authorization.authorized(dataName)
	}
}
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 is a vulnerability that occurs when credentials or other security-critical data is stored in a manner that allows it to be accessed by unintended parties. This can occur when credentials are stored in plain text or with insufficiently strong encryption, or if authentication systems are not sufficiently secure. Attackers can gain access to these credentials, potentially allowing them to access sensitive information or carry out malicious actions.

### Vulnerable Code

```go
package main

import (
	"fmt"
)

func main() {
	username := "admin"
	password := "password123" // This password is insufficiently protected

	fmt.Println("Username:", username)
	fmt.Println("Password:", password)
}
```

### Remediation

```go
One remediation approach for CWE-522 is to ensure that all credentials used to access sensitive data are encrypted. This can be done by using encryption libraries and secure protocols when storing, transmitting, and receiving credentials. Additionally, any user-generated passwords should be hashed using a secure algorithm before being stored in the database. Finally, access to credentials should be restricted to only those who absolutely need it.
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-522-Insufficiently-Protected-Credentials",
  patterns: [
    // matches hardcoded credentials
    pattern: "const %{var:credential} = %{string:value}",
    // matches credentials in plaintext
    pattern: "var %{var:credential} = %{string:value}",
    // matches credentials stored in plaintext
    pattern: "storage.%{var:credential} = %{string:value}"
  ],
  message: "CWE-522: Insufficiently Protected Credentials found in {{$credential}}",
  severity: "CRITICAL"
}
```

### CodeQL Rule

```ql
import Go
import Security

class InsufficientlyProtectedCredentials extends Go.CallGraph {
  Expr authFunction
  
  predicate isAuthFunction(Function f) {
    f.hasAnnotation("auth")
  }
  
  InsufficientlyProtectedCredentials() {
    authFunction := this.getFunction("auth")
  }
  
  // Checks if a variable is hardcoded
  predicate isHardcodedCredential(Expr e) {
    e.isLiteral() or e.isStringLiteral()
  }
  
  // Checks if a variable is passed as a parameter
  predicate isParameterCredential(Expr e) {
    e.isParameter()
  }
  
  // Checks if a variable is stored in a global variable
  predicate isGlobalCredential(Expr e) {
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability that occurs when an application parses XML input without properly restricting the ability of malicious actors to reference external entities. This can allow attackers to gain access to sensitive system files, or cause denial-of-service attacks. An attacker can exploit this vulnerability by crafting malicious XML input that contains external entity references, which if left unchecked, can lead to the execution of arbitrary code or disclosure of sensitive information.

### Vulnerable Code

```go
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "http://example.com/data.xml"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Vulnerable code
	// XML external entity reference
	var v struct {
		XMLName xml.Name
		Data    string `xml:"data"`
	}
	if err := xml.
```

### Remediation

```go
The most effective way to prevent XML External Entity (XXE) attacks is to disable the processing of external entities altogether. This can be done by setting the XML parser's "resolveExternalEntities" option to false. For example, in Go's xml package, this can be done as follows:

decoder := xml.NewDecoder(r)
decoder.ResolveEntity = func(publicID, systemID string) (xml.Entity, error) {
    return nil, fmt.Errorf("XXE disabled")
}
```

### Semgrep Rule

```yaml
rule = {
	id: "CWE-611-XML-External-Entity-Reference",
	pattern: "xml.Unmarshal(data)",
	message: "Improper Restriction of XML External Entity Reference (CWE-611)",
	severity: "warning"
}
```

### CodeQL Rule

```ql
import cwe
import go

class Vuln_CWE_611 : go.GoCheck {
 
  // Checks for XML documents that are parsed by the Go language
  // and that contain an external entity reference
  predicate isXMLDoc() {
    exists(go.FuncCall cal | 
      cal.getTarget().matches("encoding/xml.|Unmarshal")
    )
  }
  
  // Checks if a given expression contains an external entity reference
  predicate hasExternalEntityRef(go.Expr e) {
    exists(go.XmlExpr xml | 
      xml.getKind() = go.XmlExprKind.EntityRef
      and e = xml.getExpr()
    )
  }
  
  // Checks if any of the function calls being analyzed contain an external entity reference
  predicate is
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

CWE-918 is a type of vulnerability that occurs when an application makes a server-side request to a URL or file that is outside of its control. The malicious request can be used to access resources that the application should not have access to, such as internal network services or other applications. This vulnerability can be exploited to gain unauthorized access to data, or to cause a denial of service.

### Vulnerable Code

```go
package main

import (
    "net/http"
    "log"
    "io/ioutil"
)

func main() {
    // Read in the contents of a URL 
    resp, err := http.Get("http://example.com")
    if err != nil {
        log.Fatal(err)
    }

    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
    }
    log.Println(string(body))
}

The code above is vulnerable to Server Side Request Forgery (SSRF) because it does not validate the URL supplied by the user, allowing them to request arbitrary URLs. This could be exploited to access internal services that should not be publicly exposed.
```

### Remediation

```go
1) Implement a whitelist of allowed IP addresses and/or domains to limit requests to known, trusted sources.
2) Use parameterized requests to ensure that requests cannot be modified in transit.
3) Perform input validation and output encoding to mitigate against malicious payloads.
4) Implement rate limiting to reduce the likelihood of brute-force attacks.
5) Monitor logs for suspicious requests.
6) Utilize web application firewalls to block malicious requests.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "CWE-918: Server-Side Request Forgery (SSRF)"
      author = "Semgrep"
    strings:
      $url = /[a-zA-Z]+:\/\/[a-zA-Z0-9:._~%#?&=+/-]+/
    condition:
      $url
}
```

### CodeQL Rule

```ql
import cwe_918

class SSRFVulnerability(cwe_918.Vulnerability):
    def __init__(self):
        cwe_918.Vulnerability.__init__(self)

    def predicate(self, q):
        return q.FindFunction("http.NewRequest").HasCall("net/http.Client.Do")
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a type of vulnerability that allows attackers to inject malicious commands into a program or system. This can be done by manipulating user input and sending it to a program or system in a way that it is executed as a command. This can lead to data being compromised or malicious code being executed. It is considered a serious security risk and should be addressed as soon as possible.

### Vulnerable Code

```go
package main

import "fmt"

func main() {
	userInput := ""
	fmt.Print("Please enter a command: ")
	fmt.Scan(&userInput)
	
	// Vulnerable code:
	result := exec(userInput)
	fmt.Println(result)
}

func exec(command string) string {
	// Execute command here
}
```

### Remediation

```go
// Before remediation
command := fmt.Sprintf("run cmd %s", userInput)
exec.Command(command)

// After remediation
command := fmt.Sprintf("run cmd %s", sanitize(userInput))
exec.Command(command)

// Function for sanitizing user input
func sanitize(input string) string {
    // Replace all special characters with a space
    return strings.ReplaceAll(input, "[^a-zA-Z0-9]", " ")
}
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-077",
  patterns: [
    {
      pattern: "exec(\"${{param}}\")",
      message: "Potential command injection detected",
      severity: "WARNING"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe077

class CWE_077_Command_Injection:
  string command
 
  // Find any command-executing functions that are passed user-controlled inputs
  // without proper sanitization
  query command_injection_sources {
    Call c
    CommandExecution cce
    cce.targets(c)
    c.receiver.type.name = "os/exec"
    c.argument.value.sources(input)
  }
 
  // Report issues for sources that are not properly sanitized
  vulnerability as Vulnerability cwe077.CommandInjection(command_injection_sources, command) {
    message = "Command injection vulnerability detected."
  }
}
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295 is an improper certificate validation vulnerability that occurs when an application fails to properly validate the authenticity and validity of digital certificates. This type of vulnerability can allow an attacker to bypass authentication or encryption using a malicious, invalid, or self-signed digital certificate. It can also allow an attacker to impersonate a valid user or service by using a valid digital certificate. This vulnerability can be particularly dangerous when used in conjunction with a man-in-the-middle attack.

### Vulnerable Code

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	// Create an insecure client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make a request to an HTTPs endpoint
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	// Print the response
	fmt.Println(resp)
}

In the code above, the client is configured to skip certificate validation. This could
```

### Remediation

```go
// Before:
resp, err := http.Get(url)

// After:
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}
resp, err := client.Get(url)
```

### Semgrep Rule

```yaml
rule = {
	id: cwe-295-certificate-validation-vuln,
	severity: error,
	pattern: (
				(tls | crypto)\.
				(
					VerifyPeerCertificate |
					InsecureSkipVerify
				)
			),
	message: "Insecure certificate validation detected."
}
```

### CodeQL Rule

```ql
import cwe295
import go

class CWE295_ImproperCertificateValidation implements Rule {
  // List of packages which should be excluded from analysis
  // to prevent false positives
  private static readonly excludedPackages = ["crypto/x509"]

  // Finds calls to certificate validation methods
  private predicate ValidateCertificateCall(Expr node) {
    return
      (node instanceof go.CallExpr) and
      (node.func.name == "VerifyHostname" or
       node.func.name == "VerifyPeerCertificate" or
       node.func.name == "VerifyCertificate") and
      not excludedPackages.contains(node.func.pkg)
  }

  // Finds declarations of certificates
  private predicate CertDeclaration(Expr node) {
    return
      (node instanceof
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability which occurs when user-supplied input is not properly sanitized, allowing malicious code to be injected into the application. In the context of Go, this vulnerability can occur when user-supplied input is passed to functions like exec.Command() or template.Execute() without proper validation, allowing the attacker to inject malicious code into the application. This can lead to the application executing arbitrary code, resulting in a serious security breach.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		execCommand := "curl " + url
		fmt.Println(execCommand)
		fmt.Fprintln(w, execCommand)
	})

	http.ListenAndServe(":8080", nil)
}

In this example, the application is vulnerable to code injection. The application is taking an input from the URL query parameter "url" and executing a curl command with that input. If an attacker is able to craft an appropriate input, they can inject malicious code into the application.
```

### Remediation

```go
// Remediation example

package main

import (
	"os"
	"strings"
)

func main() {
	// Get user input
	input := os.Args[1]
	
	// Sanitize user input to avoid code injection
	safeInput := strings.ReplaceAll(input, ";", "")
	
	// Pass safe input to the program
	// ...
}
```

### Semgrep Rule

```yaml
rule = {
    strings:
        $cmd = /.*/
    condition:
        $cmd
}
```

### CodeQL Rule

```ql
import cwe094

class CWE094Rule extends Rule {
    // Rule definition
    meta {
        // Rule metadata
        // The following example is for a rule that detects CWE-094
        // Improper Control of Generation of Code ('Code Injection')
        // For more information, see https://cwe.mitre.org/data/definitions/94.html
        id = "CWE-094"
        description = "Improper Control of Generation of Code (Code Injection)"
        author = "Example company"
        severity = Severity.CRITICAL
        references = ["https://cwe.mitre.org/data/definitions/94.html"]
    }
    
    // Query definition 
    predicate isInjection(stmt: Statement) {
        // Statement is considered a code injection if it is an invocation of an
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 is a type of vulnerability related to improper privilege management. It occurs when an application fails to properly manage user privileges, allowing users with lower privileges to access or modify data or files that should be restricted to users with higher privileges. This could include allowing users to modify system files, access confidential data, or perform other actions that should not be allowed by their user level.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("/bin/sh", "-c", `cat /etc/shadow`)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(output))
}

In this code, the application is executing a command as a privileged user without proper authentication or authorization, allowing users with access to the application to gain unauthorized access to privileged files.
```

### Remediation

```go
One example of remediation for CWE-269 would be to ensure that the privileges assigned to each user are tailored to the user's specific job duties. For example, if a user only needs to access certain files, they should only be granted access to those specific files instead of being given general administrative privileges. Additionally, any unused privileges should be revoked and access control lists should be set up to ensure that only authorized users can access the system.
```

### Semgrep Rule

```yaml
rule = "

import "syscalls"

syscall.setgid as x

+

syscall.setuid as y

-

syscall.setresgid as z

"
message = "Improper privilege management detected: using setgid and setuid without using setresgid"
severity = "warning"
```

### CodeQL Rule

```ql
import cwe269

class CWE269ImproperPrivilegeManagement:
    // Detects code where an application mismanages user privileges
    // to perform an action that should only be available to certain 
    // users or processes.
    //
    // The rule flags functions that grant access or privileges to 
    // users or processes without proper checks.
    def vulnerable_functions():
        // Retrieves functions that grant access or privileges
        // to users or processes.
        return cwe269.getVulnerableFunctions()
    
    def vulnerable_code():
        // Retrieves vulnerable code from the functions
        // identified above.
        return cwe269.getVulnerableCode()
    
    // Flags code that is vulnerable to CWE-269
    vulnerable_code() {
      message("Improper privilege management detected")
    }
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is a type of injection vulnerability which occurs when an application fails to properly validate or neutralize special elements used in an expression language statement. It allows an attacker to inject malicious code into an application or system which can be used to manipulate or extract data from the system. This vulnerability is particularly dangerous as it can be used to inject malicious code with access to sensitive information.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable code
		queryParam := r.URL.Query().Get("username")
		fmt.Fprintf(w, "Hello %s!", queryParam)
	})
	http.ListenAndServe(":8080", nil)
}

In this example, the code is vulnerable to Expression Language Injection because it is directly using the query parameter, `queryParam`, in the `fmt.Fprintf` call without properly sanitizing the input. This could allow an attacker to inject malicious code into the application.
```

### Remediation

```go
In Go, the most common way to remediate Expression Language Injection vulnerabilities is to use the html.EscapeString() function. This function takes a string as an argument and returns a string where any special characters have been replaced with their HTML escaped equivalents. 

For example, suppose a user input is stored in a variable called "userInput". To prevent expression language injection, the following code should be used:

escapedUserInput := html.EscapeString(userInput)
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Detects potential Expression Language Injection"
      severity = "CRITICAL"
    source:
      language = "go"
    patterns:
      - pattern: |
          template.Parse(string)
        message: "Potential Expression Language Injection detected"
        contexts:
          - context:
              source:
                binary:
                  function: "template.Parse"
}
```

### CodeQL Rule

```ql
import cwe917

class CWE917ExpressionLanguageInjection:
	
	// Finds suspicious uses of the expression language
	// which may be vulnerable to injection
	@CWE917
	@CxPCQuery("CWE917ExpressionLanguageInjection")
	def getVulnerableExpressions():
		
		// Finds suspicious uses of the expression language
		// which may be vulnerable to injection
		expr = Find.allExpressions(Go.Expression)
			.where(e | e.isExpressionLanguage())
			
		// Finds suspicious uses of the expression language
		// which may be vulnerable to injection
		return expr.select(e | e.containingFunction())
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability that occurs when an application fails to properly check the location of a file before accessing it. This can allow an attacker to manipulate the program by redirecting the access to a malicious file, which can be used to exploit the application. This can happen when an application follows a link to a file without validating the link, which can lead to the application accessing a file from an unexpected location.

### Vulnerable Code

```go
package main

import (
	"io/ioutil"
	"log"
	"os"
)

func main() {
	pwd, _ := os.Getwd()
	fileName := "../../../../../../etc/passwd"
	filePath := pwd + fileName
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
}

In the above example, the code is vulnerable to CWE-059 because the file path used to read the file is not properly normalized, allowing an attacker to navigate outside the intended directory. This can lead to information disclosure, or overwrite of sensitive files.
```

### Remediation

```go
The following code snippet shows an example of remediation for CWE-059. The code checks whether a file is a symbolic link before accessing it to ensure that the link target is safe:

// Check if the file is a symbolic link
if fi, err := os.Lstat(filePath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
	// Resolve the link target
	if target, err := os.Readlink(filePath); err == nil {
		// Check if the link target is safe
		if isSafeLinkTarget(target) {
			// Access the link target
			// ...
		}
	}
}
```

### Semgrep Rule

```yaml
rule = {
    meta:
      name = "CWE-059: Improper Link Resolution Before File Access ('Link Following')"
      description = "Detects attempts to follow links without proper access checks first"
      author = "Your Name"
      references = ["https://cwe.mitre.org/data/definitions/59.html"]
      id = "CWE-059"
      severity = "CRITICAL"
      tags = ["CWE", "security"]
    source:
      lang = "go"
    detection:
      condition: all
      patterns:
        - pattern: |
            os.Open(
            (
              (
                "|'.*
              )
            )
          message: |
            Use of os.Open() without proper access checks before following a link.
          source:
            - "**/*.go"
```

### CodeQL Rule

```ql
import cwe059 from CWE-059

class GoImproperLinkResolutionVulnerability implements CodeQLAnalysis {
  CWE059LinkResolutionIssue() {
    // Find code that follows a link
    File f1 = ...;
    File f2 = f1->followLink();
   
    // Find code that accesses the link without verifying its validity
    if (f2.exists()) {
      // Trigger a CWE-059 issue
      cwe059.trigger();
    }
  }
}
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information is transmitted in plaintext over a network. This means that the data is not encrypted and can be easily intercepted and read by anyone on the network. This type of vulnerability can lead to the theft of confidential data such as passwords, financial information, or other sensitive data. It is important to always encrypt sensitive data before sending it over a network to ensure that it remains secure.

### Vulnerable Code

```go
package main

import (
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        username := r.FormValue("username")
        password := r.FormValue("password")

        // Vulnerable code
        resp, _ := http.Get("http://example.com/login?username=" + username + "&password=" + password)
    })
    http.ListenAndServe(":8080", nil)
}

In this example, the username and password are sent over the network as plaintext, which is vulnerable to interception and can lead to a security breach.
```

### Remediation

```go
The best way to remediate CWE-319 is to encrypt all sensitive information before transmitting it over the network. In Go, this can be done using the crypto/tls package to establish a TLS connection and encrypt the data before sending it. Here's an example of how to do this:

// Create a TLS configuration
tlsConfig := &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_
```

### Semgrep Rule

```yaml
rule = {
	severity: "warning"
	pattern: "http://* || ftp://*"
	message: "Cleartext transmission of sensitive information detected"
}
```

### CodeQL Rule

```ql
import cwe319

class CWE319_CleartextTransmissionOfSensitiveInfo:
    // Rule to detect cleartext transmission of sensitive information
    // as defined in CWE-319
    // https://cwe.mitre.org/data/definitions/319.html
   
    // Get list of sensitive information variables
    let sensitiveInfo = cwe319.getSensitiveInfo()

    // Get list of functions used to transmit data
    let transmissionFunctions = cwe319.getTransmissionFunctions()

    // Get list of functions used to encrypt data
    let encryptionFunctions = cwe319.getEncryptionFunctions()

    // Get list of functions used to decrypt data
    let decryptionFunctions = cwe319.getDecryptionFunctions()

    // Get list of functions used to check for encryption
    let encryptionCheckFunctions = cwe
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601, also known as an Open Redirect vulnerability, is a vulnerability that occurs when an application or website redirects an unsuspecting user to a malicious or untrusted website. This type of vulnerability is often used in phishing attacks to lure users to a malicious website, where they may be asked to enter personal information or be exposed to malicious code. Attackers may also use this vulnerability to redirect users to malicious sites that contain malware, viruses, or other malicious content.

### Vulnerable Code

```go
package main

import (
	"fmt"
	"net/http"
)

func redirect(w http.ResponseWriter, r *http.Request) {
	// Get the URL to redirect to
	redirectURL := r.URL.Query().Get("url")

	// Redirect to the URL
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirect)
	fmt.Println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)
}

The code above contains a vulnerability because the URL parameter is not validated before being used for a redirect. This allows attackers to redirect users to malicious sites, which can be used for phishing attacks, malware distribution, or other malicious activities.
```

### Remediation

```go
The following example shows how to prevent open redirects in a Go web application. 

// Parse the URL
url, err := url.ParseRequestURI(req.URL.String())
if err != nil {
    // Handle the error
    return
}

// Check if the URL contains an external domain
if url.Host != req.Host {
    // Redirect to a safe URL
	http.Redirect(w, r, "https://www.example.com/safe-url", http.StatusSeeOther)
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
    severity = "WARNING"
  strings:
    $redir_func = /http\.Redirect/
    $redir_url = /[a-zA-Z]+\:\/\/.+/
  condition:
    $redir_func and $redir_url
}
```

### CodeQL Rule

```ql
import go

import semmle.code.go.ast.expressions.StringLiteral

class UrlRedirectionToUntrustedSite extends Query {
  /**
  * Finds methods that contain a URL redirection to an untrusted site
  */
  vulnerableMethod() {
    MethodCall m1;
    StringLiteral redirectionUrl;

    m1 = this.methodCallThatInvokesRedirection()
    redirectionUrl = m1.getArgumentExpr(0)
    // Finds methods that contain a URL redirection to an untrusted site
    //  (i.e. URLs that have not been whitelisted)
    redirectionUrl.isUntrustedUrl()
    m1@isVulnerable
  }

  methodCallThatInvokesRedirection() {
    // Finds methods that could cause a redirection
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is a vulnerability in which sensitive information is inadvertently inserted into a log file. This can occur if a log file does not have proper protections in place and allows for sensitive information to be inadvertently stored in the log file. Sensitive information can include usernames and passwords, session tokens, credit card numbers, and other confidential information. An attacker can exploit this vulnerability to gain access to sensitive information, potentially leading to data breaches or other malicious activity.

### Vulnerable Code

```go
f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
if err != nil {
    log.Fatal(err)
}

// Write sensitive information to the log file
fmt.Fprintln(f, "username: admin, password: password123")

// Close the file
defer f.Close()
```

### Remediation

```go
One way to remediate this vulnerability is to use an application that allows for the filtering of sensitive information from log files. This will ensure that any sensitive information is not included in the log files and is kept secure. Additionally, the application should include a feature to alert the system administrator when a log file has been created that contains sensitive information. This will allow the system administrator to take appropriate action in order to protect the sensitive information.
```

### Semgrep Rule

```yaml
rule = {
    id: cwe-532-insertion-of-sensitive-information-into-log-files
    patterns:
     - pattern: log.Print(...)
       message: "Sensitive information is being inserted into a log file"
       severity: WARNING
    meta:
     author: "Your Name"
}
```

### CodeQL Rule

```ql
import sys
import cwe532

class CWE532LogInsertionRule(cwe532.LogInsertionRule):
  def __init__(self):
    cwe532.LogInsertionRule.__init__(self)

  def get_vulnerability_entries(self, file, language):
    if language != "Go":
      return []
    
    entries = []
    # Look for functions that write to log files
    for func in cwe532.get_write_functions(file):
      # Look for calls to functions that take sensitive data as parameters
      for call in func.called_functions():
        for param in call.parameters():
          if cwe532.is_sensitive_data(param):
            entries.append(call.location)
    return entries
```


# JavaScript

## CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

Cross-site scripting (XSS) is a type of vulnerability that occurs when a malicious website or script injects malicious code into a web page. The vulnerability occurs when user input is not properly sanitized or validated, allowing the malicious code to be executed in the user's browser. This can lead to a variety of malicious activities, such as hijacking user accounts, stealing user data, or redirecting the user to a malicious website. XSS is particularly dangerous because it can be used to spread malware and malicious code, and can even be used to conduct phishing attacks.

### Vulnerable Code

```javascript
// This code is vulnerable to Cross-site Scripting
let userInput = document.getElementById('userInput').value;
document.write('<h1>' + userInput + '</h1>');
```

### Remediation

```javascript
// Before
<script>
var userInput = prompt('Please enter your name');
document.write('Hello ' + userInput + '!');
</script>

// After
<script>
var userInput = prompt('Please enter your name');
document.write('Hello ' + escapeHTML(userInput) + '!');

function escapeHTML(unsafeText) {
    return unsafeText
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
</script>
```

### Semgrep Rule

```yaml
rule = {
	meta:
		author = "John Doe"
		description = "Detects improper neutralization of input during web page generation"
		severity = "high"
		confidence = "high"
	
	strings:
		$input_1 = /<[^>]*[^\/]>.*[^<\/]$/
		
	condition:
		$input_1
}
```

### CodeQL Rule

```ql
import cwe080
import semmle.code.cpp.security.InputValidation

class XSSVulnerability extends SecurityFlow {
  XSSVulnerability() {
    this = XSSVulnerability.generateStartFlow()
  }

  predicate isVulnerableInput(InputValidation::SanitizedData data) {
    not data.isTrusted()
  }

  predicate isSanitization(InputValidation::Sanitization sanitization) {
    sanitization.sanitizes(this.getArgument(0))
  }

  // Find flows from tainted input to sink
  from TaintedInput = InputValidation::TaintedData.all()
  to XSSSink = cwe080.XSSSink()
  such that
    // Require vulnerable input
    isVulnerableInput(TaintedInput) and
    // Require
```

## CWE-020: Improper Input Validation

### Description

Improper input validation is a vulnerability that occurs when an application does not properly validate or sanitize user input. This can lead to malicious code being injected into the application, allowing an attacker to gain access to sensitive data or perform malicious activities. In JavaScript, this vulnerability can occur if user input is used in any sort of dynamic evaluation, such as an eval() statement, or if user input is used as a parameter in a function call.

### Vulnerable Code

```javascript
function handleInput(inputData) {
  // Do some processing
  // ...

  // Store input without any kind of validation
  const result = storeInput(inputData);

  return result;
}
```

### Remediation

```javascript
// Before
let userInput = req.body.input;
let result = doSomething(userInput);

// After
let userInput = req.body.input;
let sanitizedInput = sanitizeInput(userInput);
let result = doSomething(sanitizedInput);
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-020-Improper-Input-Validation",
  patterns: [
    // detect if input is not being sufficiently validated
    pattern: "if (input == * || input != *)"
  ],
  message: "Improper input validation detected",
  severity: "error"
}
```

### CodeQL Rule

```ql
import javascript

class ImproperInputValidation extends Rule {
  // Query to detect the vulnerability
  query vulnerableCode() {
    // Finds all instances of user input being used without proper input validation
    UserInput ui | 
    // Finds all instances of eval being used with the input
    EvalCall ec where ec.argument = ui
  }
  
  // Reports a warning when the vulnerability is detected
  meta:
    severity = "warning"
    description = "Improper input validation can lead to remote code execution vulnerability"
}
```

## CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Description

OS Command Injection is a type of vulnerability that occurs when an attacker is able to inject malicious commands into an operating system via a vulnerable application. It allows the attacker to gain access to the system and run unauthorized code with the privileges of the vulnerable application. This type of attack can be used to gain access to confidential data, manipulate files, or even take control of the system.

### Vulnerable Code

```javascript
// Vulnerable code
let userInput = req.query.input;
let cmd = `rm -rf ${userInput}`;
exec(cmd);
```

### Remediation

```javascript
// BEFORE
const userInput = req.body.command;

const result = execSync(userInput);

// AFTER
// Sanitize user input
const userInput = req.body.command.replace(/[^a-zA-Z ]/g, "");

// Escape any special characters
const escapedInput = userInput.replace(/[\W]/g, "\\$&");

// Execute the command
const result = execSync(escapedInput);
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-078-OS-Command-Injection-Detection",
  patterns: [
    {
      pattern: "(exec|spawn|system|popen|passthru|shell_exec|proc_open|`) *\\(",
      message: "Possible OS Command Injection detected.",
      severity: "CRITICAL"
    }
  ]
}
```

### CodeQL Rule

```ql
import os

class CWE078_OS_Command_Injection:
 
  // Detect when an application invokes a system command without properly
  // sanitizing user-supplied input
 
  os.exec*
  and not sanitize*
  and not whitelist*
```

## CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### Description

CWE-089 is a type of injection attack in which a malicious user is able to insert arbitrary SQL code into a web application and use it to access, modify or delete data in a database. This vulnerability is caused by a lack of proper input validation, allowing an attacker to inject code into an application and manipulate the underlying database. This can result in data being leaked, modified, or deleted, and can lead to other security issues such as privilege escalation.

### Vulnerable Code

```javascript
//This code allows user input to be directly inserted into a SQL query without proper encoding or sanitization

let userInput = req.body.userInput;

let query = `SELECT * FROM users WHERE name = ${userInput}`;

conn.query(query, (err, result) => {
  if (err) {
    console.log(err);
  } else {
    console.log(result);
  }
});
```

### Remediation

```javascript
// Before Remediation
const query = "SELECT * FROM users WHERE username = '" + username + "'";

// After Remediation
const query = "SELECT * FROM users WHERE username = ?";
const usernameParam = [username];
connection.query(query, usernameParam);
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects SQL injection vulnerability"
    severity = "CRITICAL"
    author = "Semgrep"
  strings:
    $sqli_pattern = /(\bconcat\b.*\bselect\b|\bselect\b.*\bconcat\b|\bunion\b.*\bselect\b|\bselect\b.*\bunion\b|\bupdate\b.*\bset\b|\bset\b.*\bupdate\b)/
  condition:
    $sqli_pattern
}
```

### CodeQL Rule

```ql
import cwe089

class CWE089_Vulnerability:
  // finds queries that have not been properly escaped
  // or use parameterized queries
  // to prevent SQL injection
  // https://cwe.mitre.org/data/definitions/89.html
 
  // find all SQL queries
  sql_query_literal = regex "\\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\\b"
 
  // find assignments to variables
  assignment_expression = 
    // find right hand side expression
    expr rhs 
    // followed by assignment operator
    where rhs.contains(sql_query_literal) 
    // and left hand side as a variable
    where rhs.hasAssignee()
 
  // find function calls
  function_call = 
    // find
```

## CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Description

Path Traversal is a vulnerability that occurs when an attacker is able to access files and directories that are outside of the intended directory structure. In JavaScript, this vulnerability can be caused by applications that allow user input to modify the path of a file or directory that is accessed. For example, if an application requests a file from a specific directory and the user input is used to modify the path, an attacker can craft a malicious input that would allow them to access files outside of the intended directory.

### Vulnerable Code

```javascript
// vulnerable code
const path = require('path');

const userInput = '/../../etc/passwd';  // user controlled input

const filePath = path.join(__dirname, userInput);

fs.readFile(filePath, (err, data) => {
  // potentially malicious code
});
```

### Remediation

```javascript
//Before
let filePath = req.query.path;

//After
let filePath = path.join(__dirname, req.query.path);
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-022",
  patterns: [
    // Detects attempts to access a restricted directory
    pattern: 'file.open(**/*)',
    message: 'Accessing a restricted directory is not allowed',
    severity: 'warning'
  ]
}
```

### CodeQL Rule

```ql
import cwe022

class PathTraversalVulnerability extends Vulnerability {
  PathTraversalVulnerability() {
    super(cwe022.CWE_022);
  }

  @Override
  predicate isVulnerable(Node node) {
    // Check for calls to functions that could lead to a path traversal vulnerability
    return exists(node,
      // Functions that accept a file path as an argument
      call("fopen", _)
        or call("fread", _)
        or call("readlink", _)
        or call("exec", _)
        or call("system", _)
        or call("popen", _)
        or call("opendir", _)
        or call("open", _)
      // Functions that accept a directory path as an argument
      or call("mkdir", _)
        or call("
```

## CWE-352: Cross-Site Request Forgery (CSRF)

### Description

Cross-site request forgery (CSRF) is a type of attack that occurs when a malicious website, email, or program causes a user’s web browser to perform an unwanted action on a trusted site for which the user is currently authenticated. This type of attack takes advantage of the trust that a website has for a user’s browser, forcing the user’s browser to send requests to the trusted site without the user’s knowledge or consent. This type of attack can be used to perform various malicious actions such as updating account information, making purchases, or transferring funds.

### Vulnerable Code

```javascript
<script>
  function submitForm() {
    var form = document.getElementById("form");
    form.action = "https://vulnerable-website.com/process";
    form.submit();
  }
</script>
<form action="" id="form" method="post">
  <input type="hidden" name="user_name" value="hacker">
  <input type="hidden" name="password" value="12345">
  <input type="submit" onclick="submitForm()" value="Submit">
</form>

In this code, an attacker can craft a malicious link or an image that points to this form and automatically submit it without the user's knowledge. This is because the form submission is triggered by the onclick event and the form is automatically submitted without any user input. This is an example of a Cross-Site Request Forgery (CSRF)
```

### Remediation

```javascript
The best way to remediate a CSRF vulnerability is to use the Synchronizer Token Pattern. This requires the application to generate a unique token for each request and to verify the token on the server-side before processing the request.

First, the application must generate a unique token for each request. This token should be cryptographically strong, randomized, and unpredictable. The token should also have an expiration time.

Next, the application should include the token with each request as a hidden input field in the form or as a query parameter.

Finally, the application should verify the token on the server-side before processing the request. The server should check that the token is valid, has not expired, and that it matches the token stored in the user's session. If the token is invalid, the request should be rejected.
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects Cross-Site Request Forgery (CSRF) vulnerability"
    id = "RULE_ID"
    severity = "high"
  source:
    languages = ["JavaScript"]
  patterns:
    - pattern: '<form[^>]*method="post"[^>]*>'
      message: "Possible CSRF vulnerability detected"
}
```

### CodeQL Rule

```ql
import cwe

class CWE352_CrossSiteRequestForgery_Detector extends SecurityCodeScannerRule {

  // rule to detect cross-site request forgery (CSRF)
  CWE352CrossSiteRequestForgery() {
    when {
        // checks if request is coming from a different origin
        cwe.OriginCheck()
    }
    then {
        // raises a security warning if the request is coming from a different origin
        report SecurityWarning("Cross-site request forgery detected")
    }
  }

}
```

## CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

CWE-434 is a type of vulnerability that allows an attacker to upload a file with a dangerous type such as a malicious script, executable code, or other type of malicious file, to a web application or server. The application does not properly validate the file type or restrict the types of files that can be uploaded. This allows malicious users to upload malicious files onto the server, which can then be used to gain access to the server, execute malicious code, or exfiltrate data from the application or server.

### Vulnerable Code

```javascript
let fileInput = document.getElementById("fileInput");
let fileData = fileInput.files[0];
let fileName = fileData.name;

// extract the file extension
let fileExtension = fileName.substr(fileName.lastIndexOf(".") + 1);

// create an array of allowed file types
let allowedFileTypes = ['.jpg','.gif','.png'];

// check if the file extension is allowed
if(allowedFileTypes.includes(fileExtension)){
    // upload file
    let fileURL = uploadFile(fileData);
}
```

### Remediation

```javascript
The best way to remediate this vulnerability is to restrict the types of files that can be uploaded to the application. This can be done by adding a whitelist of allowed file types and rejecting any files that do not match the whitelist. For example, the following code could be used to ensure that only JPG and PNG files are allowed to be uploaded:

// Whitelist of allowed file types
const allowedTypes = [".jpg", ".png"];

// Check if the uploaded file matches a whitelisted type
if (allowedTypes.includes(file.type)) {
    // Upload file
    ...
} else {
    // Reject file
    ...
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects unrestricted upload of file with dangerous type"
    severity = "WARNING"
    id = "CWE-434"
    tags = ["security", "cwe-434"]
  source: 
    languages = ["JavaScript"]
  detection:
  	condition: |
      (call (id "fopen") (string.contains_re ".*\.(bat|exe|com|sh|reg|vbs|scr|js|php)$") )
}
```

### CodeQL Rule

```ql
import cwe434

class CWE434_Unrestricted_Upload_of_File_with_Dangerous_Type extends Rule {
  // Query identifies code that allows unrestricted file uploads of dangerous types
  // such as executable files
  //
  // This query looks for calls to functions that allow file uploads,
  // such as a web form or API, and checks if the file type is not restricted
  // to only safe files, such as images and text files.
  //
  // If the file type is not restricted, this query raises an issue.
  //
  // This rule is marked as CWE-434, Unrestricted Upload of File with Dangerous Type.
 
  // Find any calls to functions that allow file uploads
  // such as web forms or API functions
  predicate isFileUploadFunctionCall(CallExpr ce) {
    // ...
  }
```

## CWE-306: Missing Authentication for Critical Function

### Description

CWE-306 is a vulnerability where a critical function on a website, application, or system does not have authentication enabled to protect it from unauthorized access. This means that anyone can access the function, regardless of their credentials or access privileges, and can potentially use it to cause damage or to steal sensitive data. This type of vulnerability is particularly dangerous because it can be used to gain access to confidential information or to manipulate data in a malicious way.

### Vulnerable Code

```javascript
let username = "";
let password = "";

function performCriticalOperation() {
    // perform action that requires authentication
}

if (username !== "" && password !== "") {
    performCriticalOperation();
}
```

### Remediation

```javascript
// Before Remediation

function deleteRecord(recordId) {
  const record = findRecordById(recordId);
  deleteFromDatabase(record);
}

// After Remediation

function deleteRecord(recordId, userId) {
  const record = findRecordById(recordId);
  if (record.ownerId === userId) {
    deleteFromDatabase(record);
  }
}
```

### Semgrep Rule

```yaml
rule = { 
  meta: 
    description = "Detects missing authentication for critical functions" 
    id = "CWE-306" 
  strings: 
    $function_call = "critical_function" 
  condition: 
    not all of them ($function_call) at (parameters.count == 0)
}
```

### CodeQL Rule

```ql
import cwe
import semmle.CodeGen.CGlobals

class MissingAuthForCriticalFunction extends SecurityChecker {
    // Checks for functions that lack authentication
    // when access to them should be restricted
    predicate isCriticalFunction() {
        //Enter here the name of the functions that should be restricted
        //with authentication
    }
    
    @Override
    check(CFunctionCallExpr call) {
        if (call.getTarget().matches(isCriticalFunction())) {
            //Check if the function call lacks authentication
            //If authentication is missing, raise an issue
            if (!call.hasAuthentication()) {
                report(call.getTarget(), "Missing authentication for critical function", cwe.CWE_306);
            }
        }
    }
}
```

## CWE-502: Deserialization of Untrusted Data

### Description

CWE-502 is a vulnerability related to the deserialization of untrusted data. This vulnerability occurs when an application or system attempts to deserialize data from an untrusted source, such as user input or a remote source, without properly validating the data. Attackers can exploit this vulnerability by modifying the data before it is deserialized, allowing them to inject malicious code into the application or system. This can lead to remote code execution, access to sensitive data, and other malicious activities.

### Vulnerable Code

```javascript
let userData = JSON.parse(req.body.userData);

// vulnerable code
let adminAccess = userData.admin;
if (adminAccess) {
   // grant admin privileges
   grantAdminPriviledges();
} 

In this example, userData is parsed from an untrusted source, which could contain malicious code. If the malicious code sets adminAccess to true, the application will grant admin privileges without verifying that the user is actually an administrator. This can lead to arbitrary code execution and other security issues.
```

### Remediation

```javascript
// Example of serialization
const dataToSerialize = {
    id: 123,
    name: "John Doe"
};

// Serializing the data
const serializedData = JSON.stringify(dataToSerialize);

// Example of deserialization
// Remediation using try/catch
try {
    const deserializedData = JSON.parse(serializedData);
} catch (err) {
    console.error('Unable to deserialize data');
}
```

### Semgrep Rule

```yaml
rule = {
  meta: {
    id: "CWE-502",
    description: "Deserialization of untrusted data",
    severity: "critical"
  },
  pattern: [
    {
      regexp: /JSON\.parse\(.*\)/
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe

class DeserializationOfUntrustedDataVulnerability(cwe.Vulnerability):
  def __init__(self):
    self.id = 502
    self.name = "Deserialization of Untrusted Data"
    self.description = "The application deserializes untrusted data without properly validating it, allowing an attacker to inject malicious objects into the application"
    
class DeserializationOfUntrustedDataQuery(cwe.Query):
  def __init__(self):
    self.vulnerability = DeserializationOfUntrustedDataVulnerability()
  
  def getQuery(self):
    return (
      from deserializationCall in Call
      where deserializationCall.getTarget().hasAnnotation("java.io.ObjectInputStream.readObject")
      select deserializationCall
    )
```

## CWE-287: Improper Authentication

### Description

CWE-287 is a vulnerability related to authentication. It occurs when authentication procedures are not properly implemented or enforced, allowing unauthorized users to gain access to restricted resources. This vulnerability can allow malicious users to gain access to a system, including gaining access to confidential or sensitive information. Additionally, improper authentication can also allow attackers to bypass authentication mechanisms or modify authentication data.

### Vulnerable Code

```javascript
// This code assumes that the 'username' and 'password' variables have been set somewhere else in the program

let authenticated = false;

if (username === "admin" && password === "password") {
  authenticated = true;
}

if (authenticated) {
  // Execute code that requires authentication
}
```

### Remediation

```javascript
// Before Remediation

const user = getUserFromRequest();

if (user.name) {
  // Perform an action
}

// After Remediation

const user = getUserFromRequest();

if (user.name && user.authenticated) {
  // Perform an action
}
```

### Semgrep Rule

```yaml
rule = ["source.lang.js", rule_id: "CWE-287-Improper-Authentication", message: "Improper Authentication detected",
	      condition: "if (auth !== user && auth !== pass) { return false; }"]
```

### CodeQL Rule

```ql
import cwe287

class CWE287ImproperAuthenticationRule extends Rule {
  // Look for authentication attempts
  // where the username or password is not
  // securely checked
 
  // Find authentication attempts
  // where the username or password is not
  // securely checked
 
  // This query looks for use of login()
  // methods which are not using a secure
  // authentication method
  query LoginCall {
    LoginCall = call("login")
    where not exists (
      Method m 
      such that m.id = LoginCall.callee 
      and m.hasAnnotation("cwe287")
    )
  }
 
  // This query reports the vulnerability
  // if a login() call is found without
  // using a secure authentication method
  vulnerability CWE287ImproperAuthentication {
    when = LoginCall
```

## CWE-798: Use of Hard-coded Credentials

### Description

CWE-798 is a vulnerability in which an application or system uses hard-coded credentials that are stored in the code. This means that secure information, such as usernames and passwords, are stored directly in the source code, making them visible to anyone who has access to the code. This can expose the system to potential hackers or malicious actors who can use the credentials to access sensitive data or change system settings. This vulnerability can be especially dangerous if the credentials are used in multiple systems, as a breach in one system can lead to a breach in all systems.

### Vulnerable Code

```javascript
//Example of vulnerable code 
let username = "admin";
let password = "password123";

if (username == "admin" && password == "password123") {
    //Allow user access
} else {
    //Deny access
}
```

### Remediation

```javascript
// Before 
const username = 'admin';
const password = 'password123';

// After 
const username = process.env.USERNAME;
const password = process.env.PASSWORD;
```

### Semgrep Rule

```yaml
rule = id:"CWE-798-hardcoded-credentials"
     message:"Possible use of hard-coded credentials detected"
     severity:"WARNING"
     patterns:[
         {pattern:"const username = \"[a-zA-Z0-9]+\"", kind: "literal"},
         {pattern:"const password = \"[a-zA-Z0-9]+\"", kind: "literal"}
     ]
```

### CodeQL Rule

```ql
import cwe
import javascript

class HardcodedCredentialsVulnerability extends Rule {
  // Query to detect instances of hardcoded credentials
  // where a string literal is assigned to a variable
  // inside a javascript file
  getMatches() {
    let strings = VariableAssignment.objects({
      rhs: StringLiteral
    })
    .select(s => s.parent.parent.parent)
    .filter(f => f instanceof javascript.File)
  
    return strings.filter(s => {
      return s.hasDescendant(d => d.isInstanceOf(StringLiteral) &&
        (d.string.contains("username") || d.string.contains("password") || 
        d.string.contains("passcode")));
    })
  }
  
  // Report instances of hardcoded credentials
```

## CWE-276: Incorrect Default Permissions

### Description

CWE-276 Incorrect Default Permissions is a vulnerability that occurs when a software application assigns incorrect default permissions for files and directories. This could include granting non-privileged users access to sensitive resources, or granting an overly broad set of permissions to files or directories. This vulnerability can be used to gain unauthorized access to files or system resources, and can lead to other security issues such as data leakage or data manipulation.

### Vulnerable Code

```javascript
fs.chmodSync("/tmp/myfile.txt", 0755);

The code above sets the permissions for the file "/tmp/myfile.txt" to 0755. This may be too permissive and allow anyone to read and write to the file. To reduce the risk, it is best to set the permissions to a more secure value, such as 0644 or 0600.
```

### Remediation

```javascript
// Before remediation
fs.writeFile('data.txt', 'This is some data', (err) => {
  if (err) {
    console.error(err);
  }
});

// After remediation
fs.writeFile('data.txt', 'This is some data', { mode: 0o600 }, (err) => {
  if (err) {
    console.error(err);
  }
});
```

### Semgrep Rule

```yaml
rule = {
  meta: {
    id: "CWE-276",
    description: "Incorrect Default Permissions",
    author: "Example Security Team"
  },
  strings: {
    // Detects when file permissions are set to 777
    $permissions = /777/
  },
  condition: $permissions
}
```

### CodeQL Rule

```ql
import cwe276

class IncorrectDefaultPermissions extends Rule {
  // Rule definition
  getQuery() {
    return (
      // Get all assignments of the target to a new object
      // with an incorrect permission
      Query.fromIndex("assignments", cwe276.IncorrectPermissionsAssignment)
    )
  }
 
  // Rule body
  afterQuery(query) {
    query.forEach(result => {
      // Warn about the incorrect permission
      const permission = result.permission;
      this.report(result.target, "Incorrect permission: " + permission);
    });
  }
}
```

## CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

### Description

CWE-200 is a vulnerability that occurs when sensitive information is exposed to an unauthorized actor. This can include information such as passwords, financial data, health records, or other confidential information. This vulnerability can occur when an application is not properly secured, allowing a malicious actor to access sensitive data without proper authentication or authorization. Additionally, this vulnerability can occur when data is sent over an insecure network connection, or when data is stored in an unprotected environment.

### Vulnerable Code

```javascript
// Vulnerable code
let userInfo = {
  name: 'John Doe',
  address: '123 Main Street',
  ssn: '123-45-6789'
};

// Assume this is a public API endpoint
app.get('/userInfo', (req, res) => {
  res.json(userInfo);
});
```

### Remediation

```javascript
// Before
const userData = {
  name: 'John Smith',
  ssn: '123-45-6789'
};

// After
const userData = {
  name: 'John Smith'
};

const ssn = '123-45-6789';

// Ensure that ssn is not exposed to an unauthorized actor
if (userData.ssn === ssn) {
  // Perform sensitive action
}
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects exposure of sensitive information to unauthorized actors"
    severity = "high"
    reference = "CWE-200"
  strings:
    $sensitive_info = /(private|confidential)/
  condition:
    $sensitive_info
}
```

### CodeQL Rule

```ql
import javascript

class SensitiveInfoExposure extends Rule {
  // Query to detect the sensitive information exposure
  Query exposureQuery {
    // Find all variable declarations
    VarDecl[kind]
    // and assignments to them
    (AssignExpr[left](_, VarRef[name == kind.name]))
    // which contain data whose value could be considered sensitive
    | (AssignExpr[left] (_, StringLiteral[value contains "password"]))
    | (AssignExpr[left] (_, NumberLiteral[value contains "credit card"]))
    | (AssignExpr[left] (_, BooleanLiteral[value contains "sensitive"]))
    // and which are not within a try/catch block
    where not getAncestor(TryStmt)
  }

  // Report any matches of the query
  get
```

## CWE-522: Insufficiently Protected Credentials

### Description

CWE-522 occurs when credentials are stored in an insecure manner, such as in plain text or with weak encryption. This can allow an attacker to gain access to the credentials and use them for malicious purposes. Without adequate protection, attackers can easily access the credentials and use them to gain access to sensitive resources.

### Vulnerable Code

```javascript
// Vulnerable code example
let username = 'admin';
let password = 'admin123';

// This code sends the username and password to an API endpoint
let apiEndpoint = 'http://www.example.com/api/login';
let response = fetch(apiEndpoint, {
    method: "POST",
    body: JSON.stringify({ username: username, password: password })
});
```

### Remediation

```javascript
When storing credentials, they should always be encrypted and stored securely. For example, instead of storing plaintext passwords, use a library like bcrypt or PBKDF2 to hash the passwords before storing them. Additionally, make sure to use a secure encryption algorithm and key for encrypting the credentials. Finally, it's best practice to use two-factor authentication (2FA) when available to add an extra layer of security.
```

### Semgrep Rule

```yaml
rule = {
    meta:
      description = "Insufficiently Protected Credentials"
      severity = "WARNING"
    strings:
      $cred1 = /(username|password|passcode|pin|token|hash|key)/
    condition:
      $cred1 @/[^A-Za-z0-9$&+,:;=?@#|'<>.^*()%!-]/
}
```

### CodeQL Rule

```ql
import cwe522

class InsufficientlyProtectedCredentialsRule extends Rule {
  // rule definition
  Boolean vulnerable(Credential c) {
    return exists(Method m, 
      m.getName() == "checkCredentials" 
      && m.getParameters().includes(c)
      && !m.hasAnnotation(cwe522.SecureCredentialStorage)
    )
  }

  // query definition
  query InsufficientlyProtectedCredentials() {
    Credential c
    vulnerable(c)
  }
}
```

## CWE-611: Improper Restriction of XML External Entity Reference

### Description

CWE-611 is a vulnerability involving the improper restriction of XML External Entity References. This vulnerability allows an attacker to access files and other resources on the system by leveraging an XML document that contains a reference to an external entity. By doing so, the attacker can gain access to data that should otherwise be restricted. The attacker can also execute malicious code on the system by exploiting the vulnerability.

### Vulnerable Code

```javascript
let parser = new DOMParser();
let xml = '<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>';

let doc = parser.parseFromString(xml, "text/xml");

console.log(doc.documentElement.firstChild.nodeValue);
```

### Remediation

```javascript
// Before
let parser = new DOMParser();
let xmlDoc = parser.parseFromString(xmlString, "text/xml");

// After
let parser = new DOMParser();
let xmlDoc = parser.parseFromString(xmlString, "text/xml", {
  forbidExternal: true,
  allowAmpersand: false,
  resolveExternalEntities: false
});
```

### Semgrep Rule

```yaml
rule = {
  meta:
    severity = "medium"
    description = "Detects improper restriction of XML external entity references"
    author = "Security Team"
  strings:
    $x1 = /<[\s]*[Xx][Mm][Ll]/
    $x2 = /[Ee][Nn][Tt][Ii][Tt][Yy]/
    $x3 = /[Ss][Yy][Ss][Tt][Ee][Mm]/
  condition:
    $x1 and $x2 and $x3
}
```

### CodeQL Rule

```ql
import cwe

class VulnerableXmlExternalEntityReference(cwe.Vulnerability):

  // Find XML documents which contain an external entity reference
  // with an unrestricted system identifier
  @Find("$x := /XmlDocument/ExternalEntityRef/@systemId")
  def vulnerable(x: Expr):
    if $x.isUnrestricted():
      return [cwe.CWE_611]
```

## CWE-918: Server-Side Request Forgery (SSRF)

### Description

Server-Side Request Forgery (SSRF) is a type of vulnerability which allows an attacker to send malicious requests from the vulnerable server to other internal or external systems. This vulnerability can allow the attacker to gain access to sensitive information and potentially compromise systems. The attacker can use the vulnerable server as a proxy to bypass authentication and authorization controls and attack other systems.

### Vulnerable Code

```javascript
fetch('http://localhost:8080/?url=' + request.query.url)
  .then(response => response.text())
  .then(body => {
    // Do something with body
  });

This code is vulnerable to SSRF because it takes the value of the 'url' parameter from the request object and uses it in a fetch call. This means an attacker could craft a malicious request and cause the server to make a request to a site of their choosing.
```

### Remediation

```javascript
//Before
const request = require('request');

// user supplied url
let userURL = req.query.url;

request(userURL, (err, resp, body) => {
    if (err) {
        // error handling
    }
    else {
        // do something with the body
    }
});

//After
const request = require('request');

// user supplied url
let userURL = req.query.url;

// whitelist only approved domains
let whitelist = [
	'https://example.com',
	'https://example2.com'
];

// check if the userURL is in the whitelist
if (whitelist.includes(userURL)) {
	request(userURL, (err, resp, body) => {
		if (err) {
			// error handling
```

### Semgrep Rule

```yaml
rule = {
  patterns: [
    {
      pattern: "fetch('$URL$')",
      message: "Possible Server-Side Request Forgery (SSRF) vulnerability detected",
      severity: "CRITICAL"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe
import semmle.code.cpp.dataflow.TaintTracking

class ServerSideRequestForgeryVulnerability extends CweRule {
    ServerSideRequestForgeryVulnerability() {
        super(cwe.CWE_918_SSRF)
    }

    @Override
    Boolean predicate(Trusted<Node> startNode) {
        // Find all nodes that take user input
        Trusted<Node> sourceNode := startNode.sourceNodes(TaintTracking.sources)

        // Find all nodes that perform a request or open a connection
        Trusted<Node> sinkNode := startNode.sinkNodes(TaintTracking.sinks)
        (exists (Trusted<Node> n | n.hasDescendant(sinkNode)))
    }
}
```

## CWE-077: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### Description

Command injection is a vulnerability that occurs when an attacker is able to execute arbitrary commands on a system by manipulating the inputs to an application. This is typically done by passing malicious input to an application that is then used to execute commands in the underlying operating system. These commands can be used to access sensitive data, delete files, or even manipulate the entire system. This vulnerability can be exploited in a wide range of contexts, including web applications, operating system commands, and even embedded systems.

### Vulnerable Code

```javascript
let userInput = document.getElementById('input').value;
let command = `rm -rf ${userInput}`;

// Execute the command
exec(command);
```

### Remediation

```javascript
//Before:

const userInput = req.body.query;
const query = `SELECT * FROM table_name WHERE column_name=${userInput}`;

//After:

const userInput = req.body.query;
const query = `SELECT * FROM table_name WHERE column_name=?`;
const values = [userInput];
const sanitizedQuery = mysql.format(query, values);
```

### Semgrep Rule

```yaml
rule = {
  meta: 
    description = "Detects potential command injection vulnerabilities"
    severity = "CRITICAL"
  source: 
    patterns: 
    - pattern: 'exec(.+)'
  detection:
    condition: all
}
```

### CodeQL Rule

```ql
import cwe077

class CWE_077_Command_Injection extends Rule {
  // Checks for command injection
  getCallsTo: {
    // Checks for any calls to exec or system
    exec | system
  }

  // Report any matches
  getMatches {
    // Check for any call to exec or system
    call, sym <- getCallsTo
    if sym.name == "exec" or sym.name == "system"
    report cwe077 call
  }
}
```

## CWE-295: Improper Certificate Validation

### Description

CWE-295 is a vulnerability that occurs when an application fails to properly validate X.509 certificates. This vulnerability can allow attackers to gain access to sensitive information by bypassing the authentication process, spoofing a user, or tampering with the communication between two systems. Additionally, attackers can use this vulnerability to execute malicious code on the target system. This vulnerability can be exploited by manipulating the certificate's contents, such as the domain name, public key, or digital signature.

### Vulnerable Code

```javascript
//This code will fail to properly validate the server certificate
//and may result in a man-in-the-middle attack.

var xhr = new XMLHttpRequest();
xhr.open("GET", "https://example.com");
xhr.send();

//This code should be modified to properly validate the server certificate
//and reject the connection if the certificate is invalid.

var xhr = new XMLHttpRequest();
xhr.open("GET", "https://example.com");
xhr.setRequestHeader("Authorization", "Basic " + btoa(username + ":" + password));
xhr.sslVerifyPeer = true;
xhr.sslVerifyHost = true;
xhr.send();
```

### Remediation

```javascript
//Before Remediation
let cert = fs.readFileSync('cert.pem');

//After Remediation
let cert = fs.readFileSync('cert.pem');
let certData = crypto.certificate.parse(cert);
let valid = crypto.verifyCertificateChain(certData);
if (!valid) {
   throw new Error('Invalid Certificate');
}
```

### Semgrep Rule

```yaml
rule = {
  id: "detect-improper-certificate-validation-vulnerability",
  patterns: [
    pattern: "(request|fetch|axios).(cert|ca).(check|verify|validate)",
    message: "Possible improper certificate validation vulnerability detected",
    severity: "WARNING"
  ]
}
```

### CodeQL Rule

```ql
import os
import cwe

class ImproperCertificateValidation(cwe.Rule):
  def __init__(self):
    cwe.Rule.__init__(self, "CWE-295")

  def check(self, qctx, obj):
    if (obj.name == "XMLHttpRequest" and
        "open" in obj.calls and
        any(arg.value == "https://" for arg in obj.calls.open.args)):
      qctx.report(obj.calls.open, "Improper certificate validation may lead to a vulnerability (CWE-295)")
```

## CWE-094: Improper Control of Generation of Code ('Code Injection')

### Description

CWE-094 is a type of code injection vulnerability which occurs when an application allows user-supplied input to be injected into a code template, or does not properly validate or sanitize the user-supplied data before it is used to generate code. This type of vulnerability can be exploited by attackers to inject malicious code into a program which can be used to gain access to sensitive information, or to cause the application to execute arbitrary or unintended code.

### Vulnerable Code

```javascript
//User input stored as 'userInput'
var userInput = "userInput";

//Vulnerable code
eval(userInput);
```

### Remediation

```javascript
// Before
const userInput = req.query.name;
eval(userInput);

// After
const userInput = req.query.name;
const sanitizedInput = sanitizeInput(userInput);
eval(sanitizedInput);
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-094",
  patterns: [
    {
      pattern: "{command}(${string}|${number})",
      message: "Improper control of code generation detected. Possible code injection attack.",
      severity: "error"
    }
  ]
}
```

### CodeQL Rule

```ql
import cwe094

class CWE094_Improper_Control_of_Generation_of_Code_Injection:
  //CWE-094: Improper Control of Generation of Code ('Code Injection')
  //Vulnerability occurs when user input is injected into a code generation process.
  //This can lead to arbitrary code execution.
  //This rule looks for code that takes user input that is used to generate code in
  //a way that is not properly validated.
 
  boolean vulnerable(Function func) {
    //Find all call expressions
    Expr callExpr = func.allCallExprs()
    //Find all functions that take user input
    Callable userInputFunc = callExpr.calls(builtin.getUserInput())
    //Find all functions that generate code
    Callable codeGeneratorFunc = callExpr
```

## CWE-269: Improper Privilege Management

### Description

CWE-269 is a type of vulnerability related to privilege management. It occurs when an application or system fails to properly assign and manage privileges, resulting in granting users more access than they should have. This can allow users to access or manipulate data that they shouldn't be able to, which can lead to data breaches or other malicious activities.

### Vulnerable Code

```javascript
// User input is taken without validating it first
let userRole = prompt('What is your role?');

// User role is used for authorization without further checks
if (userRole == 'admin') {
    // Admin privileges
    doAdminAction();
} else {
    // Normal privileges
    doNormalAction();
}
```

### Remediation

```javascript
// Before
function addUser(userInfo) {
  let user = new User(userInfo);
  user.save();
}

// After
function addUser(userInfo) {
  let user = new User(userInfo);
  user.setRole('USER');  // Set the user's role to USER
  user.save();
}
```

### Semgrep Rule

```yaml
rule = {
        meta:
          description = "Detects improper privilege management"
          severity = "MEDIUM"
        source:
          languages = ["JavaScript"]
        detection:
          condition: any(
            // All functions that call setuid
            // or setgid should be inspected
            m.name == "setuid"
            m.name == "setgid"
          )
        }
```

### CodeQL Rule

```ql
import cwe269

class ImproperPrivilegeManagement extends Rule {
    // This rule searches for any statements that create or modify
    // privileges without explicit authorization checks
   
    // Query to find any statements that create or modify privileges
    // without explicit authorization check
    query alwaysFails {
        find assignPrivilege(_, _) 
    }
   
    // This is the main rule query
    query cwe269_ImproperPrivilegeManagement {
        // Find any assignment of privilege
        assignPrivilege as var(func: <assignPrivilege>)
       
        // And check that there is no explicit authorization check
        // before the privilege is assigned
        not {
            some func @requiresAuth(func)
        }
       
        // Report the assignment of privilege as a vulnerability
        vulnerability(func: uid(assignPrivilege)) {
            c
```

## CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

### Description

CWE-917 is a vulnerability that occurs when an application fails to properly neutralize special elements used in an expression language statement or expression. Expression language injection is a type of attack in which an attacker injects malicious code into an expression language statement or expression, allowing the attacker to gain access to sensitive information or execute malicious code on the system. This vulnerability can be exploited in multiple ways, such as manipulating the code to return true or false conditions, manipulating the application logic, and performing remote code execution.

### Vulnerable Code

```javascript
let userInput = '${request.parameterMap["someParam"]}';
let query = 'SELECT * FROM users WHERE username = ' + userInput;
db.query(query);

In this example, the code is vulnerable to expression language injection because user input is directly being appended to a query string without any validation or sanitization.
```

### Remediation

```javascript
// Before
let query = "SELECT * FROM users WHERE id = " + req.params.id;

// After
let query = "SELECT * FROM users WHERE id = ?";
let params = [req.params.id];

// Run the query
db.query(query, params, (err, result) => {
  // Handle the query results
});
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-917-expression-language-injection",
  pattern: {
    regexp: "(?<!\\w)(?:[^\\w]?)(?:[{])(?:[^\\w]?)(?:[#])(?:[^\\w]?)(?:[{])(?:.*)(?:[}])(?:[^\\w]?)(?:[}])(?!\\w)",
    message: "Possible Expression Language Injection Vulnerability detected"
  }
}
```

### CodeQL Rule

```ql
import cwe917

class CWE917ExpressionLanguageInjection extends Rule {
  // Query to detect potential Expression Language Injection
  // vulnerabilities
  Query potentialInjection() {
    // Find EL statements
    ExpressionStatement elStmt =
      find pattern elStmt: ExpressionStatement 
      where elStmt.getExpression().isEL()
    // Find uses of user input in EL statements
    Expression inputExpr =
      find pattern inputExpr: Expression
      where inputExpr.usesUserInput()
    // Find uses of user input in EL statements
    select elStmt, inputExpr
    such that elStmt.getExpression().contains(inputExpr)
  }

  // Test to detect actual Expression Language Injection
  // vulnerabilities
  Test cwe917Test() {
    // Find EL statements
    ExpressionStatement
```

## CWE-059: Improper Link Resolution Before File Access ('Link Following')

### Description

CWE-059 is a vulnerability where an application follows a link without properly verifying that the link is valid and secure. This can lead to an attacker being able to access sensitive files or data that the application is not authorized to view. For example, an attacker can provide a malicious link in a web page, which an application may follow, allowing the attacker to gain access to confidential data.

### Vulnerable Code

```javascript
let filePath = "../test/test.txt"; 
let file = fs.readFileSync(filePath); 

In this example, the code is vulnerable to improper link resolution before file access. By using the relative path "../test/test.txt", the code can access files outside of the intended directory structure, which can lead to security vulnerabilities.
```

### Remediation

```javascript
The following code example shows the use of the realpath function to ensure that any relative links used in the application are resolved correctly before any file operations take place.

var fs = require('fs');

// Resolve relative links in path before opening the file
var path = fs.realpathSync(filename);

fs.open(path, 'r', function(err, fd) {
  // File operations
});
```

### Semgrep Rule

```yaml
rule = {
  meta:
    description = "Detects improper link resolution before file access vulnerability"
    author = "Security Team"
    date = "2020-08-12"
  strings:
    $file_var = /.*/
  condition:
    $file_var and not @resolve(@file($file_var))
}
```

### CodeQL Rule

```ql
import cwe_059

class CWE059 : Vulnerability {
  /**
   * Finds instances of improper link resolution before file access.
   */
  private predicate isImproperLinkResolution(Expr link, Expr file) {
    // Check if the file argument is a string literal
    not isStringLiteral(file)
  }

  /**
   * Finds functions that are vulnerable to improper link resolution.
   */
  private static predicate isVulnerableFunction(Function func) {
    // Check if the function is a file access function
    isFileAccessFunction(func)
  }

  /**
   * Checks if the given function is a file access function.
   */
  private static predicate isFileAccessFunction(Function func) {
    // Checks if the given function is a file access function
    func.hasName("open") or func.
```

## CWE-319: Cleartext Transmission of Sensitive Information

### Description

CWE-319 is a vulnerability that occurs when sensitive information is transmitted over a network in cleartext instead of being encrypted. This type of vulnerability can be exploited by attackers who can intercept the data in transit and gain access to the sensitive information. This can have serious consequences such as identity theft, financial loss, or other malicious activity. In order to fix this vulnerability, organizations should ensure that all sensitive information is encrypted before being sent over a network.

### Vulnerable Code

```javascript
const http = require('http');

http.createServer(function (req, res) {
  let userInfo = {
    username: req.body.username,
    password: req.body.password
  };

  let data = JSON.stringify(userInfo);

  // Vulnerable code
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.write(data);
  res.end();

}).listen(8080);
```

### Remediation

```javascript
// Before
const apiUrl = 'http://example.com/api';

// After
const apiUrl = 'https://example.com/api';
```

### Semgrep Rule

```yaml
rule = [{
  id: "CWE-319-detection",
  patterns: ["send(params.password=*)"],
  message: "Sensitive information is being transmitted over a cleartext protocol.",
  severity: "WARNING"
}]
```

### CodeQL Rule

```ql
import cwe319

class CleartextTransmissionVulnerability implements Rule {
  // Query to detect Cleartext Transmission of Sensitive Information
  query CleartextTransmission() {
    // Find constructor calls of classes that allow sending data over
    // unencrypted connections
    ClassType cls
    where cls.derivesFrom("java.net.URLConnection")
    or cls.derivesFrom("java.net.HttpURLConnection")
    or cls.derivesFrom("java.net.HttpClient")
    or cls.derivesFrom("javax.net.ssl.HttpsURLConnection")
    or cls.derivesFrom("org.apache.http.impl.client.CloseableHttpClient")
    or cls.derivesFrom("org.apache.http.client.HttpClient")
    or cls.derivesFrom("
```

## CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### Description

CWE-601 is a vulnerability that occurs when an application redirects a user to an untrusted site. This type of vulnerability can be exploited by malicious actors to redirect users to malicious websites, which can result in the user's credentials being stolen or malicious code being injected onto the user's machine. This vulnerability is especially dangerous when the URL redirection is used to bypass authentication or authorization checks, as the malicious actor can access the target website without any authentication or authorization credentials.

### Vulnerable Code

```javascript
// The following code will allow a malicious user to redirect the page to an untrusted website
let pageRedirect = window.location.href;
let redirectURL = getParameterByName('redirect');
window.location.href = redirectURL;
```

### Remediation

```javascript
// Before
window.location.href = getURLParameter('redirect');

// After
if (isValidRedirectUrl(getURLParameter('redirect'))) {
  window.location.href = getURLParameter('redirect');
} else {
  window.location.href = '/error';
}

function isValidRedirectUrl(url) {
  // Perform validation here
}
```

### Semgrep Rule

```yaml
rules:
  - id: open-redirect
    message: "Potential open redirect vulnerability detected."
    severity: WARNING
    patterns:
    - pattern: |
        window.location = $url
        window.open($url)
      filters:
      - not:
          any:
            - pattern: "//[A-Za-z0-9.-]*{{hostname}}"
            - pattern: "//localhost"
            - pattern: "//127.0.0.1"
            - pattern: "//0.0.0.0"
            - pattern: "//[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

### CodeQL Rule

```ql
import cwe601

class UntrustedRedirection:
  // Define the query in the form of a CodeQL predicate
  predicate isUntrustedRedirection(CallExpr call) {
  	// Check if the call is an HTTP redirect
  	exists(Method meth |
  		meth.getName() == "redirect" and
  		meth.getClass().getName() == "HttpResponse" and
  		meth.getClass().getModule().matches(".*http.*") and
      call.getTarget() == meth
  	)
  }

  // Check if the URL passed to the redirect is untrusted
  @Cwe601
  predicate vulnerableToCwe601(CallExpr call) {
  	isUntrustedRedirection(call) and
  	exists(Expr arg |
```

## CWE-532: Insertion of Sensitive Information into Log File

### Description

CWE-532 is an issue where an application writes sensitive information, such as passwords, credit card numbers, or other confidential data, into a log file. This can lead to unintended disclosure of the information if an attacker is able to gain access to the log files. Furthermore, if log files are left in an unsecured location, or are not properly monitored, the sensitive data can be accessed by unauthorized personnel.

### Vulnerable Code

```javascript
// Logging a user's password in plain text
let username = 'user123';
let password = 'password123';

console.log('Username: ' + username + ' Password: ' + password);
```

### Remediation

```javascript
// Remediation

// Replace sensitive information with a generic string
function sanitizeLogs(logData) {
  return logData.replace(/[A-Za-z0-9]{10,20}/g, '*****');
}

// Write log data to a file
fs.writeFile('logs.txt', sanitizeLogs(logData), (err) => {
  if (err) {
    console.log("Error writing to log file");
  }
});
```

### Semgrep Rule

```yaml
rule = {
  id: "CWE-532-detection",
  patterns: [
    // detect log functions
    { pattern: "console.log(/sensitive_information/)" },
    { pattern: "console.warn(/sensitive_information/)" },
    { pattern: "console.error(/sensitive_information/)" },
    { pattern: "console.info(/sensitive_information/)" },
    { pattern: "console.debug(/sensitive_information/)" },
    { pattern: "console.trace(/sensitive_information/)" },

    // detect other logging methods
    { pattern: "logger.log(/sensitive_information/)" },
    { pattern: "logger.warn(/sensitive_information/)" },
    { pattern: "logger.error(/sensitive_information/)" },
    { pattern: "log
```

### CodeQL Rule

```ql
import cwe532

class CWE532_LogFileInsertion extends Rule {
  // Check for logging of sensitive information into log files
  query insertSensitiveInfoLogFile() {
    // Find all log statements
    LogStatement[] logStatements =
      // Find all logging statements
      // (e.g. console.log, console.error, etc.)
      find LogStatement(_);

    // For each LogStatement
    for (LogStatement logStmt : logStatements) {
      // Find all sensitive information
      SensitiveData[] sensitiveData =
        // Find all sensitive information
        find SensitiveData(_);

      // Check if sensitive information is being logged
      if (exists(logStmt.args, sensitiveData)) {
        // Report as CWE-532 vulnerable
        report cwe532.VulnerableLogging(logStmt
```


