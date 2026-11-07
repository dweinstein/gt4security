Class {
	#name : 'Gt4SecurityCwe',
	#superclass : 'Object',
	#instVars : [
		'id',
		'description',
		'source'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'cwe catalog' }
Gt4SecurityCwe class >> descriptionFor: anId [
	"Canonical description for a CWE id, or nil if unknown."
	^ self knownDescriptions at: anId ifAbsent: [ nil ]
]

{ #category : 'instance creation' }
Gt4SecurityCwe class >> id: aString [
	"Create a CWE from just an ID like 'CWE-79'."
	^ self new id: aString; yourself
]

{ #category : 'instance creation' }
Gt4SecurityCwe class >> id: anId description: aDescription source: aSource [
	^ self new
		id: anId;
		description: aDescription;
		source: aSource;
		yourself
]

{ #category : 'catalog' }
Gt4SecurityCwe class >> knownDescriptions [
	"Canonical CWE names from MITRE's Comprehensive CWE List (View-2000).
	Regenerate by evaluating Gt4SecurityCwe class>>#regenerateKnownDescriptions."
	^ Dictionary new
	at: 'CWE-5' put: 'J2EE Misconfiguration: Data Transmission Without Encryption';
	at: 'CWE-6' put: 'J2EE Misconfiguration: Insufficient Session-ID Length';
	at: 'CWE-7' put: 'J2EE Misconfiguration: Missing Custom Error Page';
	at: 'CWE-8' put: 'J2EE Misconfiguration: Entity Bean Declared Remote';
	at: 'CWE-9' put: 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods';
	at: 'CWE-11' put: 'ASP.NET Misconfiguration: Creating Debug Binary';
	at: 'CWE-12' put: 'ASP.NET Misconfiguration: Missing Custom Error Page';
	at: 'CWE-13' put: 'ASP.NET Misconfiguration: Password in Configuration File';
	at: 'CWE-14' put: 'Compiler Removal of Code to Clear Buffers';
	at: 'CWE-15' put: 'External Control of System or Configuration Setting';
	at: 'CWE-20' put: 'Improper Input Validation';
	at: 'CWE-22' put: 'Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'')';
	at: 'CWE-23' put: 'Relative Path Traversal';
	at: 'CWE-24' put: 'Path Traversal: ''../filedir''';
	at: 'CWE-25' put: 'Path Traversal: ''/../filedir''';
	at: 'CWE-26' put: 'Path Traversal: ''/dir/../filename''';
	at: 'CWE-27' put: 'Path Traversal: ''dir/../../filename''';
	at: 'CWE-28' put: 'Path Traversal: ''..filedir''';
	at: 'CWE-29' put: 'Path Traversal: ''..filename''';
	at: 'CWE-30' put: 'Path Traversal: ''dir..filename''';
	at: 'CWE-31' put: 'Path Traversal: ''dir....filename''';
	at: 'CWE-32' put: 'Path Traversal: ''...'' (Triple Dot)';
	at: 'CWE-33' put: 'Path Traversal: ''....'' (Multiple Dot)';
	at: 'CWE-34' put: 'Path Traversal: ''....//''';
	at: 'CWE-35' put: 'Path Traversal: ''.../...//''';
	at: 'CWE-36' put: 'Absolute Path Traversal';
	at: 'CWE-37' put: 'Path Traversal: ''/absolute/pathname/here''';
	at: 'CWE-38' put: 'Path Traversal: ''absolutepathnamehere''';
	at: 'CWE-39' put: 'Path Traversal: ''C:dirname''';
	at: 'CWE-40' put: 'Path Traversal: ''UNCsharename'' (Windows UNC Share)';
	at: 'CWE-41' put: 'Improper Resolution of Path Equivalence';
	at: 'CWE-42' put: 'Path Equivalence: ''filename.'' (Trailing Dot)';
	at: 'CWE-43' put: 'Path Equivalence: ''filename....'' (Multiple Trailing Dot)';
	at: 'CWE-44' put: 'Path Equivalence: ''file.name'' (Internal Dot)';
	at: 'CWE-45' put: 'Path Equivalence: ''file...name'' (Multiple Internal Dot)';
	at: 'CWE-46' put: 'Path Equivalence: ''filename '' (Trailing Space)';
	at: 'CWE-47' put: 'Path Equivalence: '' filename'' (Leading Space)';
	at: 'CWE-48' put: 'Path Equivalence: ''file name'' (Internal Whitespace)';
	at: 'CWE-49' put: 'Path Equivalence: ''filename/'' (Trailing Slash)';
	at: 'CWE-50' put: 'Path Equivalence: ''//multiple/leading/slash''';
	at: 'CWE-51' put: 'Path Equivalence: ''/multiple//internal/slash''';
	at: 'CWE-52' put: 'Path Equivalence: ''/multiple/trailing/slash//''';
	at: 'CWE-53' put: 'Path Equivalence: ''multipleinternalbackslash''';
	at: 'CWE-54' put: 'Path Equivalence: ''filedir'' (Trailing Backslash)';
	at: 'CWE-55' put: 'Path Equivalence: ''/./'' (Single Dot Directory)';
	at: 'CWE-56' put: 'Path Equivalence: ''filedir*'' (Wildcard)';
	at: 'CWE-57' put: 'Path Equivalence: ''fakedir/../realdir/filename''';
	at: 'CWE-58' put: 'Path Equivalence: Windows 8.3 Filename';
	at: 'CWE-59' put: 'Improper Link Resolution Before File Access (''Link Following'')';
	at: 'CWE-61' put: 'UNIX Symbolic Link (Symlink) Following';
	at: 'CWE-62' put: 'UNIX Hard Link';
	at: 'CWE-64' put: 'Windows Shortcut Following (.LNK)';
	at: 'CWE-65' put: 'Windows Hard Link';
	at: 'CWE-66' put: 'Improper Handling of File Names that Identify Virtual Resources';
	at: 'CWE-67' put: 'Improper Handling of Windows Device Names';
	at: 'CWE-69' put: 'Improper Handling of Windows ::DATA Alternate Data Stream';
	at: 'CWE-71' put: 'DEPRECATED: Apple ''.DS_Store''';
	at: 'CWE-72' put: 'Improper Handling of Apple HFS+ Alternate Data Stream Path';
	at: 'CWE-73' put: 'External Control of File Name or Path';
	at: 'CWE-74' put: 'Improper Neutralization of Special Elements in Output Used by a Downstream Component (''Injection'')';
	at: 'CWE-75' put: 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)';
	at: 'CWE-76' put: 'Improper Neutralization of Equivalent Special Elements';
	at: 'CWE-77' put: 'Improper Neutralization of Special Elements used in a Command (''Command Injection'')';
	at: 'CWE-78' put: 'Improper Neutralization of Special Elements used in an OS Command (''OS Command Injection'')';
	at: 'CWE-79' put: 'Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'')';
	at: 'CWE-80' put: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)';
	at: 'CWE-81' put: 'Improper Neutralization of Script in an Error Message Web Page';
	at: 'CWE-82' put: 'Improper Neutralization of Script in Attributes of IMG Tags in a Web Page';
	at: 'CWE-83' put: 'Improper Neutralization of Script in Attributes in a Web Page';
	at: 'CWE-84' put: 'Improper Neutralization of Encoded URI Schemes in a Web Page';
	at: 'CWE-85' put: 'Doubled Character XSS Manipulations';
	at: 'CWE-86' put: 'Improper Neutralization of Invalid Characters in Identifiers in Web Pages';
	at: 'CWE-87' put: 'Improper Neutralization of Alternate XSS Syntax';
	at: 'CWE-88' put: 'Improper Neutralization of Argument Delimiters in a Command (''Argument Injection'')';
	at: 'CWE-89' put: 'Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')';
	at: 'CWE-90' put: 'Improper Neutralization of Special Elements used in an LDAP Query (''LDAP Injection'')';
	at: 'CWE-91' put: 'XML Injection (aka Blind XPath Injection)';
	at: 'CWE-92' put: 'DEPRECATED: Improper Sanitization of Custom Special Characters';
	at: 'CWE-93' put: 'Improper Neutralization of CRLF Sequences (''CRLF Injection'')';
	at: 'CWE-94' put: 'Improper Control of Generation of Code (''Code Injection'')';
	at: 'CWE-95' put: 'Improper Neutralization of Directives in Dynamically Evaluated Code (''Eval Injection'')';
	at: 'CWE-96' put: 'Improper Neutralization of Directives in Statically Saved Code (''Static Code Injection'')';
	at: 'CWE-97' put: 'Improper Neutralization of Server-Side Includes (SSI) Within a Web Page';
	at: 'CWE-98' put: 'Improper Control of Filename for Include/Require Statement in PHP Program (''PHP Remote File Inclusion'')';
	at: 'CWE-99' put: 'Improper Control of Resource Identifiers (''Resource Injection'')';
	at: 'CWE-102' put: 'Struts: Duplicate Validation Forms';
	at: 'CWE-103' put: 'Struts: Incomplete validate() Method Definition';
	at: 'CWE-104' put: 'Struts: Form Bean Does Not Extend Validation Class';
	at: 'CWE-105' put: 'Struts: Form Field Without Validator';
	at: 'CWE-106' put: 'Struts: Plug-in Framework not in Use';
	at: 'CWE-107' put: 'Struts: Unused Validation Form';
	at: 'CWE-108' put: 'Struts: Unvalidated Action Form';
	at: 'CWE-109' put: 'Struts: Validator Turned Off';
	at: 'CWE-110' put: 'Struts: Validator Without Form Field';
	at: 'CWE-111' put: 'Direct Use of Unsafe JNI';
	at: 'CWE-112' put: 'Missing XML Validation';
	at: 'CWE-113' put: 'Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Request/Response Splitting'')';
	at: 'CWE-114' put: 'Process Control';
	at: 'CWE-115' put: 'Misinterpretation of Input';
	at: 'CWE-116' put: 'Improper Encoding or Escaping of Output';
	at: 'CWE-117' put: 'Improper Output Neutralization for Logs';
	at: 'CWE-118' put: 'Incorrect Access of Indexable Resource (''Range Error'')';
	at: 'CWE-119' put: 'Improper Restriction of Operations within the Bounds of a Memory Buffer';
	at: 'CWE-120' put: 'Buffer Copy without Checking Size of Input (''Classic Buffer Overflow'')';
	at: 'CWE-121' put: 'Stack-based Buffer Overflow';
	at: 'CWE-122' put: 'Heap-based Buffer Overflow';
	at: 'CWE-123' put: 'Write-what-where Condition';
	at: 'CWE-124' put: 'Buffer Underwrite (''Buffer Underflow'')';
	at: 'CWE-125' put: 'Out-of-bounds Read';
	at: 'CWE-126' put: 'Buffer Over-read';
	at: 'CWE-127' put: 'Buffer Under-read';
	at: 'CWE-128' put: 'Wrap-around Error';
	at: 'CWE-129' put: 'Improper Validation of Array Index';
	at: 'CWE-130' put: 'Improper Handling of Length Parameter Inconsistency';
	at: 'CWE-131' put: 'Incorrect Calculation of Buffer Size';
	at: 'CWE-132' put: 'DEPRECATED: Miscalculated Null Termination';
	at: 'CWE-134' put: 'Use of Externally-Controlled Format String';
	at: 'CWE-135' put: 'Incorrect Calculation of Multi-Byte String Length';
	at: 'CWE-138' put: 'Improper Neutralization of Special Elements';
	at: 'CWE-140' put: 'Improper Neutralization of Delimiters';
	at: 'CWE-141' put: 'Improper Neutralization of Parameter/Argument Delimiters';
	at: 'CWE-142' put: 'Improper Neutralization of Value Delimiters';
	at: 'CWE-143' put: 'Improper Neutralization of Record Delimiters';
	at: 'CWE-144' put: 'Improper Neutralization of Line Delimiters';
	at: 'CWE-145' put: 'Improper Neutralization of Section Delimiters';
	at: 'CWE-146' put: 'Improper Neutralization of Expression/Command Delimiters';
	at: 'CWE-147' put: 'Improper Neutralization of Input Terminators';
	at: 'CWE-148' put: 'Improper Neutralization of Input Leaders';
	at: 'CWE-149' put: 'Improper Neutralization of Quoting Syntax';
	at: 'CWE-150' put: 'Improper Neutralization of Escape, Meta, or Control Sequences';
	at: 'CWE-151' put: 'Improper Neutralization of Comment Delimiters';
	at: 'CWE-152' put: 'Improper Neutralization of Macro Symbols';
	at: 'CWE-153' put: 'Improper Neutralization of Substitution Characters';
	at: 'CWE-154' put: 'Improper Neutralization of Variable Name Delimiters';
	at: 'CWE-155' put: 'Improper Neutralization of Wildcards or Matching Symbols';
	at: 'CWE-156' put: 'Improper Neutralization of Whitespace';
	at: 'CWE-157' put: 'Failure to Sanitize Paired Delimiters';
	at: 'CWE-158' put: 'Improper Neutralization of Null Byte or NUL Character';
	at: 'CWE-159' put: 'Improper Handling of Invalid Use of Special Elements';
	at: 'CWE-160' put: 'Improper Neutralization of Leading Special Elements';
	at: 'CWE-161' put: 'Improper Neutralization of Multiple Leading Special Elements';
	at: 'CWE-162' put: 'Improper Neutralization of Trailing Special Elements';
	at: 'CWE-163' put: 'Improper Neutralization of Multiple Trailing Special Elements';
	at: 'CWE-164' put: 'Improper Neutralization of Internal Special Elements';
	at: 'CWE-165' put: 'Improper Neutralization of Multiple Internal Special Elements';
	at: 'CWE-166' put: 'Improper Handling of Missing Special Element';
	at: 'CWE-167' put: 'Improper Handling of Additional Special Element';
	at: 'CWE-168' put: 'Improper Handling of Inconsistent Special Elements';
	at: 'CWE-170' put: 'Improper Null Termination';
	at: 'CWE-172' put: 'Encoding Error';
	at: 'CWE-173' put: 'Improper Handling of Alternate Encoding';
	at: 'CWE-174' put: 'Double Decoding of the Same Data';
	at: 'CWE-175' put: 'Improper Handling of Mixed Encoding';
	at: 'CWE-176' put: 'Improper Handling of Unicode Encoding';
	at: 'CWE-177' put: 'Improper Handling of URL Encoding (Hex Encoding)';
	at: 'CWE-178' put: 'Improper Handling of Case Sensitivity';
	at: 'CWE-179' put: 'Incorrect Behavior Order: Early Validation';
	at: 'CWE-180' put: 'Incorrect Behavior Order: Validate Before Canonicalize';
	at: 'CWE-181' put: 'Incorrect Behavior Order: Validate Before Filter';
	at: 'CWE-182' put: 'Collapse of Data into Unsafe Value';
	at: 'CWE-183' put: 'Permissive List of Allowed Inputs';
	at: 'CWE-184' put: 'Incomplete List of Disallowed Inputs';
	at: 'CWE-185' put: 'Incorrect Regular Expression';
	at: 'CWE-186' put: 'Overly Restrictive Regular Expression';
	at: 'CWE-187' put: 'Partial String Comparison';
	at: 'CWE-188' put: 'Reliance on Data/Memory Layout';
	at: 'CWE-190' put: 'Integer Overflow or Wraparound';
	at: 'CWE-191' put: 'Integer Underflow (Wrap or Wraparound)';
	at: 'CWE-192' put: 'Integer Coercion Error';
	at: 'CWE-193' put: 'Off-by-one Error';
	at: 'CWE-194' put: 'Unexpected Sign Extension';
	at: 'CWE-195' put: 'Signed to Unsigned Conversion Error';
	at: 'CWE-196' put: 'Unsigned to Signed Conversion Error';
	at: 'CWE-197' put: 'Numeric Truncation Error';
	at: 'CWE-198' put: 'Use of Incorrect Byte Ordering';
	at: 'CWE-200' put: 'Exposure of Sensitive Information to an Unauthorized Actor';
	at: 'CWE-201' put: 'Insertion of Sensitive Information Into Sent Data';
	at: 'CWE-202' put: 'Exposure of Sensitive Information Through Data Queries';
	at: 'CWE-203' put: 'Observable Discrepancy';
	at: 'CWE-204' put: 'Observable Response Discrepancy';
	at: 'CWE-205' put: 'Observable Behavioral Discrepancy';
	at: 'CWE-206' put: 'Observable Internal Behavioral Discrepancy';
	at: 'CWE-207' put: 'Observable Behavioral Discrepancy With Equivalent Products';
	at: 'CWE-208' put: 'Observable Timing Discrepancy';
	at: 'CWE-209' put: 'Generation of Error Message Containing Sensitive Information';
	at: 'CWE-210' put: 'Self-generated Error Message Containing Sensitive Information';
	at: 'CWE-211' put: 'Externally-Generated Error Message Containing Sensitive Information';
	at: 'CWE-212' put: 'Improper Removal of Sensitive Information Before Storage or Transfer';
	at: 'CWE-213' put: 'Exposure of Sensitive Information Due to Incompatible Policies';
	at: 'CWE-214' put: 'Invocation of Process Using Visible Sensitive Information';
	at: 'CWE-215' put: 'Insertion of Sensitive Information Into Debugging Code';
	at: 'CWE-216' put: 'DEPRECATED: Containment Errors (Container Errors)';
	at: 'CWE-217' put: 'DEPRECATED: Failure to Protect Stored Data from Modification';
	at: 'CWE-218' put: 'DEPRECATED: Failure to provide confidentiality for stored data';
	at: 'CWE-219' put: 'Storage of File with Sensitive Data Under Web Root';
	at: 'CWE-220' put: 'Storage of File With Sensitive Data Under FTP Root';
	at: 'CWE-221' put: 'Information Loss or Omission';
	at: 'CWE-222' put: 'Truncation of Security-relevant Information';
	at: 'CWE-223' put: 'Omission of Security-relevant Information';
	at: 'CWE-224' put: 'Obscured Security-relevant Information by Alternate Name';
	at: 'CWE-225' put: 'DEPRECATED: General Information Management Problems';
	at: 'CWE-226' put: 'Sensitive Information in Resource Not Removed Before Reuse';
	at: 'CWE-228' put: 'Improper Handling of Syntactically Invalid Structure';
	at: 'CWE-229' put: 'Improper Handling of Values';
	at: 'CWE-230' put: 'Improper Handling of Missing Values';
	at: 'CWE-231' put: 'Improper Handling of Extra Values';
	at: 'CWE-232' put: 'Improper Handling of Undefined Values';
	at: 'CWE-233' put: 'Improper Handling of Parameters';
	at: 'CWE-234' put: 'Failure to Handle Missing Parameter';
	at: 'CWE-235' put: 'Improper Handling of Extra Parameters';
	at: 'CWE-236' put: 'Improper Handling of Undefined Parameters';
	at: 'CWE-237' put: 'Improper Handling of Structural Elements';
	at: 'CWE-238' put: 'Improper Handling of Incomplete Structural Elements';
	at: 'CWE-239' put: 'Failure to Handle Incomplete Element';
	at: 'CWE-240' put: 'Improper Handling of Inconsistent Structural Elements';
	at: 'CWE-241' put: 'Improper Handling of Unexpected Data Type';
	at: 'CWE-242' put: 'Use of Inherently Dangerous Function';
	at: 'CWE-243' put: 'Creation of chroot Jail Without Changing Working Directory';
	at: 'CWE-244' put: 'Improper Clearing of Heap Memory Before Release (''Heap Inspection'')';
	at: 'CWE-245' put: 'J2EE Bad Practices: Direct Management of Connections';
	at: 'CWE-246' put: 'J2EE Bad Practices: Direct Use of Sockets';
	at: 'CWE-247' put: 'DEPRECATED: Reliance on DNS Lookups in a Security Decision';
	at: 'CWE-248' put: 'Uncaught Exception';
	at: 'CWE-249' put: 'DEPRECATED: Often Misused: Path Manipulation';
	at: 'CWE-250' put: 'Execution with Unnecessary Privileges';
	at: 'CWE-252' put: 'Unchecked Return Value';
	at: 'CWE-253' put: 'Incorrect Check of Function Return Value';
	at: 'CWE-256' put: 'Plaintext Storage of a Password';
	at: 'CWE-257' put: 'Storing Passwords in a Recoverable Format';
	at: 'CWE-258' put: 'Empty Password in Configuration File';
	at: 'CWE-259' put: 'Use of Hard-coded Password';
	at: 'CWE-260' put: 'Password in Configuration File';
	at: 'CWE-261' put: 'Weak Encoding for Password';
	at: 'CWE-262' put: 'Not Using Password Aging';
	at: 'CWE-263' put: 'Password Aging with Long Expiration';
	at: 'CWE-266' put: 'Incorrect Privilege Assignment';
	at: 'CWE-267' put: 'Privilege Defined With Unsafe Actions';
	at: 'CWE-268' put: 'Privilege Chaining';
	at: 'CWE-269' put: 'Improper Privilege Management';
	at: 'CWE-270' put: 'Privilege Context Switching Error';
	at: 'CWE-271' put: 'Privilege Dropping / Lowering Errors';
	at: 'CWE-272' put: 'Least Privilege Violation';
	at: 'CWE-273' put: 'Improper Check for Dropped Privileges';
	at: 'CWE-274' put: 'Improper Handling of Insufficient Privileges';
	at: 'CWE-276' put: 'Incorrect Default Permissions';
	at: 'CWE-277' put: 'Insecure Inherited Permissions';
	at: 'CWE-278' put: 'Insecure Preserved Inherited Permissions';
	at: 'CWE-279' put: 'Incorrect Execution-Assigned Permissions';
	at: 'CWE-280' put: 'Improper Handling of Insufficient Permissions or Privileges ';
	at: 'CWE-281' put: 'Improper Preservation of Permissions';
	at: 'CWE-282' put: 'Improper Ownership Management';
	at: 'CWE-283' put: 'Unverified Ownership';
	at: 'CWE-284' put: 'Improper Access Control';
	at: 'CWE-285' put: 'Improper Authorization';
	at: 'CWE-286' put: 'Incorrect User Management';
	at: 'CWE-287' put: 'Improper Authentication';
	at: 'CWE-288' put: 'Authentication Bypass Using an Alternate Path or Channel';
	at: 'CWE-289' put: 'Authentication Bypass by Alternate Name';
	at: 'CWE-290' put: 'Authentication Bypass by Spoofing';
	at: 'CWE-291' put: 'Reliance on IP Address for Authentication';
	at: 'CWE-292' put: 'DEPRECATED: Trusting Self-reported DNS Name';
	at: 'CWE-293' put: 'Using Referer Field for Authentication';
	at: 'CWE-294' put: 'Authentication Bypass by Capture-replay';
	at: 'CWE-295' put: 'Improper Certificate Validation';
	at: 'CWE-296' put: 'Improper Following of a Certificate''s Chain of Trust';
	at: 'CWE-297' put: 'Improper Validation of Certificate with Host Mismatch';
	at: 'CWE-298' put: 'Improper Validation of Certificate Expiration';
	at: 'CWE-299' put: 'Improper Check for Certificate Revocation';
	at: 'CWE-300' put: 'Channel Accessible by Non-Endpoint';
	at: 'CWE-301' put: 'Reflection Attack in an Authentication Protocol';
	at: 'CWE-302' put: 'Authentication Bypass by Assumed-Immutable Data';
	at: 'CWE-303' put: 'Incorrect Implementation of Authentication Algorithm';
	at: 'CWE-304' put: 'Missing Critical Step in Authentication';
	at: 'CWE-305' put: 'Authentication Bypass by Primary Weakness';
	at: 'CWE-306' put: 'Missing Authentication for Critical Function';
	at: 'CWE-307' put: 'Improper Restriction of Excessive Authentication Attempts';
	at: 'CWE-308' put: 'Use of Single-factor Authentication';
	at: 'CWE-309' put: 'Use of Password System for Primary Authentication';
	at: 'CWE-311' put: 'Missing Encryption of Sensitive Data';
	at: 'CWE-312' put: 'Cleartext Storage of Sensitive Information';
	at: 'CWE-313' put: 'Cleartext Storage in a File or on Disk';
	at: 'CWE-314' put: 'Cleartext Storage in the Registry';
	at: 'CWE-315' put: 'Cleartext Storage of Sensitive Information in a Cookie';
	at: 'CWE-316' put: 'Cleartext Storage of Sensitive Information in Memory';
	at: 'CWE-317' put: 'Cleartext Storage of Sensitive Information in GUI';
	at: 'CWE-318' put: 'Cleartext Storage of Sensitive Information in Executable';
	at: 'CWE-319' put: 'Cleartext Transmission of Sensitive Information';
	at: 'CWE-321' put: 'Use of Hard-coded Cryptographic Key';
	at: 'CWE-322' put: 'Key Exchange without Entity Authentication';
	at: 'CWE-323' put: 'Reusing a Nonce, Key Pair in Encryption';
	at: 'CWE-324' put: 'Use of a Key Past its Expiration Date';
	at: 'CWE-325' put: 'Missing Cryptographic Step';
	at: 'CWE-326' put: 'Inadequate Encryption Strength';
	at: 'CWE-327' put: 'Use of a Broken or Risky Cryptographic Algorithm';
	at: 'CWE-328' put: 'Use of Weak Hash';
	at: 'CWE-329' put: 'Generation of Predictable IV with CBC Mode';
	at: 'CWE-330' put: 'Use of Insufficiently Random Values';
	at: 'CWE-331' put: 'Insufficient Entropy';
	at: 'CWE-332' put: 'Insufficient Entropy in PRNG';
	at: 'CWE-333' put: 'Improper Handling of Insufficient Entropy in TRNG';
	at: 'CWE-334' put: 'Small Space of Random Values';
	at: 'CWE-335' put: 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)';
	at: 'CWE-336' put: 'Same Seed in Pseudo-Random Number Generator (PRNG)';
	at: 'CWE-337' put: 'Predictable Seed in Pseudo-Random Number Generator (PRNG)';
	at: 'CWE-338' put: 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)';
	at: 'CWE-339' put: 'Small Seed Space in PRNG';
	at: 'CWE-340' put: 'Generation of Predictable Numbers or Identifiers';
	at: 'CWE-341' put: 'Predictable from Observable State';
	at: 'CWE-342' put: 'Predictable Exact Value from Previous Values';
	at: 'CWE-343' put: 'Predictable Value Range from Previous Values';
	at: 'CWE-344' put: 'Use of Invariant Value in Dynamically Changing Context';
	at: 'CWE-345' put: 'Insufficient Verification of Data Authenticity';
	at: 'CWE-346' put: 'Origin Validation Error';
	at: 'CWE-347' put: 'Improper Verification of Cryptographic Signature';
	at: 'CWE-348' put: 'Use of Less Trusted Source';
	at: 'CWE-349' put: 'Acceptance of Extraneous Untrusted Data With Trusted Data';
	at: 'CWE-350' put: 'Reliance on Reverse DNS Resolution for a Security-Critical Action';
	at: 'CWE-351' put: 'Insufficient Type Distinction';
	at: 'CWE-352' put: 'Cross-Site Request Forgery (CSRF)';
	at: 'CWE-353' put: 'Missing Support for Integrity Check';
	at: 'CWE-354' put: 'Improper Validation of Integrity Check Value';
	at: 'CWE-356' put: 'Product UI does not Warn User of Unsafe Actions';
	at: 'CWE-357' put: 'Insufficient UI Warning of Dangerous Operations';
	at: 'CWE-358' put: 'Improperly Implemented Security Check for Standard';
	at: 'CWE-359' put: 'Exposure of Private Personal Information to an Unauthorized Actor';
	at: 'CWE-360' put: 'Trust of System Event Data';
	at: 'CWE-362' put: 'Concurrent Execution using Shared Resource with Improper Synchronization (''Race Condition'')';
	at: 'CWE-363' put: 'Race Condition Enabling Link Following';
	at: 'CWE-364' put: 'Signal Handler Race Condition';
	at: 'CWE-365' put: 'DEPRECATED: Race Condition in Switch';
	at: 'CWE-366' put: 'Race Condition within a Thread';
	at: 'CWE-367' put: 'Time-of-check Time-of-use (TOCTOU) Race Condition';
	at: 'CWE-368' put: 'Context Switching Race Condition';
	at: 'CWE-369' put: 'Divide By Zero';
	at: 'CWE-370' put: 'Missing Check for Certificate Revocation after Initial Check';
	at: 'CWE-372' put: 'Incomplete Internal State Distinction';
	at: 'CWE-373' put: 'DEPRECATED: State Synchronization Error';
	at: 'CWE-374' put: 'Passing Mutable Objects to an Untrusted Method';
	at: 'CWE-375' put: 'Returning a Mutable Object to an Untrusted Caller';
	at: 'CWE-377' put: 'Insecure Temporary File';
	at: 'CWE-378' put: 'Creation of Temporary File With Insecure Permissions';
	at: 'CWE-379' put: 'Creation of Temporary File in Directory with Insecure Permissions';
	at: 'CWE-382' put: 'J2EE Bad Practices: Use of System.exit()';
	at: 'CWE-383' put: 'J2EE Bad Practices: Direct Use of Threads';
	at: 'CWE-384' put: 'Session Fixation';
	at: 'CWE-385' put: 'Covert Timing Channel';
	at: 'CWE-386' put: 'Symbolic Name not Mapping to Correct Object';
	at: 'CWE-390' put: 'Detection of Error Condition Without Action';
	at: 'CWE-391' put: 'Unchecked Error Condition';
	at: 'CWE-392' put: 'Missing Report of Error Condition';
	at: 'CWE-393' put: 'Return of Wrong Status Code';
	at: 'CWE-394' put: 'Unexpected Status Code or Return Value';
	at: 'CWE-395' put: 'Use of NullPointerException Catch to Detect NULL Pointer Dereference';
	at: 'CWE-396' put: 'Declaration of Catch for Generic Exception';
	at: 'CWE-397' put: 'Declaration of Throws for Generic Exception';
	at: 'CWE-400' put: 'Uncontrolled Resource Consumption';
	at: 'CWE-401' put: 'Missing Release of Memory after Effective Lifetime';
	at: 'CWE-402' put: 'Transmission of Private Resources into a New Sphere (''Resource Leak'')';
	at: 'CWE-403' put: 'Exposure of File Descriptor to Unintended Control Sphere (''File Descriptor Leak'')';
	at: 'CWE-404' put: 'Improper Resource Shutdown or Release';
	at: 'CWE-405' put: 'Asymmetric Resource Consumption (Amplification)';
	at: 'CWE-406' put: 'Insufficient Control of Network Message Volume (Network Amplification)';
	at: 'CWE-407' put: 'Inefficient Algorithmic Complexity';
	at: 'CWE-408' put: 'Incorrect Behavior Order: Early Amplification';
	at: 'CWE-409' put: 'Improper Handling of Highly Compressed Data (Data Amplification)';
	at: 'CWE-410' put: 'Insufficient Resource Pool';
	at: 'CWE-412' put: 'Unrestricted Externally Accessible Lock';
	at: 'CWE-413' put: 'Improper Resource Locking';
	at: 'CWE-414' put: 'Missing Lock Check';
	at: 'CWE-415' put: 'Double Free';
	at: 'CWE-416' put: 'Use After Free';
	at: 'CWE-419' put: 'Unprotected Primary Channel';
	at: 'CWE-420' put: 'Unprotected Alternate Channel';
	at: 'CWE-421' put: 'Race Condition During Access to Alternate Channel';
	at: 'CWE-422' put: 'Unprotected Windows Messaging Channel (''Shatter'')';
	at: 'CWE-423' put: 'DEPRECATED: Proxied Trusted Channel';
	at: 'CWE-424' put: 'Improper Protection of Alternate Path';
	at: 'CWE-425' put: 'Direct Request (''Forced Browsing'')';
	at: 'CWE-426' put: 'Untrusted Search Path';
	at: 'CWE-427' put: 'Uncontrolled Search Path Element';
	at: 'CWE-428' put: 'Unquoted Search Path or Element';
	at: 'CWE-430' put: 'Deployment of Wrong Handler';
	at: 'CWE-431' put: 'Missing Handler';
	at: 'CWE-432' put: 'Dangerous Signal Handler not Disabled During Sensitive Operations';
	at: 'CWE-433' put: 'Unparsed Raw Web Content Delivery';
	at: 'CWE-434' put: 'Unrestricted Upload of File with Dangerous Type';
	at: 'CWE-435' put: 'Improper Interaction Between Multiple Correctly-Behaving Entities';
	at: 'CWE-436' put: 'Interpretation Conflict';
	at: 'CWE-437' put: 'Incomplete Model of Endpoint Features';
	at: 'CWE-439' put: 'Behavioral Change in New Version or Environment';
	at: 'CWE-440' put: 'Expected Behavior Violation';
	at: 'CWE-441' put: 'Unintended Proxy or Intermediary (''Confused Deputy'')';
	at: 'CWE-443' put: 'DEPRECATED: HTTP response splitting';
	at: 'CWE-444' put: 'Inconsistent Interpretation of HTTP Requests (''HTTP Request/Response Smuggling'')';
	at: 'CWE-446' put: 'UI Discrepancy for Security Feature';
	at: 'CWE-447' put: 'Unimplemented or Unsupported Feature in UI';
	at: 'CWE-448' put: 'Obsolete Feature in UI';
	at: 'CWE-449' put: 'The UI Performs the Wrong Action';
	at: 'CWE-450' put: 'Multiple Interpretations of UI Input';
	at: 'CWE-451' put: 'User Interface (UI) Misrepresentation of Critical Information';
	at: 'CWE-453' put: 'Insecure Default Variable Initialization';
	at: 'CWE-454' put: 'External Initialization of Trusted Variables or Data Stores';
	at: 'CWE-455' put: 'Non-exit on Failed Initialization';
	at: 'CWE-456' put: 'Missing Initialization of a Variable';
	at: 'CWE-457' put: 'Use of Uninitialized Variable';
	at: 'CWE-458' put: 'DEPRECATED: Incorrect Initialization';
	at: 'CWE-459' put: 'Incomplete Cleanup';
	at: 'CWE-460' put: 'Improper Cleanup on Thrown Exception';
	at: 'CWE-462' put: 'Duplicate Key in Associative List (Alist)';
	at: 'CWE-463' put: 'Deletion of Data Structure Sentinel';
	at: 'CWE-464' put: 'Addition of Data Structure Sentinel';
	at: 'CWE-466' put: 'Return of Pointer Value Outside of Expected Range';
	at: 'CWE-467' put: 'Use of sizeof() on a Pointer Type';
	at: 'CWE-468' put: 'Incorrect Pointer Scaling';
	at: 'CWE-469' put: 'Use of Pointer Subtraction to Determine Size';
	at: 'CWE-470' put: 'Use of Externally-Controlled Input to Select Classes or Code (''Unsafe Reflection'')';
	at: 'CWE-471' put: 'Modification of Assumed-Immutable Data (MAID)';
	at: 'CWE-472' put: 'External Control of Assumed-Immutable Web Parameter';
	at: 'CWE-473' put: 'PHP External Variable Modification';
	at: 'CWE-474' put: 'Use of Function with Inconsistent Implementations';
	at: 'CWE-475' put: 'Undefined Behavior for Input to API';
	at: 'CWE-476' put: 'NULL Pointer Dereference';
	at: 'CWE-477' put: 'Use of Obsolete Function';
	at: 'CWE-478' put: 'Missing Default Case in Multiple Condition Expression';
	at: 'CWE-479' put: 'Signal Handler Use of a Non-reentrant Function';
	at: 'CWE-480' put: 'Use of Incorrect Operator';
	at: 'CWE-481' put: 'Assigning instead of Comparing';
	at: 'CWE-482' put: 'Comparing instead of Assigning';
	at: 'CWE-483' put: 'Incorrect Block Delimitation';
	at: 'CWE-484' put: 'Omitted Break Statement in Switch';
	at: 'CWE-486' put: 'Comparison of Classes by Name';
	at: 'CWE-487' put: 'Reliance on Package-level Scope';
	at: 'CWE-488' put: 'Exposure of Data Element to Wrong Session';
	at: 'CWE-489' put: 'Active Debug Code';
	at: 'CWE-491' put: 'Public cloneable() Method Without Final (''Object Hijack'')';
	at: 'CWE-492' put: 'Use of Inner Class Containing Sensitive Data';
	at: 'CWE-493' put: 'Critical Public Variable Without Final Modifier';
	at: 'CWE-494' put: 'Download of Code Without Integrity Check';
	at: 'CWE-495' put: 'Private Data Structure Returned From A Public Method';
	at: 'CWE-496' put: 'Public Data Assigned to Private Array-Typed Field';
	at: 'CWE-497' put: 'Exposure of Sensitive System Information to an Unauthorized Control Sphere';
	at: 'CWE-498' put: 'Cloneable Class Containing Sensitive Information';
	at: 'CWE-499' put: 'Serializable Class Containing Sensitive Data';
	at: 'CWE-500' put: 'Public Static Field Not Marked Final';
	at: 'CWE-501' put: 'Trust Boundary Violation';
	at: 'CWE-502' put: 'Deserialization of Untrusted Data';
	at: 'CWE-506' put: 'Embedded Malicious Code';
	at: 'CWE-507' put: 'Trojan Horse';
	at: 'CWE-508' put: 'Non-Replicating Malicious Code';
	at: 'CWE-509' put: 'Replicating Malicious Code (Virus or Worm)';
	at: 'CWE-510' put: 'Trapdoor';
	at: 'CWE-511' put: 'Logic/Time Bomb';
	at: 'CWE-512' put: 'Spyware';
	at: 'CWE-514' put: 'Covert Channel';
	at: 'CWE-515' put: 'Covert Storage Channel';
	at: 'CWE-516' put: 'DEPRECATED: Covert Timing Channel';
	at: 'CWE-520' put: '.NET Misconfiguration: Use of Impersonation';
	at: 'CWE-521' put: 'Weak Password Requirements';
	at: 'CWE-522' put: 'Insufficiently Protected Credentials';
	at: 'CWE-523' put: 'Unprotected Transport of Credentials';
	at: 'CWE-524' put: 'Use of Cache Containing Sensitive Information';
	at: 'CWE-525' put: 'Use of Web Browser Cache Containing Sensitive Information';
	at: 'CWE-526' put: 'Cleartext Storage of Sensitive Information in an Environment Variable';
	at: 'CWE-527' put: 'Exposure of Version-Control Repository to an Unauthorized Control Sphere';
	at: 'CWE-528' put: 'Exposure of Core Dump File to an Unauthorized Control Sphere';
	at: 'CWE-529' put: 'Exposure of Access Control List Files to an Unauthorized Control Sphere';
	at: 'CWE-530' put: 'Exposure of Backup File to an Unauthorized Control Sphere';
	at: 'CWE-531' put: 'Inclusion of Sensitive Information in Test Code';
	at: 'CWE-532' put: 'Insertion of Sensitive Information into Log File';
	at: 'CWE-533' put: 'DEPRECATED: Information Exposure Through Server Log Files';
	at: 'CWE-534' put: 'DEPRECATED: Information Exposure Through Debug Log Files';
	at: 'CWE-535' put: 'Exposure of Information Through Shell Error Message';
	at: 'CWE-536' put: 'Servlet Runtime Error Message Containing Sensitive Information';
	at: 'CWE-537' put: 'Java Runtime Error Message Containing Sensitive Information';
	at: 'CWE-538' put: 'Insertion of Sensitive Information into Externally-Accessible File or Directory';
	at: 'CWE-539' put: 'Use of Persistent Cookies Containing Sensitive Information';
	at: 'CWE-540' put: 'Inclusion of Sensitive Information in Source Code';
	at: 'CWE-541' put: 'Inclusion of Sensitive Information in an Include File';
	at: 'CWE-542' put: 'DEPRECATED: Information Exposure Through Cleanup Log Files';
	at: 'CWE-543' put: 'Use of Singleton Pattern Without Synchronization in a Multithreaded Context';
	at: 'CWE-544' put: 'Missing Standardized Error Handling Mechanism';
	at: 'CWE-545' put: 'DEPRECATED: Use of Dynamic Class Loading';
	at: 'CWE-546' put: 'Suspicious Comment';
	at: 'CWE-547' put: 'Use of Hard-coded, Security-relevant Constants';
	at: 'CWE-548' put: 'Exposure of Information Through Directory Listing';
	at: 'CWE-549' put: 'Missing Password Field Masking';
	at: 'CWE-550' put: 'Server-generated Error Message Containing Sensitive Information';
	at: 'CWE-551' put: 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization';
	at: 'CWE-552' put: 'Files or Directories Accessible to External Parties';
	at: 'CWE-553' put: 'Command Shell in Externally Accessible Directory';
	at: 'CWE-554' put: 'ASP.NET Misconfiguration: Not Using Input Validation Framework';
	at: 'CWE-555' put: 'J2EE Misconfiguration: Plaintext Password in Configuration File';
	at: 'CWE-556' put: 'ASP.NET Misconfiguration: Use of Identity Impersonation';
	at: 'CWE-558' put: 'Use of getlogin() in Multithreaded Application';
	at: 'CWE-560' put: 'Use of umask() with chmod-style Argument';
	at: 'CWE-561' put: 'Dead Code';
	at: 'CWE-562' put: 'Return of Stack Variable Address';
	at: 'CWE-563' put: 'Assignment to Variable without Use';
	at: 'CWE-564' put: 'SQL Injection: Hibernate';
	at: 'CWE-565' put: 'Reliance on Cookies without Validation and Integrity Checking';
	at: 'CWE-566' put: 'Authorization Bypass Through User-Controlled SQL Primary Key';
	at: 'CWE-567' put: 'Unsynchronized Access to Shared Data in a Multithreaded Context';
	at: 'CWE-568' put: 'finalize() Method Without super.finalize()';
	at: 'CWE-570' put: 'Expression is Always False';
	at: 'CWE-571' put: 'Expression is Always True';
	at: 'CWE-572' put: 'Call to Thread run() instead of start()';
	at: 'CWE-573' put: 'Improper Following of Specification by Caller';
	at: 'CWE-574' put: 'EJB Bad Practices: Use of Synchronization Primitives';
	at: 'CWE-575' put: 'EJB Bad Practices: Use of AWT Swing';
	at: 'CWE-576' put: 'EJB Bad Practices: Use of Java I/O';
	at: 'CWE-577' put: 'EJB Bad Practices: Use of Sockets';
	at: 'CWE-578' put: 'EJB Bad Practices: Use of Class Loader';
	at: 'CWE-579' put: 'J2EE Bad Practices: Non-serializable Object Stored in Session';
	at: 'CWE-580' put: 'clone() Method Without super.clone()';
	at: 'CWE-581' put: 'Object Model Violation: Just One of Equals and Hashcode Defined';
	at: 'CWE-582' put: 'Array Declared Public, Final, and Static';
	at: 'CWE-583' put: 'finalize() Method Declared Public';
	at: 'CWE-584' put: 'Return Inside Finally Block';
	at: 'CWE-585' put: 'Empty Synchronized Block';
	at: 'CWE-586' put: 'Explicit Call to Finalize()';
	at: 'CWE-587' put: 'Assignment of a Fixed Address to a Pointer';
	at: 'CWE-588' put: 'Attempt to Access Child of a Non-structure Pointer';
	at: 'CWE-589' put: 'Call to Non-ubiquitous API';
	at: 'CWE-590' put: 'Free of Memory not on the Heap';
	at: 'CWE-591' put: 'Sensitive Data Storage in Improperly Locked Memory';
	at: 'CWE-592' put: 'DEPRECATED: Authentication Bypass Issues';
	at: 'CWE-593' put: 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created';
	at: 'CWE-594' put: 'J2EE Framework: Saving Unserializable Objects to Disk';
	at: 'CWE-595' put: 'Comparison of Object References Instead of Object Contents';
	at: 'CWE-596' put: 'DEPRECATED: Incorrect Semantic Object Comparison';
	at: 'CWE-597' put: 'Use of Wrong Operator in String Comparison';
	at: 'CWE-598' put: 'Use of GET Request Method With Sensitive Query Strings';
	at: 'CWE-599' put: 'Missing Validation of OpenSSL Certificate';
	at: 'CWE-600' put: 'Uncaught Exception in Servlet ';
	at: 'CWE-601' put: 'URL Redirection to Untrusted Site (''Open Redirect'')';
	at: 'CWE-602' put: 'Client-Side Enforcement of Server-Side Security';
	at: 'CWE-603' put: 'Use of Client-Side Authentication';
	at: 'CWE-605' put: 'Multiple Binds to the Same Port';
	at: 'CWE-606' put: 'Unchecked Input for Loop Condition';
	at: 'CWE-607' put: 'Public Static Final Field References Mutable Object';
	at: 'CWE-608' put: 'Struts: Non-private Field in ActionForm Class';
	at: 'CWE-609' put: 'Double-Checked Locking';
	at: 'CWE-610' put: 'Externally Controlled Reference to a Resource in Another Sphere';
	at: 'CWE-611' put: 'Improper Restriction of XML External Entity Reference';
	at: 'CWE-612' put: 'Improper Authorization of Index Containing Sensitive Information';
	at: 'CWE-613' put: 'Insufficient Session Expiration';
	at: 'CWE-614' put: 'Sensitive Cookie in HTTPS Session Without ''Secure'' Attribute';
	at: 'CWE-615' put: 'Inclusion of Sensitive Information in Source Code Comments';
	at: 'CWE-616' put: 'Incomplete Identification of Uploaded File Variables (PHP)';
	at: 'CWE-617' put: 'Reachable Assertion';
	at: 'CWE-618' put: 'Exposed Unsafe ActiveX Method';
	at: 'CWE-619' put: 'Dangling Database Cursor (''Cursor Injection'')';
	at: 'CWE-620' put: 'Unverified Password Change';
	at: 'CWE-621' put: 'Variable Extraction Error';
	at: 'CWE-622' put: 'Improper Validation of Function Hook Arguments';
	at: 'CWE-623' put: 'Unsafe ActiveX Control Marked Safe For Scripting';
	at: 'CWE-624' put: 'Executable Regular Expression Error';
	at: 'CWE-625' put: 'Permissive Regular Expression';
	at: 'CWE-626' put: 'Null Byte Interaction Error (Poison Null Byte)';
	at: 'CWE-627' put: 'Dynamic Variable Evaluation';
	at: 'CWE-628' put: 'Function Call with Incorrectly Specified Arguments';
	at: 'CWE-636' put: 'Not Failing Securely (''Failing Open'')';
	at: 'CWE-637' put: 'Unnecessary Complexity in Protection Mechanism (Not Using ''Economy of Mechanism'')';
	at: 'CWE-638' put: 'Not Using Complete Mediation';
	at: 'CWE-639' put: 'Authorization Bypass Through User-Controlled Key';
	at: 'CWE-640' put: 'Weak Password Recovery Mechanism for Forgotten Password';
	at: 'CWE-641' put: 'Improper Restriction of Names for Files and Other Resources';
	at: 'CWE-642' put: 'External Control of Critical State Data';
	at: 'CWE-643' put: 'Improper Neutralization of Data within XPath Expressions (''XPath Injection'')';
	at: 'CWE-644' put: 'Improper Neutralization of HTTP Headers for Scripting Syntax';
	at: 'CWE-645' put: 'Overly Restrictive Account Lockout Mechanism';
	at: 'CWE-646' put: 'Reliance on File Name or Extension of Externally-Supplied File';
	at: 'CWE-647' put: 'Use of Non-Canonical URL Paths for Authorization Decisions';
	at: 'CWE-648' put: 'Incorrect Use of Privileged APIs';
	at: 'CWE-649' put: 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking';
	at: 'CWE-650' put: 'Trusting HTTP Permission Methods on the Server Side';
	at: 'CWE-651' put: 'Exposure of WSDL File Containing Sensitive Information';
	at: 'CWE-652' put: 'Improper Neutralization of Data within XQuery Expressions (''XQuery Injection'')';
	at: 'CWE-653' put: 'Improper Isolation or Compartmentalization';
	at: 'CWE-654' put: 'Reliance on a Single Factor in a Security Decision';
	at: 'CWE-655' put: 'Insufficient Psychological Acceptability';
	at: 'CWE-656' put: 'Reliance on Security Through Obscurity';
	at: 'CWE-657' put: 'Violation of Secure Design Principles';
	at: 'CWE-662' put: 'Improper Synchronization';
	at: 'CWE-663' put: 'Use of a Non-reentrant Function in a Concurrent Context';
	at: 'CWE-664' put: 'Improper Control of a Resource Through its Lifetime';
	at: 'CWE-665' put: 'Improper Initialization';
	at: 'CWE-666' put: 'Operation on Resource in Wrong Phase of Lifetime';
	at: 'CWE-667' put: 'Improper Locking';
	at: 'CWE-668' put: 'Exposure of Resource to Wrong Sphere';
	at: 'CWE-669' put: 'Incorrect Resource Transfer Between Spheres';
	at: 'CWE-670' put: 'Always-Incorrect Control Flow Implementation';
	at: 'CWE-671' put: 'Lack of Administrator Control over Security';
	at: 'CWE-672' put: 'Operation on a Resource after Expiration or Release';
	at: 'CWE-673' put: 'External Influence of Sphere Definition';
	at: 'CWE-674' put: 'Uncontrolled Recursion';
	at: 'CWE-675' put: 'Multiple Operations on Resource in Single-Operation Context';
	at: 'CWE-676' put: 'Use of Potentially Dangerous Function';
	at: 'CWE-680' put: 'Integer Overflow to Buffer Overflow';
	at: 'CWE-681' put: 'Incorrect Conversion between Numeric Types';
	at: 'CWE-682' put: 'Incorrect Calculation';
	at: 'CWE-683' put: 'Function Call With Incorrect Order of Arguments';
	at: 'CWE-684' put: 'Incorrect Provision of Specified Functionality';
	at: 'CWE-685' put: 'Function Call With Incorrect Number of Arguments';
	at: 'CWE-686' put: 'Function Call With Incorrect Argument Type';
	at: 'CWE-687' put: 'Function Call With Incorrectly Specified Argument Value';
	at: 'CWE-688' put: 'Function Call With Incorrect Variable or Reference as Argument';
	at: 'CWE-689' put: 'Permission Race Condition During Resource Copy';
	at: 'CWE-690' put: 'Unchecked Return Value to NULL Pointer Dereference';
	at: 'CWE-691' put: 'Insufficient Control Flow Management';
	at: 'CWE-692' put: 'Incomplete Denylist to Cross-Site Scripting';
	at: 'CWE-693' put: 'Protection Mechanism Failure';
	at: 'CWE-694' put: 'Use of Multiple Resources with Duplicate Identifier';
	at: 'CWE-695' put: 'Use of Low-Level Functionality';
	at: 'CWE-696' put: 'Incorrect Behavior Order';
	at: 'CWE-697' put: 'Incorrect Comparison';
	at: 'CWE-698' put: 'Execution After Redirect (EAR)';
	at: 'CWE-703' put: 'Improper Check or Handling of Exceptional Conditions';
	at: 'CWE-704' put: 'Incorrect Type Conversion or Cast';
	at: 'CWE-705' put: 'Incorrect Control Flow Scoping';
	at: 'CWE-706' put: 'Use of Incorrectly-Resolved Name or Reference';
	at: 'CWE-707' put: 'Improper Neutralization';
	at: 'CWE-708' put: 'Incorrect Ownership Assignment';
	at: 'CWE-710' put: 'Improper Adherence to Coding Standards';
	at: 'CWE-732' put: 'Incorrect Permission Assignment for Critical Resource';
	at: 'CWE-733' put: 'Compiler Optimization Removal or Modification of Security-critical Code';
	at: 'CWE-749' put: 'Exposed Dangerous Method or Function';
	at: 'CWE-754' put: 'Improper Check for Unusual or Exceptional Conditions';
	at: 'CWE-755' put: 'Improper Handling of Exceptional Conditions';
	at: 'CWE-756' put: 'Missing Custom Error Page';
	at: 'CWE-757' put: 'Selection of Less-Secure Algorithm During Negotiation (''Algorithm Downgrade'')';
	at: 'CWE-758' put: 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior';
	at: 'CWE-759' put: 'Use of a One-Way Hash without a Salt';
	at: 'CWE-760' put: 'Use of a One-Way Hash with a Predictable Salt';
	at: 'CWE-761' put: 'Free of Pointer not at Start of Buffer';
	at: 'CWE-762' put: 'Mismatched Memory Management Routines';
	at: 'CWE-763' put: 'Release of Invalid Pointer or Reference';
	at: 'CWE-764' put: 'Multiple Locks of a Critical Resource';
	at: 'CWE-765' put: 'Multiple Unlocks of a Critical Resource';
	at: 'CWE-766' put: 'Critical Data Element Declared Public';
	at: 'CWE-767' put: 'Access to Critical Private Variable via Public Method';
	at: 'CWE-768' put: 'Incorrect Short Circuit Evaluation';
	at: 'CWE-769' put: 'DEPRECATED: Uncontrolled File Descriptor Consumption';
	at: 'CWE-770' put: 'Allocation of Resources Without Limits or Throttling';
	at: 'CWE-771' put: 'Missing Reference to Active Allocated Resource';
	at: 'CWE-772' put: 'Missing Release of Resource after Effective Lifetime';
	at: 'CWE-773' put: 'Missing Reference to Active File Descriptor or Handle';
	at: 'CWE-774' put: 'Allocation of File Descriptors or Handles Without Limits or Throttling';
	at: 'CWE-775' put: 'Missing Release of File Descriptor or Handle after Effective Lifetime';
	at: 'CWE-776' put: 'Improper Restriction of Recursive Entity References in DTDs (''XML Entity Expansion'')';
	at: 'CWE-777' put: 'Regular Expression without Anchors';
	at: 'CWE-778' put: 'Insufficient Logging';
	at: 'CWE-779' put: 'Logging of Excessive Data';
	at: 'CWE-780' put: 'Use of RSA Algorithm without OAEP';
	at: 'CWE-781' put: 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code';
	at: 'CWE-782' put: 'Exposed IOCTL with Insufficient Access Control';
	at: 'CWE-783' put: 'Operator Precedence Logic Error';
	at: 'CWE-784' put: 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision';
	at: 'CWE-785' put: 'Use of Path Manipulation Function without Maximum-sized Buffer';
	at: 'CWE-786' put: 'Access of Memory Location Before Start of Buffer';
	at: 'CWE-787' put: 'Out-of-bounds Write';
	at: 'CWE-788' put: 'Access of Memory Location After End of Buffer';
	at: 'CWE-789' put: 'Memory Allocation with Excessive Size Value';
	at: 'CWE-790' put: 'Improper Filtering of Special Elements';
	at: 'CWE-791' put: 'Incomplete Filtering of Special Elements';
	at: 'CWE-792' put: 'Incomplete Filtering of One or More Instances of Special Elements';
	at: 'CWE-793' put: 'Only Filtering One Instance of a Special Element';
	at: 'CWE-794' put: 'Incomplete Filtering of Multiple Instances of Special Elements';
	at: 'CWE-795' put: 'Only Filtering Special Elements at a Specified Location';
	at: 'CWE-796' put: 'Only Filtering Special Elements Relative to a Marker';
	at: 'CWE-797' put: 'Only Filtering Special Elements at an Absolute Position';
	at: 'CWE-798' put: 'Use of Hard-coded Credentials';
	at: 'CWE-799' put: 'Improper Control of Interaction Frequency';
	at: 'CWE-804' put: 'Guessable CAPTCHA';
	at: 'CWE-805' put: 'Buffer Access with Incorrect Length Value';
	at: 'CWE-806' put: 'Buffer Access Using Size of Source Buffer';
	at: 'CWE-807' put: 'Reliance on Untrusted Inputs in a Security Decision';
	at: 'CWE-820' put: 'Missing Synchronization';
	at: 'CWE-821' put: 'Incorrect Synchronization';
	at: 'CWE-822' put: 'Untrusted Pointer Dereference';
	at: 'CWE-823' put: 'Use of Out-of-range Pointer Offset';
	at: 'CWE-824' put: 'Access of Uninitialized Pointer';
	at: 'CWE-825' put: 'Expired Pointer Dereference';
	at: 'CWE-826' put: 'Premature Release of Resource During Expected Lifetime';
	at: 'CWE-827' put: 'Improper Control of Document Type Definition';
	at: 'CWE-828' put: 'Signal Handler with Functionality that is not Asynchronous-Safe';
	at: 'CWE-829' put: 'Inclusion of Functionality from Untrusted Control Sphere';
	at: 'CWE-830' put: 'Inclusion of Web Functionality from an Untrusted Source';
	at: 'CWE-831' put: 'Signal Handler Function Associated with Multiple Signals';
	at: 'CWE-832' put: 'Unlock of a Resource that is not Locked';
	at: 'CWE-833' put: 'Deadlock';
	at: 'CWE-834' put: 'Excessive Iteration';
	at: 'CWE-835' put: 'Loop with Unreachable Exit Condition (''Infinite Loop'')';
	at: 'CWE-836' put: 'Use of Password Hash Instead of Password for Authentication';
	at: 'CWE-837' put: 'Improper Enforcement of a Single, Unique Action';
	at: 'CWE-838' put: 'Inappropriate Encoding for Output Context';
	at: 'CWE-839' put: 'Numeric Range Comparison Without Minimum Check';
	at: 'CWE-841' put: 'Improper Enforcement of Behavioral Workflow';
	at: 'CWE-842' put: 'Placement of User into Incorrect Group';
	at: 'CWE-843' put: 'Access of Resource Using Incompatible Type (''Type Confusion'')';
	at: 'CWE-862' put: 'Missing Authorization';
	at: 'CWE-863' put: 'Incorrect Authorization';
	at: 'CWE-908' put: 'Use of Uninitialized Resource';
	at: 'CWE-909' put: 'Missing Initialization of Resource';
	at: 'CWE-910' put: 'Use of Expired File Descriptor';
	at: 'CWE-911' put: 'Improper Update of Reference Count';
	at: 'CWE-912' put: 'Hidden Functionality';
	at: 'CWE-913' put: 'Improper Control of Dynamically-Managed Code Resources';
	at: 'CWE-914' put: 'Improper Control of Dynamically-Identified Variables';
	at: 'CWE-915' put: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes';
	at: 'CWE-916' put: 'Use of Password Hash With Insufficient Computational Effort';
	at: 'CWE-917' put: 'Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')';
	at: 'CWE-918' put: 'Server-Side Request Forgery (SSRF)';
	at: 'CWE-920' put: 'Improper Restriction of Power Consumption';
	at: 'CWE-921' put: 'Storage of Sensitive Data in a Mechanism without Access Control';
	at: 'CWE-922' put: 'Insecure Storage of Sensitive Information';
	at: 'CWE-923' put: 'Improper Restriction of Communication Channel to Intended Endpoints';
	at: 'CWE-924' put: 'Improper Enforcement of Message Integrity During Transmission in a Communication Channel';
	at: 'CWE-925' put: 'Improper Verification of Intent by Broadcast Receiver';
	at: 'CWE-926' put: 'Improper Export of Android Application Components';
	at: 'CWE-927' put: 'Use of Implicit Intent for Sensitive Communication';
	at: 'CWE-939' put: 'Improper Authorization in Handler for Custom URL Scheme';
	at: 'CWE-940' put: 'Improper Verification of Source of a Communication Channel';
	at: 'CWE-941' put: 'Incorrectly Specified Destination in a Communication Channel';
	at: 'CWE-942' put: 'Permissive Cross-domain Security Policy with Untrusted Domains';
	at: 'CWE-943' put: 'Improper Neutralization of Special Elements in Data Query Logic';
	at: 'CWE-1004' put: 'Sensitive Cookie Without ''HttpOnly'' Flag';
	at: 'CWE-1007' put: 'Insufficient Visual Distinction of Homoglyphs Presented to User';
	at: 'CWE-1021' put: 'Improper Restriction of Rendered UI Layers or Frames';
	at: 'CWE-1022' put: 'Use of Web Link to Untrusted Target with window.opener Access';
	at: 'CWE-1023' put: 'Incomplete Comparison with Missing Factors';
	at: 'CWE-1024' put: 'Comparison of Incompatible Types';
	at: 'CWE-1025' put: 'Comparison Using Wrong Factors';
	at: 'CWE-1037' put: 'Processor Optimization Removal or Modification of Security-critical Code';
	at: 'CWE-1038' put: 'Insecure Automated Optimizations';
	at: 'CWE-1039' put: 'Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism';
	at: 'CWE-1041' put: 'Use of Redundant Code';
	at: 'CWE-1042' put: 'Static Member Data Element outside of a Singleton Class Element';
	at: 'CWE-1043' put: 'Data Element Aggregating an Excessively Large Number of Non-Primitive Elements';
	at: 'CWE-1044' put: 'Architecture with Number of Horizontal Layers Outside of Expected Range';
	at: 'CWE-1045' put: 'Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor';
	at: 'CWE-1046' put: 'Creation of Immutable Text Using String Concatenation';
	at: 'CWE-1047' put: 'Modules with Circular Dependencies';
	at: 'CWE-1048' put: 'Invokable Control Element with Large Number of Outward Calls';
	at: 'CWE-1049' put: 'Excessive Data Query Operations in a Large Data Table';
	at: 'CWE-1050' put: 'Excessive Platform Resource Consumption within a Loop';
	at: 'CWE-1051' put: 'Initialization with Hard-Coded Network Resource Configuration Data';
	at: 'CWE-1052' put: 'Excessive Use of Hard-Coded Literals in Initialization';
	at: 'CWE-1053' put: 'Missing Documentation for Design';
	at: 'CWE-1054' put: 'Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer';
	at: 'CWE-1055' put: 'Multiple Inheritance from Concrete Classes';
	at: 'CWE-1056' put: 'Invokable Control Element with Variadic Parameters';
	at: 'CWE-1057' put: 'Data Access Operations Outside of Expected Data Manager Component';
	at: 'CWE-1058' put: 'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element';
	at: 'CWE-1059' put: 'Insufficient Technical Documentation';
	at: 'CWE-1060' put: 'Excessive Number of Inefficient Server-Side Data Accesses';
	at: 'CWE-1061' put: 'Insufficient Encapsulation';
	at: 'CWE-1062' put: 'Parent Class with References to Child Class';
	at: 'CWE-1063' put: 'Creation of Class Instance within a Static Code Block';
	at: 'CWE-1064' put: 'Invokable Control Element with Signature Containing an Excessive Number of Parameters';
	at: 'CWE-1065' put: 'Runtime Resource Management Control Element in a Component Built to Run on Application Servers';
	at: 'CWE-1066' put: 'Missing Serialization Control Element';
	at: 'CWE-1067' put: 'Excessive Execution of Sequential Searches of Data Resource';
	at: 'CWE-1068' put: 'Inconsistency Between Implementation and Documented Design';
	at: 'CWE-1069' put: 'Empty Exception Block';
	at: 'CWE-1070' put: 'Serializable Data Element Containing non-Serializable Item Elements';
	at: 'CWE-1071' put: 'Empty Code Block';
	at: 'CWE-1072' put: 'Data Resource Access without Use of Connection Pooling';
	at: 'CWE-1073' put: 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses';
	at: 'CWE-1074' put: 'Class with Excessively Deep Inheritance';
	at: 'CWE-1075' put: 'Unconditional Control Flow Transfer outside of Switch Block';
	at: 'CWE-1076' put: 'Insufficient Adherence to Expected Conventions';
	at: 'CWE-1077' put: 'Floating Point Comparison with Incorrect Operator';
	at: 'CWE-1078' put: 'Inappropriate Source Code Style or Formatting';
	at: 'CWE-1079' put: 'Parent Class without Virtual Destructor Method';
	at: 'CWE-1080' put: 'Source Code File with Excessive Number of Lines of Code';
	at: 'CWE-1082' put: 'Class Instance Self Destruction Control Element';
	at: 'CWE-1083' put: 'Data Access from Outside Expected Data Manager Component';
	at: 'CWE-1084' put: 'Invokable Control Element with Excessive File or Data Access Operations';
	at: 'CWE-1085' put: 'Invokable Control Element with Excessive Volume of Commented-out Code';
	at: 'CWE-1086' put: 'Class with Excessive Number of Child Classes';
	at: 'CWE-1087' put: 'Class with Virtual Method without a Virtual Destructor';
	at: 'CWE-1088' put: 'Synchronous Access of Remote Resource without Timeout';
	at: 'CWE-1089' put: 'Large Data Table with Excessive Number of Indices';
	at: 'CWE-1090' put: 'Method Containing Access of a Member Element from Another Class';
	at: 'CWE-1091' put: 'Use of Object without Invoking Destructor Method';
	at: 'CWE-1092' put: 'Use of Same Invokable Control Element in Multiple Architectural Layers';
	at: 'CWE-1093' put: 'Excessively Complex Data Representation';
	at: 'CWE-1094' put: 'Excessive Index Range Scan for a Data Resource';
	at: 'CWE-1095' put: 'Loop Condition Value Update within the Loop';
	at: 'CWE-1096' put: 'Singleton Class Instance Creation without Proper Locking or Synchronization';
	at: 'CWE-1097' put: 'Persistent Storable Data Element without Associated Comparison Control Element';
	at: 'CWE-1098' put: 'Data Element containing Pointer Item without Proper Copy Control Element';
	at: 'CWE-1099' put: 'Inconsistent Naming Conventions for Identifiers';
	at: 'CWE-1100' put: 'Insufficient Isolation of System-Dependent Functions';
	at: 'CWE-1101' put: 'Reliance on Runtime Component in Generated Code';
	at: 'CWE-1102' put: 'Reliance on Machine-Dependent Data Representation';
	at: 'CWE-1103' put: 'Use of Platform-Dependent Third Party Components';
	at: 'CWE-1104' put: 'Use of Unmaintained Third Party Components';
	at: 'CWE-1105' put: 'Insufficient Encapsulation of Machine-Dependent Functionality';
	at: 'CWE-1106' put: 'Insufficient Use of Symbolic Constants';
	at: 'CWE-1107' put: 'Insufficient Isolation of Symbolic Constant Definitions';
	at: 'CWE-1108' put: 'Excessive Reliance on Global Variables';
	at: 'CWE-1109' put: 'Use of Same Variable for Multiple Purposes';
	at: 'CWE-1110' put: 'Incomplete Design Documentation';
	at: 'CWE-1111' put: 'Incomplete I/O Documentation';
	at: 'CWE-1112' put: 'Incomplete Documentation of Program Execution';
	at: 'CWE-1113' put: 'Inappropriate Comment Style';
	at: 'CWE-1114' put: 'Inappropriate Whitespace Style';
	at: 'CWE-1115' put: 'Source Code Element without Standard Prologue';
	at: 'CWE-1116' put: 'Inaccurate Source Code Comments';
	at: 'CWE-1117' put: 'Callable with Insufficient Behavioral Summary';
	at: 'CWE-1118' put: 'Insufficient Documentation of Error Handling Techniques';
	at: 'CWE-1119' put: 'Excessive Use of Unconditional Branching';
	at: 'CWE-1120' put: 'Excessive Code Complexity';
	at: 'CWE-1121' put: 'Excessive McCabe Cyclomatic Complexity';
	at: 'CWE-1122' put: 'Excessive Halstead Complexity';
	at: 'CWE-1123' put: 'Excessive Use of Self-Modifying Code';
	at: 'CWE-1124' put: 'Excessively Deep Nesting';
	at: 'CWE-1125' put: 'Excessive Attack Surface';
	at: 'CWE-1126' put: 'Declaration of Variable with Unnecessarily Wide Scope';
	at: 'CWE-1127' put: 'Compilation with Insufficient Warnings or Errors';
	at: 'CWE-1164' put: 'Irrelevant Code';
	at: 'CWE-1173' put: 'Improper Use of Validation Framework';
	at: 'CWE-1174' put: 'ASP.NET Misconfiguration: Improper Model Validation';
	at: 'CWE-1176' put: 'Inefficient CPU Computation';
	at: 'CWE-1177' put: 'Use of Prohibited Code';
	at: 'CWE-1187' put: 'DEPRECATED: Use of Uninitialized Resource';
	at: 'CWE-1188' put: 'Initialization of a Resource with an Insecure Default';
	at: 'CWE-1189' put: 'Improper Isolation of Shared Resources on System-on-a-Chip (SoC)';
	at: 'CWE-1190' put: 'DMA Device Enabled Too Early in Boot Phase';
	at: 'CWE-1191' put: 'On-Chip Debug and Test Interface With Improper Access Control';
	at: 'CWE-1192' put: 'Improper Identifier for IP Block used in System-On-Chip (SOC)';
	at: 'CWE-1193' put: 'Power-On of Untrusted Execution Core Before Enabling Fabric Access Control';
	at: 'CWE-1204' put: 'Generation of Weak Initialization Vector (IV)';
	at: 'CWE-1209' put: 'Failure to Disable Reserved Bits';
	at: 'CWE-1220' put: 'Insufficient Granularity of Access Control';
	at: 'CWE-1221' put: 'Incorrect Register Defaults or Module Parameters';
	at: 'CWE-1222' put: 'Insufficient Granularity of Address Regions Protected by Register Locks';
	at: 'CWE-1223' put: 'Race Condition for Write-Once Attributes';
	at: 'CWE-1224' put: 'Improper Restriction of Write-Once Bit Fields';
	at: 'CWE-1229' put: 'Creation of Emergent Resource';
	at: 'CWE-1230' put: 'Exposure of Sensitive Information Through Metadata';
	at: 'CWE-1231' put: 'Improper Prevention of Lock Bit Modification';
	at: 'CWE-1232' put: 'Improper Lock Behavior After Power State Transition';
	at: 'CWE-1233' put: 'Security-Sensitive Hardware Controls with Missing Lock Bit Protection';
	at: 'CWE-1234' put: 'Hardware Internal or Debug Modes Allow Override of Locks';
	at: 'CWE-1235' put: 'Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations';
	at: 'CWE-1236' put: 'Improper Neutralization of Formula Elements in a CSV File';
	at: 'CWE-1239' put: 'Improper Zeroization of Hardware Register';
	at: 'CWE-1240' put: 'Use of a Cryptographic Primitive with a Risky Implementation';
	at: 'CWE-1241' put: 'Use of Predictable Algorithm in Random Number Generator';
	at: 'CWE-1242' put: 'Inclusion of Undocumented Features or Chicken Bits';
	at: 'CWE-1243' put: 'Sensitive Non-Volatile Information Not Protected During Debug';
	at: 'CWE-1244' put: 'Internal Asset Exposed to Unsafe Debug Access Level or State';
	at: 'CWE-1245' put: 'Improper Finite State Machines (FSMs) in Hardware Logic';
	at: 'CWE-1246' put: 'Improper Write Handling in Limited-write Non-Volatile Memories';
	at: 'CWE-1247' put: 'Improper Protection Against Voltage and Clock Glitches';
	at: 'CWE-1248' put: 'Semiconductor Defects in Hardware Logic with Security-Sensitive Implications';
	at: 'CWE-1249' put: 'Application-Level Admin Tool with Inconsistent View of Underlying Operating System';
	at: 'CWE-1250' put: 'Improper Preservation of Consistency Between Independent Representations of Shared State';
	at: 'CWE-1251' put: 'Mirrored Regions with Different Values';
	at: 'CWE-1252' put: 'CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations';
	at: 'CWE-1253' put: 'Incorrect Selection of Fuse Values';
	at: 'CWE-1254' put: 'Incorrect Comparison Logic Granularity';
	at: 'CWE-1255' put: 'Comparison Logic is Vulnerable to Power Side-Channel Attacks';
	at: 'CWE-1256' put: 'Improper Restriction of Software Interfaces to Hardware Features';
	at: 'CWE-1257' put: 'Improper Access Control Applied to Mirrored or Aliased Memory Regions';
	at: 'CWE-1258' put: 'Exposure of Sensitive System Information Due to Uncleared Debug Information';
	at: 'CWE-1259' put: 'Improper Restriction of Security Token Assignment';
	at: 'CWE-1260' put: 'Improper Handling of Overlap Between Protected Memory Ranges';
	at: 'CWE-1261' put: 'Improper Handling of Single Event Upsets';
	at: 'CWE-1262' put: 'Improper Access Control for Register Interface';
	at: 'CWE-1263' put: 'Improper Physical Access Control';
	at: 'CWE-1264' put: 'Hardware Logic with Insecure De-Synchronization between Control and Data Channels';
	at: 'CWE-1265' put: 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls';
	at: 'CWE-1266' put: 'Improper Scrubbing of Sensitive Data from Decommissioned Device';
	at: 'CWE-1267' put: 'Policy Uses Obsolete Encoding';
	at: 'CWE-1268' put: 'Policy Privileges are not Assigned Consistently Between Control and Data Agents';
	at: 'CWE-1269' put: 'Product Released in Non-Release Configuration';
	at: 'CWE-1270' put: 'Generation of Incorrect Security Tokens';
	at: 'CWE-1271' put: 'Uninitialized Value on Reset for Registers Holding Security Settings';
	at: 'CWE-1272' put: 'Sensitive Information Uncleared Before Debug/Power State Transition';
	at: 'CWE-1273' put: 'Device Unlock Credential Sharing';
	at: 'CWE-1274' put: 'Improper Access Control for Volatile Memory Containing Boot Code';
	at: 'CWE-1275' put: 'Sensitive Cookie with Improper SameSite Attribute';
	at: 'CWE-1276' put: 'Hardware Child Block Incorrectly Connected to Parent System';
	at: 'CWE-1277' put: 'Firmware Not Updateable';
	at: 'CWE-1278' put: 'Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques';
	at: 'CWE-1279' put: 'Cryptographic Operations are run Before Supporting Units are Ready';
	at: 'CWE-1280' put: 'Access Control Check Implemented After Asset is Accessed';
	at: 'CWE-1281' put: 'Sequence of Processor Instructions Leads to Unexpected Behavior';
	at: 'CWE-1282' put: 'Assumed-Immutable Data is Stored in Writable Memory';
	at: 'CWE-1283' put: 'Mutable Attestation or Measurement Reporting Data';
	at: 'CWE-1284' put: 'Improper Validation of Specified Quantity in Input';
	at: 'CWE-1285' put: 'Improper Validation of Specified Index, Position, or Offset in Input';
	at: 'CWE-1286' put: 'Improper Validation of Syntactic Correctness of Input';
	at: 'CWE-1287' put: 'Improper Validation of Specified Type of Input';
	at: 'CWE-1288' put: 'Improper Validation of Consistency within Input';
	at: 'CWE-1289' put: 'Improper Validation of Unsafe Equivalence in Input';
	at: 'CWE-1290' put: 'Incorrect Decoding of Security Identifiers ';
	at: 'CWE-1291' put: 'Public Key Re-Use for Signing both Debug and Production Code';
	at: 'CWE-1292' put: 'Incorrect Conversion of Security Identifiers';
	at: 'CWE-1293' put: 'Missing Source Correlation of Multiple Independent Data';
	at: 'CWE-1294' put: 'Insecure Security Identifier Mechanism';
	at: 'CWE-1295' put: 'Debug Messages Revealing Unnecessary Information';
	at: 'CWE-1296' put: 'Incorrect Chaining or Granularity of Debug Components';
	at: 'CWE-1297' put: 'Unprotected Confidential Information on Device is Accessible by OSAT Vendors';
	at: 'CWE-1298' put: 'Hardware Logic Contains Race Conditions';
	at: 'CWE-1299' put: 'Missing Protection Mechanism for Alternate Hardware Interface';
	at: 'CWE-1300' put: 'Improper Protection of Physical Side Channels';
	at: 'CWE-1301' put: 'Insufficient or Incomplete Data Removal within Hardware Component';
	at: 'CWE-1302' put: 'Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)';
	at: 'CWE-1303' put: 'Non-Transparent Sharing of Microarchitectural Resources';
	at: 'CWE-1304' put: 'Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation';
	at: 'CWE-1310' put: 'Missing Ability to Patch ROM Code';
	at: 'CWE-1311' put: 'Improper Translation of Security Attributes by Fabric Bridge';
	at: 'CWE-1312' put: 'Missing Protection for Mirrored Regions in On-Chip Fabric Firewall';
	at: 'CWE-1313' put: 'Hardware Allows Activation of Test or Debug Logic at Runtime';
	at: 'CWE-1314' put: 'Missing Write Protection for Parametric Data Values';
	at: 'CWE-1315' put: 'Improper Setting of Bus Controlling Capability in Fabric End-point';
	at: 'CWE-1316' put: 'Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges';
	at: 'CWE-1317' put: 'Improper Access Control in Fabric Bridge';
	at: 'CWE-1318' put: 'Missing Support for Security Features in On-chip Fabrics or Buses';
	at: 'CWE-1319' put: 'Improper Protection against Electromagnetic Fault Injection (EM-FI)';
	at: 'CWE-1320' put: 'Improper Protection for Outbound Error Messages and Alert Signals';
	at: 'CWE-1321' put: 'Improperly Controlled Modification of Object Prototype Attributes (''Prototype Pollution'')';
	at: 'CWE-1322' put: 'Use of Blocking Code in Single-threaded, Non-blocking Context';
	at: 'CWE-1323' put: 'Improper Management of Sensitive Trace Data';
	at: 'CWE-1324' put: 'DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface';
	at: 'CWE-1325' put: 'Improperly Controlled Sequential Memory Allocation';
	at: 'CWE-1326' put: 'Missing Immutable Root of Trust in Hardware';
	at: 'CWE-1327' put: 'Binding to an Unrestricted IP Address';
	at: 'CWE-1328' put: 'Security Version Number Mutable to Older Versions';
	at: 'CWE-1329' put: 'Reliance on Component That is Not Updateable';
	at: 'CWE-1330' put: 'Remanent Data Readable after Memory Erase';
	at: 'CWE-1331' put: 'Improper Isolation of Shared Resources in Network On Chip (NoC)';
	at: 'CWE-1332' put: 'Improper Handling of Faults that Lead to Instruction Skips';
	at: 'CWE-1333' put: 'Inefficient Regular Expression Complexity';
	at: 'CWE-1334' put: 'Unauthorized Error Injection Can Degrade Hardware Redundancy';
	at: 'CWE-1335' put: 'Incorrect Bitwise Shift of Integer';
	at: 'CWE-1336' put: 'Improper Neutralization of Special Elements Used in a Template Engine';
	at: 'CWE-1338' put: 'Improper Protections Against Hardware Overheating';
	at: 'CWE-1339' put: 'Insufficient Precision or Accuracy of a Real Number';
	at: 'CWE-1341' put: 'Multiple Releases of Same Resource or Handle';
	at: 'CWE-1342' put: 'Information Exposure through Microarchitectural State after Transient Execution';
	at: 'CWE-1351' put: 'Improper Handling of Hardware Behavior in Exceptionally Cold Environments';
	at: 'CWE-1357' put: 'Reliance on Insufficiently Trustworthy Component';
	at: 'CWE-1384' put: 'Improper Handling of Physical or Environmental Conditions';
	at: 'CWE-1385' put: 'Missing Origin Validation in WebSockets';
	at: 'CWE-1386' put: 'Insecure Operation on Windows Junction / Mount Point';
	at: 'CWE-1389' put: 'Incorrect Parsing of Numbers with Different Radices';
	at: 'CWE-1390' put: 'Weak Authentication';
	at: 'CWE-1391' put: 'Use of Weak Credentials';
	at: 'CWE-1392' put: 'Use of Default Credentials';
	at: 'CWE-1393' put: 'Use of Default Password';
	at: 'CWE-1394' put: 'Use of Default Cryptographic Key';
	at: 'CWE-1395' put: 'Dependency on Vulnerable Third-Party Component';
	at: 'CWE-1419' put: 'Incorrect Initialization of Resource';
	at: 'CWE-1420' put: 'Exposure of Sensitive Information during Transient Execution';
	at: 'CWE-1421' put: 'Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution';
	at: 'CWE-1422' put: 'Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution';
	at: 'CWE-1423' put: 'Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution';
	at: 'CWE-1426' put: 'Improper Validation of Generative AI Output';
	at: 'CWE-1427' put: 'Improper Neutralization of Input Used for LLM Prompting';
	at: 'CWE-1428' put: 'Reliance on HTTP instead of HTTPS';
	at: 'CWE-1429' put: 'Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface';
	at: 'CWE-1431' put: 'Driving Intermediate Cryptographic State/Results to Hardware Module Outputs';
	at: 'CWE-1434' put: 'Insecure Setting of Generative AI/ML Model Inference Parameters';
	yourself
]

{ #category : 'catalog' }
Gt4SecurityCwe class >> regenerateKnownDescriptions [
	"Refresh the CWE catalog from MITRE's Comprehensive CWE List (View-2000).
	Downloads the ZIP, parses the CSV, and recompiles #knownDescriptions in place.
	Run this when MITRE publishes a new release."
	| client bytes archive member csv file parsed dict sortedKeys src stream |
	client := ZnClient new.
	client url: 'https://cwe.mitre.org/data/csv/2000.csv.zip'.
	client enforceHttpSuccess: true.
	client beBinary.
	bytes := client get.
	archive := (ZipArchive new) readFrom: bytes readStream; yourself.
	member := archive memberNamed: '2000.csv'.
	csv := member contents utf8Decoded.
	file := FileLocator temp asFileReference / 'gt4sec_cwe_regen.csv'.
	file exists ifTrue: [ file delete ].
	file writeStreamDo: [ :s | s nextPutAll: csv ].
	parsed := CSVParser parseFileWithHeader: file fullName.
	dict := Dictionary new.
	parsed do: [ :row |
		| id name |
		id := row at: 'CWE-ID' ifAbsent: [ nil ].
		name := row at: 'Name' ifAbsent: [ nil ].
		(id notNil and: [ name notNil and: [ id notEmpty and: [ name notEmpty ] ] ])
			ifTrue: [ dict at: 'CWE-', id put: name ] ].
	sortedKeys := dict keys asSortedCollection: [ :a :b |
		(a copyFrom: 5 to: a size) asNumber < (b copyFrom: 5 to: b size) asNumber ].
	stream := String new writeStream.
	stream
		nextPutAll: 'knownDescriptions'; lf;
		tab; nextPutAll: '"Canonical CWE names from MITRE''s Comprehensive CWE List (View-2000).'; lf;
		tab; nextPutAll: 'Regenerate by evaluating Gt4SecurityCwe class>>#regenerateKnownDescriptions."'; lf;
		tab; nextPutAll: '^ Dictionary new'; lf.
	sortedKeys do: [ :k |
		stream
			tab; nextPutAll: 'at: '''; nextPutAll: k; nextPutAll: ''' put: ''';
			nextPutAll: ((dict at: k) copyReplaceAll: '''' with: ''''''); nextPutAll: ''';'; lf ].
	stream tab; nextPutAll: 'yourself'.
	src := stream contents.
	self class compile: src classified: 'catalog'.
	^ dict size
]

{ #category : 'accessing' }
Gt4SecurityCwe >> description [
	"Explicit description from the API if one was set, else fall back to the catalog lookup."
	^ description ifNil: [ self class descriptionFor: id ]
]

{ #category : 'accessing' }
Gt4SecurityCwe >> description: aString [
	description := aString
]

{ #category : 'printing' }
Gt4SecurityCwe >> gtDisplayOn: aStream [
	aStream nextPutAll: (id ifNil: [ '(no id)' ]).
	self description ifNotNil: [ :d |
		aStream nextPutAll: ' — '; nextPutAll: d ]
]

{ #category : 'gt - views' }
Gt4SecurityCwe >> gtOpenMitreActionFor: anAction [
	<gtAction>
	self mitreUrl ifNil: [ ^ anAction noAction ].
	^ anAction button
		icon: BrGlamorousVectorIcons browse;
		tooltip: 'Open MITRE CWE page';
		priority: 10;
		action: [ :aButton | WebBrowser openOn: self mitreUrl ]
]

{ #category : 'gt - views' }
Gt4SecurityCwe >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'CWE';
		priority: 1;
		items: [ {
			'ID' -> (id ifNil: [ '(none)' ]).
			'Description' -> (description ifNil: [ '(none)' ]).
			'Source' -> (source ifNil: [ '(unknown)' ]).
			'MITRE URL' -> (self mitreUrl ifNil: [ '(n/a)' ]) } ];
		column: 'Property' text: [ :a | a key ] weight: 1;
		column: 'Value' text: [ :a | a value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityCwe >> id [
	^ id
]

{ #category : 'accessing' }
Gt4SecurityCwe >> id: aString [
	id := aString
]

{ #category : 'derived' }
Gt4SecurityCwe >> mitreUrl [
	"URL to the MITRE CWE entry — open with the toolbar action."
	self number ifNil: [ ^ nil ].
	^ 'https://cwe.mitre.org/data/definitions/' , self number printString , '.html'
]

{ #category : 'derived' }
Gt4SecurityCwe >> number [
	"The numeric portion of the CWE id, e.g. 79 from 'CWE-79'. Nil if not a standard CWE-* id."
	(id isNil or: [ (id beginsWith: 'CWE-') not ]) ifTrue: [ ^ nil ].
	^ [ (id copyFrom: 5 to: id size) asInteger ] on: Error do: [ :e | nil ]
]

{ #category : 'printing' }
Gt4SecurityCwe >> printOn: aStream [
	aStream nextPutAll: (id ifNil: [ '(no id)' ]).
	self description ifNotNil: [ :d |
		aStream nextPutAll: ' — '; nextPutAll: d ]
]

{ #category : 'accessing' }
Gt4SecurityCwe >> source [
	^ source
]

{ #category : 'accessing' }
Gt4SecurityCwe >> source: aString [
	source := aString
]
