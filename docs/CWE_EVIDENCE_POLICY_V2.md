# Detailed CWE evidence requirements

Each of the 944 official CWE entries has an evidence collection plan. Directly listed detection methods are artifact-collection alternatives, not mandatory source requirements or VEX decisions. Entries without methods start with CVE/vendor mechanism evidence.

Every mapped active non-Pillar CWE has one row. Official ancestry does not assign an analysis method. No source/operational defaults, method inheritance or keyword refinements are active.

Baseline summary: `{"undetermined": 944}`. Automatic routing is disabled. Only reported CWE IDs are used. See [the detailed criteria](CWE_ROUTING_CRITERIA.md).

| CWE | Name | Pillars | Source baseline | Operating baseline | Evidence collection plan |
| --- | --- | --- | --- | --- | --- |
| [CWE-5](https://cwe.mitre.org/data/definitions/5.html) | J2EE Misconfiguration: Data Transmission Without Encryption | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-6](https://cwe.mitre.org/data/definitions/6.html) | J2EE Misconfiguration: Insufficient Session-ID Length | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-7](https://cwe.mitre.org/data/definitions/7.html) | J2EE Misconfiguration: Missing Custom Error Page | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-8](https://cwe.mitre.org/data/definitions/8.html) | J2EE Misconfiguration: Entity Bean Declared Remote | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-9](https://cwe.mitre.org/data/definitions/9.html) | J2EE Misconfiguration: Weak Access Permissions for EJB Methods | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-11](https://cwe.mitre.org/data/definitions/11.html) | ASP.NET Misconfiguration: Creating Debug Binary | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-12](https://cwe.mitre.org/data/definitions/12.html) | ASP.NET Misconfiguration: Missing Custom Error Page | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) | ASP.NET Misconfiguration: Password in Configuration File | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) | Compiler Removal of Code to Clear Buffers | CWE-435, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | CWE-707 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Improper Limitation of a Pathname to a Restricted Directory | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-23](https://cwe.mitre.org/data/definitions/23.html) | Relative Path Traversal | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-24](https://cwe.mitre.org/data/definitions/24.html) | Path Traversal: '../filedir' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-25](https://cwe.mitre.org/data/definitions/25.html) | Path Traversal: '/../filedir' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-26](https://cwe.mitre.org/data/definitions/26.html) | Path Traversal: '/dir/../filename' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-27](https://cwe.mitre.org/data/definitions/27.html) | Path Traversal: 'dir/../../filename' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-28](https://cwe.mitre.org/data/definitions/28.html) | Path Traversal: '..\filedir' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-29](https://cwe.mitre.org/data/definitions/29.html) | Path Traversal: '\..\filename' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-30](https://cwe.mitre.org/data/definitions/30.html) | Path Traversal: '\dir\..\filename' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-31](https://cwe.mitre.org/data/definitions/31.html) | Path Traversal: 'dir\..\..\filename' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-32](https://cwe.mitre.org/data/definitions/32.html) | Path Traversal: '...' (Triple Dot) | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-33](https://cwe.mitre.org/data/definitions/33.html) | Path Traversal: '....' (Multiple Dot) | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-34](https://cwe.mitre.org/data/definitions/34.html) | Path Traversal: '....//' | CWE-664 | undetermined | undetermined | 설계 자료 검토; 소스 검토 |
| [CWE-35](https://cwe.mitre.org/data/definitions/35.html) | Path Traversal: '.../...//' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-36](https://cwe.mitre.org/data/definitions/36.html) | Absolute Path Traversal | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) | Path Traversal: '/absolute/pathname/here' | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-38](https://cwe.mitre.org/data/definitions/38.html) | Path Traversal: '\absolute\pathname\here' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-39](https://cwe.mitre.org/data/definitions/39.html) | Path Traversal: 'C:dirname' | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-40](https://cwe.mitre.org/data/definitions/40.html) | Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-41](https://cwe.mitre.org/data/definitions/41.html) | Improper Resolution of Path Equivalence | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) | Path Equivalence: 'filename.' (Trailing Dot) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) | Path Equivalence: 'filename....' (Multiple Trailing Dot) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-44](https://cwe.mitre.org/data/definitions/44.html) | Path Equivalence: 'file.name' (Internal Dot) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) | Path Equivalence: 'file...name' (Multiple Internal Dot) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) | Path Equivalence: 'filename ' (Trailing Space) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-47](https://cwe.mitre.org/data/definitions/47.html) | Path Equivalence: ' filename' (Leading Space) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-48](https://cwe.mitre.org/data/definitions/48.html) | Path Equivalence: 'file name' (Internal Whitespace) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) | Path Equivalence: 'filename/' (Trailing Slash) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) | Path Equivalence: '//multiple/leading/slash' | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-51](https://cwe.mitre.org/data/definitions/51.html) | Path Equivalence: '/multiple//internal/slash' | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) | Path Equivalence: '/multiple/trailing/slash//' | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) | Path Equivalence: '\multiple\\internal\backslash' | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) | Path Equivalence: 'filedir\' (Trailing Backslash) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-55](https://cwe.mitre.org/data/definitions/55.html) | Path Equivalence: '/./' (Single Dot Directory) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) | Path Equivalence: 'filedir*' (Wildcard) | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-57](https://cwe.mitre.org/data/definitions/57.html) | Path Equivalence: 'fakedir/../realdir/filename' | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-58](https://cwe.mitre.org/data/definitions/58.html) | Path Equivalence: Windows 8.3 Filename | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | Improper Link Resolution Before File Access | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-61](https://cwe.mitre.org/data/definitions/61.html) | UNIX Symbolic Link (Symlink) Following | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-62](https://cwe.mitre.org/data/definitions/62.html) | UNIX Hard Link | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-64](https://cwe.mitre.org/data/definitions/64.html) | Windows Shortcut Following (.LNK) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-65](https://cwe.mitre.org/data/definitions/65.html) | Windows Hard Link | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-66](https://cwe.mitre.org/data/definitions/66.html) | Improper Handling of File Names that Identify Virtual Resources | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-67](https://cwe.mitre.org/data/definitions/67.html) | Improper Handling of Windows Device Names | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-69](https://cwe.mitre.org/data/definitions/69.html) | Improper Handling of Windows ::DATA Alternate Data Stream | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-72](https://cwe.mitre.org/data/definitions/72.html) | Improper Handling of Apple HFS+ Alternate Data Stream Path | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | External Control of File Name or Path | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | Improper Neutralization of Special Elements in Output Used by a Downstream Component | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-75](https://cwe.mitre.org/data/definitions/75.html) | Failure to Sanitize Special Elements into a Different Plane | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | Improper Neutralization of Equivalent Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Improper Neutralization of Special Elements used in a Command | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Improper Neutralization of Special Elements used in an OS Command | CWE-707 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation | CWE-707 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-80](https://cwe.mitre.org/data/definitions/80.html) | Improper Neutralization of Script-Related HTML Tags in a Web Page | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-81](https://cwe.mitre.org/data/definitions/81.html) | Improper Neutralization of Script in an Error Message Web Page | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-82](https://cwe.mitre.org/data/definitions/82.html) | Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-83](https://cwe.mitre.org/data/definitions/83.html) | Improper Neutralization of Script in Attributes in a Web Page | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-84](https://cwe.mitre.org/data/definitions/84.html) | Improper Neutralization of Encoded URI Schemes in a Web Page | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-85](https://cwe.mitre.org/data/definitions/85.html) | Doubled Character XSS Manipulations | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | CWE-435, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-87](https://cwe.mitre.org/data/definitions/87.html) | Improper Neutralization of Alternate XSS Syntax | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-88](https://cwe.mitre.org/data/definitions/88.html) | Improper Neutralization of Argument Delimiters in a Command | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Improper Neutralization of Special Elements used in an SQL Command | CWE-707 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | Improper Neutralization of Special Elements used in an LDAP Query | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-91](https://cwe.mitre.org/data/definitions/91.html) | XML Injection | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-93](https://cwe.mitre.org/data/definitions/93.html) | Improper Neutralization of CRLF Sequences | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Improper Control of Generation of Code | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Improper Neutralization of Directives in Dynamically Evaluated Code | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) | Improper Neutralization of Directives in Statically Saved Code | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-98](https://cwe.mitre.org/data/definitions/98.html) | Improper Control of Filename for Include/Require Statement in PHP Program | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토 |
| [CWE-99](https://cwe.mitre.org/data/definitions/99.html) | Improper Control of Resource Identifiers | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) | Struts: Duplicate Validation Forms | CWE-707, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-103](https://cwe.mitre.org/data/definitions/103.html) | Struts: Incomplete validate() Method Definition | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-104](https://cwe.mitre.org/data/definitions/104.html) | Struts: Form Bean Does Not Extend Validation Class | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-105](https://cwe.mitre.org/data/definitions/105.html) | Struts: Form Field Without Validator | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-106](https://cwe.mitre.org/data/definitions/106.html) | Struts: Plug-in Framework not in Use | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-107](https://cwe.mitre.org/data/definitions/107.html) | Struts: Unused Validation Form | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-108](https://cwe.mitre.org/data/definitions/108.html) | Struts: Unvalidated Action Form | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-109](https://cwe.mitre.org/data/definitions/109.html) | Struts: Validator Turned Off | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-110](https://cwe.mitre.org/data/definitions/110.html) | Struts: Validator Without Form Field | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-111](https://cwe.mitre.org/data/definitions/111.html) | Direct Use of Unsafe JNI | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-112](https://cwe.mitre.org/data/definitions/112.html) | Missing XML Validation | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | CWE-435, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) | Process Control | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-115](https://cwe.mitre.org/data/definitions/115.html) | Misinterpretation of Input | CWE-435 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | CWE-707 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-117](https://cwe.mitre.org/data/definitions/117.html) | Improper Output Neutralization for Logs | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) | Incorrect Access of Indexable Resource | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Improper Restriction of Operations within the Bounds of a Memory Buffer | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer Copy without Checking Size of Input | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack-based Buffer Overflow | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap-based Buffer Overflow | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-123](https://cwe.mitre.org/data/definitions/123.html) | Write-what-where Condition | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-124](https://cwe.mitre.org/data/definitions/124.html) | Buffer Underwrite | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-125](https://cwe.mitre.org/data/definitions/125.html) | Out-of-bounds Read | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-126](https://cwe.mitre.org/data/definitions/126.html) | Buffer Over-read | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-127](https://cwe.mitre.org/data/definitions/127.html) | Buffer Under-read | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-128](https://cwe.mitre.org/data/definitions/128.html) | Wrap-around Error | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-129](https://cwe.mitre.org/data/definitions/129.html) | Improper Validation of Array Index | CWE-707 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) | Improper Handling of Length Parameter Inconsistency | CWE-703, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-131](https://cwe.mitre.org/data/definitions/131.html) | Incorrect Calculation of Buffer Size | CWE-682 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Use of Externally-Controlled Format String | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-135](https://cwe.mitre.org/data/definitions/135.html) | Incorrect Calculation of Multi-Byte String Length | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-138](https://cwe.mitre.org/data/definitions/138.html) | Improper Neutralization of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-140](https://cwe.mitre.org/data/definitions/140.html) | Improper Neutralization of Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-141](https://cwe.mitre.org/data/definitions/141.html) | Improper Neutralization of Parameter/Argument Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-142](https://cwe.mitre.org/data/definitions/142.html) | Improper Neutralization of Value Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-143](https://cwe.mitre.org/data/definitions/143.html) | Improper Neutralization of Record Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-144](https://cwe.mitre.org/data/definitions/144.html) | Improper Neutralization of Line Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-145](https://cwe.mitre.org/data/definitions/145.html) | Improper Neutralization of Section Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-146](https://cwe.mitre.org/data/definitions/146.html) | Improper Neutralization of Expression/Command Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-147](https://cwe.mitre.org/data/definitions/147.html) | Improper Neutralization of Input Terminators | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-148](https://cwe.mitre.org/data/definitions/148.html) | Improper Neutralization of Input Leaders | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-149](https://cwe.mitre.org/data/definitions/149.html) | Improper Neutralization of Quoting Syntax | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-150](https://cwe.mitre.org/data/definitions/150.html) | Improper Neutralization of Escape, Meta, or Control Sequences | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-151](https://cwe.mitre.org/data/definitions/151.html) | Improper Neutralization of Comment Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-152](https://cwe.mitre.org/data/definitions/152.html) | Improper Neutralization of Macro Symbols | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-153](https://cwe.mitre.org/data/definitions/153.html) | Improper Neutralization of Substitution Characters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-154](https://cwe.mitre.org/data/definitions/154.html) | Improper Neutralization of Variable Name Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-155](https://cwe.mitre.org/data/definitions/155.html) | Improper Neutralization of Wildcards or Matching Symbols | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-156](https://cwe.mitre.org/data/definitions/156.html) | Improper Neutralization of Whitespace | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-157](https://cwe.mitre.org/data/definitions/157.html) | Failure to Sanitize Paired Delimiters | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-158](https://cwe.mitre.org/data/definitions/158.html) | Improper Neutralization of Null Byte or NUL Character | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-159](https://cwe.mitre.org/data/definitions/159.html) | Improper Handling of Invalid Use of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-160](https://cwe.mitre.org/data/definitions/160.html) | Improper Neutralization of Leading Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-161](https://cwe.mitre.org/data/definitions/161.html) | Improper Neutralization of Multiple Leading Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-162](https://cwe.mitre.org/data/definitions/162.html) | Improper Neutralization of Trailing Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-163](https://cwe.mitre.org/data/definitions/163.html) | Improper Neutralization of Multiple Trailing Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-164](https://cwe.mitre.org/data/definitions/164.html) | Improper Neutralization of Internal Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-165](https://cwe.mitre.org/data/definitions/165.html) | Improper Neutralization of Multiple Internal Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) | Improper Handling of Missing Special Element | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) | Improper Handling of Additional Special Element | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) | Improper Handling of Inconsistent Special Elements | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-170](https://cwe.mitre.org/data/definitions/170.html) | Improper Null Termination | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) | Improper Encoding or Decoding of Data | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-173](https://cwe.mitre.org/data/definitions/173.html) | Improper Handling of Alternate Encoding | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | CWE-707, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-175](https://cwe.mitre.org/data/definitions/175.html) | Improper Handling of Mixed Encoding | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | Improper Handling of Unicode Encoding | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-177](https://cwe.mitre.org/data/definitions/177.html) | Improper Handling of URL Encoding (Hex Encoding) | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-178](https://cwe.mitre.org/data/definitions/178.html) | Improper Handling of Case Sensitivity | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) | Incorrect Behavior Order: Early Validation | CWE-691, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | Incorrect Behavior Order: Validate Before Canonicalize | CWE-691, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | CWE-691, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-182](https://cwe.mitre.org/data/definitions/182.html) | Collapse of Data into Unsafe Value | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-183](https://cwe.mitre.org/data/definitions/183.html) | Permissive List of Allowed Inputs | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | CWE-693, CWE-697 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-185](https://cwe.mitre.org/data/definitions/185.html) | Incorrect Regular Expression | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-186](https://cwe.mitre.org/data/definitions/186.html) | Overly Restrictive Regular Expression | CWE-697 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-187](https://cwe.mitre.org/data/definitions/187.html) | Partial String Comparison | CWE-697 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data/Memory Layout | CWE-435, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow or Wraparound | CWE-682 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | Integer Underflow (Wrap or Wraparound) | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-192](https://cwe.mitre.org/data/definitions/192.html) | Integer Coercion Error | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-193](https://cwe.mitre.org/data/definitions/193.html) | Off-by-one Error | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-194](https://cwe.mitre.org/data/definitions/194.html) | Unexpected Sign Extension | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-195](https://cwe.mitre.org/data/definitions/195.html) | Signed to Unsigned Conversion Error | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-196](https://cwe.mitre.org/data/definitions/196.html) | Unsigned to Signed Conversion Error | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-197](https://cwe.mitre.org/data/definitions/197.html) | Numeric Truncation Error | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) | Use of Incorrect Byte Ordering | CWE-435, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-201](https://cwe.mitre.org/data/definitions/201.html) | Insertion of Sensitive Information Into Sent Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-202](https://cwe.mitre.org/data/definitions/202.html) | Exposure of Sensitive Information Through Data Queries | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-203](https://cwe.mitre.org/data/definitions/203.html) | Observable Discrepancy | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | Observable Response Discrepancy | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-205](https://cwe.mitre.org/data/definitions/205.html) | Observable Behavioral Discrepancy | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-206](https://cwe.mitre.org/data/definitions/206.html) | Observable Internal Behavioral Discrepancy | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-207](https://cwe.mitre.org/data/definitions/207.html) | Observable Behavioral Discrepancy With Equivalent Products | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | Observable Timing Discrepancy | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) | Self-generated Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) | Externally-Generated Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-212](https://cwe.mitre.org/data/definitions/212.html) | Improper Removal of Sensitive Information Before Storage or Transfer | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-213](https://cwe.mitre.org/data/definitions/213.html) | Exposure of Sensitive Information Due to Incompatible Policies | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-214](https://cwe.mitre.org/data/definitions/214.html) | Invocation of Process Using Visible Sensitive Information | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | Insertion of Sensitive Information Into Debugging Code | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) | Storage of File with Sensitive Data Under Web Root | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) | Storage of File With Sensitive Data Under FTP Root | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-221](https://cwe.mitre.org/data/definitions/221.html) | Information Loss or Omission | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-222](https://cwe.mitre.org/data/definitions/222.html) | Truncation of Security-relevant Information | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-223](https://cwe.mitre.org/data/definitions/223.html) | Omission of Security-relevant Information | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-224](https://cwe.mitre.org/data/definitions/224.html) | Obscured Security-relevant Information by Alternate Name | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-226](https://cwe.mitre.org/data/definitions/226.html) | Sensitive Information in Resource Not Removed Before Reuse | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토 |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | CWE-703, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) | Improper Handling of Values | CWE-703, CWE-707 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) | Improper Handling of Missing Values | CWE-703, CWE-707 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) | Improper Handling of Extra Values | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) | Improper Handling of Undefined Values | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) | Improper Handling of Parameters | CWE-703, CWE-707 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) | Failure to Handle Missing Parameter | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | Improper Handling of Extra Parameters | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) | Improper Handling of Undefined Parameters | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) | Improper Handling of Structural Elements | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) | Improper Handling of Incomplete Structural Elements | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) | Failure to Handle Incomplete Element | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) | Improper Handling of Inconsistent Structural Elements | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) | Improper Handling of Unexpected Data Type | CWE-703, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) | Use of Inherently Dangerous Function | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) | Creation of chroot Jail Without Changing Working Directory | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-244](https://cwe.mitre.org/data/definitions/244.html) | Improper Clearing of Heap Memory Before Release | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-245](https://cwe.mitre.org/data/definitions/245.html) | J2EE Bad Practices: Direct Management of Connections | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-246](https://cwe.mitre.org/data/definitions/246.html) | J2EE Bad Practices: Direct Use of Sockets | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception | CWE-691, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | CWE-284, CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-252](https://cwe.mitre.org/data/definitions/252.html) | Unchecked Return Value | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | CWE-703, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of a Password | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Storing Passwords in a Recoverable Format | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) | Empty Password in Configuration File | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) | Password in Configuration File | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) | Weak Encoding for Password | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-266](https://cwe.mitre.org/data/definitions/266.html) | Incorrect Privilege Assignment | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-267](https://cwe.mitre.org/data/definitions/267.html) | Privilege Defined With Unsafe Actions | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-268](https://cwe.mitre.org/data/definitions/268.html) | Privilege Chaining | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | Improper Privilege Management | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-270](https://cwe.mitre.org/data/definitions/270.html) | Privilege Context Switching Error | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | Privilege Dropping / Lowering Errors | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-272](https://cwe.mitre.org/data/definitions/272.html) | Least Privilege Violation | CWE-284 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | CWE-284, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) | Improper Handling of Insufficient Privileges | CWE-284, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | Incorrect Default Permissions | CWE-284, CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) | Insecure Inherited Permissions | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) | Insecure Preserved Inherited Permissions | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) | Incorrect Execution-Assigned Permissions | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-280](https://cwe.mitre.org/data/definitions/280.html) | Improper Handling of Insufficient Permissions or Privileges | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) | Improper Preservation of Permissions | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-282](https://cwe.mitre.org/data/definitions/282.html) | Improper Ownership Management | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-283](https://cwe.mitre.org/data/definitions/283.html) | Unverified Ownership | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-286](https://cwe.mitre.org/data/definitions/286.html) | Incorrect User Management | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | CWE-284 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-288](https://cwe.mitre.org/data/definitions/288.html) | Authentication Bypass Using an Alternate Path or Channel | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-289](https://cwe.mitre.org/data/definitions/289.html) | Authentication Bypass by Alternate Name | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-290](https://cwe.mitre.org/data/definitions/290.html) | Authentication Bypass by Spoofing | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-291](https://cwe.mitre.org/data/definitions/291.html) | Reliance on IP Address for Authentication | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-293](https://cwe.mitre.org/data/definitions/293.html) | Using Referer Field for Authentication | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Authentication Bypass by Capture-replay | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Improper Certificate Validation | CWE-284 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) | Improper Following of a Certificate's Chain of Trust | CWE-284, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-297](https://cwe.mitre.org/data/definitions/297.html) | Improper Validation of Certificate with Host Mismatch | CWE-284 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) | Improper Validation of Certificate Expiration | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) | Improper Check for Certificate Revocation | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Channel Accessible by Non-Endpoint | CWE-284 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-301](https://cwe.mitre.org/data/definitions/301.html) | Reflection Attack in an Authentication Protocol | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | CWE-284, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-303](https://cwe.mitre.org/data/definitions/303.html) | Incorrect Implementation of Authentication Algorithm | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) | Missing Critical Step in Authentication | CWE-284, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-305](https://cwe.mitre.org/data/definitions/305.html) | Authentication Bypass by Primary Weakness | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing Authentication for Critical Functionality | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | CWE-284, CWE-691 | undetermined | undetermined | 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Cleartext Storage of Sensitive Information | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) | Cleartext Storage in a File or on Disk | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) | Cleartext Storage in the Registry | CWE-664, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) | Cleartext Storage of Sensitive Information in a Cookie | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage of Sensitive Information in Memory | CWE-664, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) | Cleartext Storage of Sensitive Information in GUI | CWE-664, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) | Cleartext Storage of Sensitive Information in Executable | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Cleartext Transmission of Sensitive Information | CWE-693 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-322](https://cwe.mitre.org/data/definitions/322.html) | Key Exchange without Entity Authentication | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-323](https://cwe.mitre.org/data/definitions/323.html) | Reusing a Nonce, Key Pair in Encryption | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-324](https://cwe.mitre.org/data/definitions/324.html) | Use of a Key Past its Expiration Date | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Cryptographic Step | CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | Inadequate Encryption Strength | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm | CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-328](https://cwe.mitre.org/data/definitions/328.html) | Use of Weak Hash | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | Use of Insufficiently Random Values | CWE-693 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-331](https://cwe.mitre.org/data/definitions/331.html) | Insufficient Entropy | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-332](https://cwe.mitre.org/data/definitions/332.html) | Insufficient Entropy in PRNG | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) | Improper Handling of Insufficient Entropy in TRNG | CWE-693, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-334](https://cwe.mitre.org/data/definitions/334.html) | Small Space of Random Values | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-336](https://cwe.mitre.org/data/definitions/336.html) | Same Seed in Pseudo-Random Number Generator (PRNG) | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-337](https://cwe.mitre.org/data/definitions/337.html) | Predictable Seed in Pseudo-Random Number Generator (PRNG) | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-339](https://cwe.mitre.org/data/definitions/339.html) | Small Seed Space in PRNG | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-340](https://cwe.mitre.org/data/definitions/340.html) | Generation of Predictable Numbers or Identifiers | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-341](https://cwe.mitre.org/data/definitions/341.html) | Predictable from Observable State | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-342](https://cwe.mitre.org/data/definitions/342.html) | Predictable Exact Value from Previous Values | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-343](https://cwe.mitre.org/data/definitions/343.html) | Predictable Value Range from Previous Values | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-344](https://cwe.mitre.org/data/definitions/344.html) | Use of Invariant Value in Dynamically Changing Context | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | CWE-284, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Improper Verification of Cryptographic Signature | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-348](https://cwe.mitre.org/data/definitions/348.html) | Use of Less Trusted Source | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-349](https://cwe.mitre.org/data/definitions/349.html) | Acceptance of Extraneous Untrusted Data With Trusted Data | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | Reliance on Reverse DNS Resolution for a Security-Critical Action | CWE-284, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-351](https://cwe.mitre.org/data/definitions/351.html) | Insufficient Type Distinction | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery | CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-353](https://cwe.mitre.org/data/definitions/353.html) | Missing Support for Integrity Check | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) | Improper Validation of Integrity Check Value | CWE-693, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-356](https://cwe.mitre.org/data/definitions/356.html) | Missing User Interaction for Potentially Unsafe Action | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-357](https://cwe.mitre.org/data/definitions/357.html) | Insufficient UI Warning of Dangerous Operations | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) | Improperly Implemented Security Check for Standard | CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-359](https://cwe.mitre.org/data/definitions/359.html) | Exposure of Private Personal Information to an Unauthorized Actor | CWE-664 | undetermined | undetermined | 설계 자료 검토; 구현 자료 검토 |
| [CWE-360](https://cwe.mitre.org/data/definitions/360.html) | Trust of System Event Data | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization | CWE-664, CWE-691 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) | Race Condition Enabling Link Following | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition within a Thread | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) | Context Switching Race Condition | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-369](https://cwe.mitre.org/data/definitions/369.html) | Divide By Zero | CWE-682 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) | Missing Check for Certificate Revocation after Initial Check | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-372](https://cwe.mitre.org/data/definitions/372.html) | Incomplete Internal State Distinction | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-374](https://cwe.mitre.org/data/definitions/374.html) | Passing Mutable Objects to an Untrusted Method | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-375](https://cwe.mitre.org/data/definitions/375.html) | Returning a Mutable Object to an Untrusted Caller | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-382](https://cwe.mitre.org/data/definitions/382.html) | J2EE Bad Practices: Use of System.exit() | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-383](https://cwe.mitre.org/data/definitions/383.html) | J2EE Bad Practices: Direct Use of Threads | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-385](https://cwe.mitre.org/data/definitions/385.html) | Covert Timing Channel | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-386](https://cwe.mitre.org/data/definitions/386.html) | Symbolic Name not Mapping to Correct Object | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) | Detection of Error Condition Without Action | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) | Missing Report of Error Condition | CWE-703, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Return of Wrong Status Code | CWE-703, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-394](https://cwe.mitre.org/data/definitions/394.html) | Unexpected Status Code or Return Value | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) | Use of NullPointerException Catch to Detect NULL Pointer Dereference | CWE-691, CWE-703 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | CWE-664, CWE-691, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | CWE-664, CWE-691, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-401](https://cwe.mitre.org/data/definitions/401.html) | Missing Release of Memory after Effective Lifetime | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-402](https://cwe.mitre.org/data/definitions/402.html) | Transmission of Private Resources into a New Sphere | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-403](https://cwe.mitre.org/data/definitions/403.html) | Exposure of File Descriptor to Unintended Control Sphere | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | Improper Resource Shutdown or Release | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-405](https://cwe.mitre.org/data/definitions/405.html) | Asymmetric Resource Consumption (Amplification) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-406](https://cwe.mitre.org/data/definitions/406.html) | Insufficient Control of Network Message Volume (Network Amplification) | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) | Inefficient Algorithmic Complexity | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) | Incorrect Behavior Order: Early Amplification | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-409](https://cwe.mitre.org/data/definitions/409.html) | Improper Handling of Highly Compressed Data (Data Amplification) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-410](https://cwe.mitre.org/data/definitions/410.html) | Insufficient Resource Pool | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) | Unrestricted Externally Accessible Lock | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) | Improper Resource Locking | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) | Missing Lock Check | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-419](https://cwe.mitre.org/data/definitions/419.html) | Unprotected Primary Channel | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-420](https://cwe.mitre.org/data/definitions/420.html) | Unprotected Alternate Channel | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | CWE-284, CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) | Unprotected Windows Messaging Channel | CWE-284, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) | Untrusted Search Path | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) | Uncontrolled Search Path Element | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-428](https://cwe.mitre.org/data/definitions/428.html) | Unquoted Search Path or Element | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-430](https://cwe.mitre.org/data/definitions/430.html) | Deployment of Wrong Handler | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-431](https://cwe.mitre.org/data/definitions/431.html) | Missing Handler | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) | Dangerous Signal Handler not Disabled During Sensitive Operations | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) | Unparsed Raw Web Content Delivery | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | CWE-664 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-436](https://cwe.mitre.org/data/definitions/436.html) | Interpretation Conflict | CWE-435 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-437](https://cwe.mitre.org/data/definitions/437.html) | Incomplete Model of Endpoint Features | CWE-435 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-439](https://cwe.mitre.org/data/definitions/439.html) | Behavioral Change in New Version or Environment | CWE-435 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-440](https://cwe.mitre.org/data/definitions/440.html) | Expected Behavior Violation | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | Unintended Proxy or Intermediary | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | Inconsistent Interpretation of HTTP Requests | CWE-435 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-446](https://cwe.mitre.org/data/definitions/446.html) | UI Discrepancy for Security Feature | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-447](https://cwe.mitre.org/data/definitions/447.html) | Unimplemented or Unsupported Feature in UI | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-448](https://cwe.mitre.org/data/definitions/448.html) | Obsolete Feature in UI | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-449](https://cwe.mitre.org/data/definitions/449.html) | The UI Performs the Wrong Action | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-450](https://cwe.mitre.org/data/definitions/450.html) | Multiple Interpretations of UI Input | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | CWE-664, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) | Insecure Default Variable Initialization | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-454](https://cwe.mitre.org/data/definitions/454.html) | External Initialization of Trusted Variables or Data Stores | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | CWE-664, CWE-691, CWE-703, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-456](https://cwe.mitre.org/data/definitions/456.html) | Missing Initialization of a Variable | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-459](https://cwe.mitre.org/data/definitions/459.html) | Incomplete Cleanup | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) | Improper Cleanup on Thrown Exception | CWE-664, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) | Duplicate Key in Associative List (Alist) | CWE-707, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-463](https://cwe.mitre.org/data/definitions/463.html) | Deletion of Data Structure Sentinel | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-464](https://cwe.mitre.org/data/definitions/464.html) | Addition of Data Structure Sentinel | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-466](https://cwe.mitre.org/data/definitions/466.html) | Return of Pointer Value Outside of Expected Range | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-467](https://cwe.mitre.org/data/definitions/467.html) | Use of sizeof() on a Pointer Type | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-468](https://cwe.mitre.org/data/definitions/468.html) | Incorrect Pointer Scaling | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-469](https://cwe.mitre.org/data/definitions/469.html) | Use of Pointer Subtraction to Determine Size | CWE-682 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-470](https://cwe.mitre.org/data/definitions/470.html) | Use of Externally-Controlled Input to Select Classes or Code | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-471](https://cwe.mitre.org/data/definitions/471.html) | Modification of Assumed-Immutable Data (MAID) | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | External Control of Assumed-Immutable Web Parameter | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-473](https://cwe.mitre.org/data/definitions/473.html) | PHP External Variable Modification | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-474](https://cwe.mitre.org/data/definitions/474.html) | Use of Function with Inconsistent Implementations | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-475](https://cwe.mitre.org/data/definitions/475.html) | Undefined Behavior for Input to API | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | CWE-703, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-477](https://cwe.mitre.org/data/definitions/477.html) | Use of Obsolete Function | CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-478](https://cwe.mitre.org/data/definitions/478.html) | Missing Default Case in Multiple Condition Expression | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of a Non-reentrant Function | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-480](https://cwe.mitre.org/data/definitions/480.html) | Use of Incorrect Operator | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-481](https://cwe.mitre.org/data/definitions/481.html) | Assigning instead of Comparing | CWE-691 | undetermined | undetermined | 구현 자료 검토; 소스 검토 |
| [CWE-482](https://cwe.mitre.org/data/definitions/482.html) | Comparing instead of Assigning | CWE-691 | undetermined | undetermined | 구현 자료 검토; 소스 검토 |
| [CWE-483](https://cwe.mitre.org/data/definitions/483.html) | Incorrect Block Delimitation | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | CWE-691, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-486](https://cwe.mitre.org/data/definitions/486.html) | Comparison of Classes by Name | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-487](https://cwe.mitre.org/data/definitions/487.html) | Reliance on Package-level Scope | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-488](https://cwe.mitre.org/data/definitions/488.html) | Exposure of Data Element to Wrong Session | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-491](https://cwe.mitre.org/data/definitions/491.html) | Public cloneable() Method Without Final | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-492](https://cwe.mitre.org/data/definitions/492.html) | Use of Inner Class Containing Sensitive Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) | Critical Public Variable Without Final Modifier | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | CWE-664, CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-495](https://cwe.mitre.org/data/definitions/495.html) | Private Data Structure Returned From A Public Method | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-496](https://cwe.mitre.org/data/definitions/496.html) | Public Data Assigned to Private Array-Typed Field | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-497](https://cwe.mitre.org/data/definitions/497.html) | Exposure of Sensitive System Information to an Unauthorized Control Sphere | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-498](https://cwe.mitre.org/data/definitions/498.html) | Cloneable Class Containing Sensitive Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-499](https://cwe.mitre.org/data/definitions/499.html) | Serializable Class Containing Sensitive Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Marked Final | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-501](https://cwe.mitre.org/data/definitions/501.html) | Trust Boundary Violation | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-507](https://cwe.mitre.org/data/definitions/507.html) | Trojan Horse | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-508](https://cwe.mitre.org/data/definitions/508.html) | Non-Replicating Malicious Code | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-509](https://cwe.mitre.org/data/definitions/509.html) | Replicating Malicious Code (Virus or Worm) | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-510](https://cwe.mitre.org/data/definitions/510.html) | Trapdoor | CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) | Logic/Time Bomb | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-512](https://cwe.mitre.org/data/definitions/512.html) | Spyware | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-514](https://cwe.mitre.org/data/definitions/514.html) | Covert Channel | CWE-664 | undetermined | undetermined | 설계 자료 검토 |
| [CWE-515](https://cwe.mitre.org/data/definitions/515.html) | Covert Storage Channel | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-520](https://cwe.mitre.org/data/definitions/520.html) | .NET Misconfiguration: Use of Impersonation | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | Weak Password Requirements | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Unprotected Transport of Credentials | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-524](https://cwe.mitre.org/data/definitions/524.html) | Use of Cache Containing Sensitive Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-525](https://cwe.mitre.org/data/definitions/525.html) | Use of Web Browser Cache Containing Sensitive Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository to an Unauthorized Control Sphere | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) | Exposure of Core Dump File to an Unauthorized Control Sphere | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) | Exposure of Access Control List Files to an Unauthorized Control Sphere | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-531](https://cwe.mitre.org/data/definitions/531.html) | Inclusion of Sensitive Information in Test Code | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Exposure of Information Through Shell Error Message | CWE-664, CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) | Servlet Runtime Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) | Java Runtime Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Insertion of Sensitive Information into Externally-Accessible File or Directory | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) | Use of Persistent Cookies Containing Sensitive Information | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | Inclusion of Sensitive Information in Source Code | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-541](https://cwe.mitre.org/data/definitions/541.html) | Inclusion of Sensitive Information in an Include File | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-544](https://cwe.mitre.org/data/definitions/544.html) | Missing Standardized Error Handling Mechanism | CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-546](https://cwe.mitre.org/data/definitions/546.html) | Suspicious Comment | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-547](https://cwe.mitre.org/data/definitions/547.html) | Use of Hard-coded, Security-relevant Constants | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | Exposure of Information Through Directory Listing | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) | Missing Password Field Masking | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) | Server-generated Error Message Containing Sensitive Information | CWE-664, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | CWE-284, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Files or Directories Accessible to External Parties | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) | Command Shell in Externally Accessible Directory | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-554](https://cwe.mitre.org/data/definitions/554.html) | ASP.NET Misconfiguration: Not Using Input Validation Framework | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) | J2EE Misconfiguration: Plaintext Password in Configuration File | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-556](https://cwe.mitre.org/data/definitions/556.html) | ASP.NET Misconfiguration: Use of Identity Impersonation | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) | Use of getlogin() in Multithreaded Application | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-560](https://cwe.mitre.org/data/definitions/560.html) | Use of umask() with chmod-style Argument | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-561](https://cwe.mitre.org/data/definitions/561.html) | Dead Code | CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-562](https://cwe.mitre.org/data/definitions/562.html) | Return of Stack Variable Address | CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-563](https://cwe.mitre.org/data/definitions/563.html) | Assignment to Variable without Use | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-564](https://cwe.mitre.org/data/definitions/564.html) | Use of Hibernate with HQL/SQL Query String Containing External Input | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) | Reliance on Cookies without Validation and Integrity Checking | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-566](https://cwe.mitre.org/data/definitions/566.html) | Authorization Bypass Through User-Controlled SQL Primary Key | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) | Unsynchronized Access to Shared Data in a Multithreaded Context | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) | finalize() Method Without super.finalize() | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-570](https://cwe.mitre.org/data/definitions/570.html) | Expression is Always False | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-571](https://cwe.mitre.org/data/definitions/571.html) | Expression is Always True | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) | Call to Thread run() instead of start() | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-573](https://cwe.mitre.org/data/definitions/573.html) | Improper Following of Specification by Caller | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | CWE-664, CWE-691, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-575](https://cwe.mitre.org/data/definitions/575.html) | EJB Bad Practices: Use of AWT Swing | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-576](https://cwe.mitre.org/data/definitions/576.html) | EJB Bad Practices: Use of Java I/O | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-577](https://cwe.mitre.org/data/definitions/577.html) | EJB Bad Practices: Use of Sockets | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-578](https://cwe.mitre.org/data/definitions/578.html) | EJB Bad Practices: Use of Class Loader | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-579](https://cwe.mitre.org/data/definitions/579.html) | J2EE Bad Practices: Non-serializable Object Stored in Session | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) | clone() Method Without super.clone() | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) | Object Model Violation: Just One of Equals and Hashcode Defined | CWE-697, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) | Array Declared Public, Final, and Static | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) | finalize() Method Declared Public | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-584](https://cwe.mitre.org/data/definitions/584.html) | Return Inside Finally Block | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-585](https://cwe.mitre.org/data/definitions/585.html) | Empty Synchronized Block | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-586](https://cwe.mitre.org/data/definitions/586.html) | Explicit Call to Finalize() | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of a Fixed Address to a Pointer | CWE-693, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of a Non-structure Pointer | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-589](https://cwe.mitre.org/data/definitions/589.html) | Call to Non-ubiquitous API | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-590](https://cwe.mitre.org/data/definitions/590.html) | Free of Memory not on the Heap | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-594](https://cwe.mitre.org/data/definitions/594.html) | J2EE Framework: Saving Unserializable Objects to Disk | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-595](https://cwe.mitre.org/data/definitions/595.html) | Comparison of Object References Instead of Object Contents | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) | Use of Wrong Operator in String Comparison | CWE-691, CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Use of HTTP Request With Sensitive Query String | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-599](https://cwe.mitre.org/data/definitions/599.html) | Missing Validation of OpenSSL Certificate | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) | Uncaught Exception in Servlet | CWE-691, CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | URL Redirection to Untrusted Site | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) | Client-Side Enforcement of Server-Side Security | CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 실행 관찰 자료 검토 |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | Use of Client-Side Authentication | CWE-284, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds to the Same Port | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-606](https://cwe.mitre.org/data/definitions/606.html) | Unchecked Input for Loop Condition | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-607](https://cwe.mitre.org/data/definitions/607.html) | Public Static Final Field References Mutable Object | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) | Struts: Non-private Field in ActionForm Class | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) | Double-Checked Locking | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-610](https://cwe.mitre.org/data/definitions/610.html) | Externally Controlled Reference to a Resource in Another Sphere | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Improper Restriction of XML External Entity Reference | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-612](https://cwe.mitre.org/data/definitions/612.html) | Improper Authorization of Index Containing Sensitive Information | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-615](https://cwe.mitre.org/data/definitions/615.html) | Inclusion of Sensitive Information in Source Code Comments | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-616](https://cwe.mitre.org/data/definitions/616.html) | Incomplete Identification of Uploaded File Variables (PHP) | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-617](https://cwe.mitre.org/data/definitions/617.html) | Reachable Assertion | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-618](https://cwe.mitre.org/data/definitions/618.html) | Exposed Unsafe ActiveX Method | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-619](https://cwe.mitre.org/data/definitions/619.html) | Dangling Database Cursor | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-620](https://cwe.mitre.org/data/definitions/620.html) | Unverified Password Change | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) | Variable Extraction Error | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-622](https://cwe.mitre.org/data/definitions/622.html) | Improper Validation of Function Hook Arguments | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-623](https://cwe.mitre.org/data/definitions/623.html) | Unsafe ActiveX Control Marked Safe For Scripting | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-624](https://cwe.mitre.org/data/definitions/624.html) | Executable Regular Expression Error | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-625](https://cwe.mitre.org/data/definitions/625.html) | Permissive Regular Expression | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) | Null Byte Interaction Error (Poison Null Byte) | CWE-435, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) | Dynamic Variable Evaluation | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-628](https://cwe.mitre.org/data/definitions/628.html) | Function Call with Incorrectly Specified Arguments | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely | CWE-703, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-637](https://cwe.mitre.org/data/definitions/637.html) | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | CWE-284, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Authorization Bypass Through User-Controlled Key | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) | Weak Password Recovery Mechanism for Forgotten Password | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-641](https://cwe.mitre.org/data/definitions/641.html) | Improper Restriction of Names for Files and Other Resources | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-642](https://cwe.mitre.org/data/definitions/642.html) | External Control of Critical State Data | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-643](https://cwe.mitre.org/data/definitions/643.html) | Improper Neutralization of Data within XPath Expressions | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-644](https://cwe.mitre.org/data/definitions/644.html) | Improper Neutralization of HTTP Headers for Scripting Syntax | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-645](https://cwe.mitre.org/data/definitions/645.html) | Overly Restrictive Account Lockout Mechanism | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-646](https://cwe.mitre.org/data/definitions/646.html) | Reliance on File Name or Extension of Externally-Supplied File | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | CWE-284, CWE-691, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-648](https://cwe.mitre.org/data/definitions/648.html) | Incorrect Use of Privileged APIs | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-649](https://cwe.mitre.org/data/definitions/649.html) | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | Trusting HTTP Permission Methods on the Server Side | CWE-435 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-651](https://cwe.mitre.org/data/definitions/651.html) | Exposure of WSDL File Containing Sensitive Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-652](https://cwe.mitre.org/data/definitions/652.html) | Improper Neutralization of Data within XQuery Expressions | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | CWE-693, CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 소스 검토 |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-657](https://cwe.mitre.org/data/definitions/657.html) | Violation of Secure Design Principles | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) | Use of a Non-reentrant Function in a Concurrent Context | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) | Improper Initialization | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) | Operation on Resource in Wrong Phase of Lifetime | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | Exposure of Resource to Wrong Sphere | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-669](https://cwe.mitre.org/data/definitions/669.html) | Incorrect Resource Transfer Between Spheres | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-670](https://cwe.mitre.org/data/definitions/670.html) | Always-Incorrect Control Flow Implementation | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-671](https://cwe.mitre.org/data/definitions/671.html) | Lack of Administrator Control over Security | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-672](https://cwe.mitre.org/data/definitions/672.html) | Operation on a Resource after Expiration or Release | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-673](https://cwe.mitre.org/data/definitions/673.html) | External Influence of Sphere Definition | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) | Multiple Operations on Resource in Single-Operation Context | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-676](https://cwe.mitre.org/data/definitions/676.html) | Use of Potentially Dangerous Function | CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) | Integer Overflow to Buffer Overflow | CWE-682 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) | Incorrect Conversion between Numeric Types | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-683](https://cwe.mitre.org/data/definitions/683.html) | Function Call With Incorrect Order of Arguments | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-684](https://cwe.mitre.org/data/definitions/684.html) | Incorrect Provision of Specified Functionality | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-685](https://cwe.mitre.org/data/definitions/685.html) | Function Call With Incorrect Number of Arguments | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-686](https://cwe.mitre.org/data/definitions/686.html) | Function Call With Incorrect Argument Type | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-687](https://cwe.mitre.org/data/definitions/687.html) | Function Call With Incorrectly Specified Argument Value | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-688](https://cwe.mitre.org/data/definitions/688.html) | Function Call With Incorrect Variable or Reference as Argument | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) | Permission Race Condition During Resource Copy | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-690](https://cwe.mitre.org/data/definitions/690.html) | Unchecked Return Value to NULL Pointer Dereference | CWE-703 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) | Incomplete Denylist to Cross-Site Scripting | CWE-693, CWE-697 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) | Use of Multiple Resources with Duplicate Identifier | CWE-707, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-695](https://cwe.mitre.org/data/definitions/695.html) | Use of Low-Level Functionality | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-696](https://cwe.mitre.org/data/definitions/696.html) | Incorrect Behavior Order | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-698](https://cwe.mitre.org/data/definitions/698.html) | Execution After Redirect (EAR) | CWE-691 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) | Incorrect Type Conversion or Cast | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-705](https://cwe.mitre.org/data/definitions/705.html) | Incorrect Control Flow Scoping | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-706](https://cwe.mitre.org/data/definitions/706.html) | Use of Incorrectly-Resolved Name or Reference | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-708](https://cwe.mitre.org/data/definitions/708.html) | Incorrect Ownership Assignment | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) | Compiler Optimization Removal or Modification of Security-critical Code | CWE-435, CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-749](https://cwe.mitre.org/data/definitions/749.html) | Exposed Dangerous Method or Function | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | Improper Check for Unusual or Exceptional Conditions | CWE-703 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-755](https://cwe.mitre.org/data/definitions/755.html) | Improper Handling of Exceptional Conditions | CWE-703 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-756](https://cwe.mitre.org/data/definitions/756.html) | Missing Custom Error Page | CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | Selection of Less-Secure Algorithm During Negotiation | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-759](https://cwe.mitre.org/data/definitions/759.html) | Use of a One-Way Hash without a Salt | CWE-693 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 소스 검토 |
| [CWE-760](https://cwe.mitre.org/data/definitions/760.html) | Use of a One-Way Hash with a Predictable Salt | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-761](https://cwe.mitre.org/data/definitions/761.html) | Free of Pointer not at Start of Buffer | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-762](https://cwe.mitre.org/data/definitions/762.html) | Mismatched Memory Management Routines | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-763](https://cwe.mitre.org/data/definitions/763.html) | Release of Invalid Pointer or Reference | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | CWE-664, CWE-691, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | CWE-664, CWE-691, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | CWE-284, CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-767](https://cwe.mitre.org/data/definitions/767.html) | Access to Critical Private Variable via Public Method | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-768](https://cwe.mitre.org/data/definitions/768.html) | Incorrect Short Circuit Evaluation | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-771](https://cwe.mitre.org/data/definitions/771.html) | Missing Reference to Active Allocated Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-772](https://cwe.mitre.org/data/definitions/772.html) | Missing Release of Resource after Effective Lifetime | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-773](https://cwe.mitre.org/data/definitions/773.html) | Missing Reference to Active File Descriptor or Handle | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-774](https://cwe.mitre.org/data/definitions/774.html) | Allocation of File Descriptors or Handles Without Limits or Throttling | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-775](https://cwe.mitre.org/data/definitions/775.html) | Missing Release of File Descriptor or Handle after Effective Lifetime | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) | Improper Restriction of Recursive Entity References in DTDs | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-777](https://cwe.mitre.org/data/definitions/777.html) | Regular Expression without Anchors | CWE-697 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Insufficient Logging | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-779](https://cwe.mitre.org/data/definitions/779.html) | Logging of Excessive Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-780](https://cwe.mitre.org/data/definitions/780.html) | Use of RSA Algorithm without OAEP | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-781](https://cwe.mitre.org/data/definitions/781.html) | Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-782](https://cwe.mitre.org/data/definitions/782.html) | Exposed IOCTL with Insufficient Access Control | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-783](https://cwe.mitre.org/data/definitions/783.html) | Operator Precedence Logic Error | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | CWE-664, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Use of Path Manipulation Function without Maximum-sized Buffer | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-786](https://cwe.mitre.org/data/definitions/786.html) | Access of Memory Location Before Start of Buffer | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Out-of-bounds Write | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-788](https://cwe.mitre.org/data/definitions/788.html) | Access of Memory Location After End of Buffer | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | Memory Allocation with Excessive Size Value | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-790](https://cwe.mitre.org/data/definitions/790.html) | Improper Filtering of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-791](https://cwe.mitre.org/data/definitions/791.html) | Incomplete Filtering of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-792](https://cwe.mitre.org/data/definitions/792.html) | Incomplete Filtering of One or More Instances of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-793](https://cwe.mitre.org/data/definitions/793.html) | Only Filtering One Instance of a Special Element | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-794](https://cwe.mitre.org/data/definitions/794.html) | Incomplete Filtering of Multiple Instances of Special Elements | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-795](https://cwe.mitre.org/data/definitions/795.html) | Only Filtering Special Elements at a Specified Location | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-796](https://cwe.mitre.org/data/definitions/796.html) | Only Filtering Special Elements Relative to a Marker | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-797](https://cwe.mitre.org/data/definitions/797.html) | Only Filtering Special Elements at an Absolute Position | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | CWE-284, CWE-693, CWE-710 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | Improper Control of Interaction Frequency | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-804](https://cwe.mitre.org/data/definitions/804.html) | Guessable CAPTCHA | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-805](https://cwe.mitre.org/data/definitions/805.html) | Buffer Access with Incorrect Length Value | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-806](https://cwe.mitre.org/data/definitions/806.html) | Buffer Access Using Size of Source Buffer | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-807](https://cwe.mitre.org/data/definitions/807.html) | Reliance on Untrusted Inputs in a Security Decision | CWE-693 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) | Missing Synchronization | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) | Incorrect Synchronization | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-822](https://cwe.mitre.org/data/definitions/822.html) | Untrusted Pointer Dereference | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-823](https://cwe.mitre.org/data/definitions/823.html) | Use of Out-of-range Pointer Offset | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-824](https://cwe.mitre.org/data/definitions/824.html) | Access of Uninitialized Pointer | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-825](https://cwe.mitre.org/data/definitions/825.html) | Expired Pointer Dereference | CWE-664 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-826](https://cwe.mitre.org/data/definitions/826.html) | Premature Release of Resource During Expected Lifetime | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-827](https://cwe.mitre.org/data/definitions/827.html) | Improper Control of Document Type Definition | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) | Signal Handler with Functionality that is not Asynchronous-Safe | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | CWE-664 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-830](https://cwe.mitre.org/data/definitions/830.html) | Inclusion of Web Functionality from an Untrusted Source | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) | Signal Handler Function Associated with Multiple Signals | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of a Resource that is not Locked | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) | Deadlock | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-834](https://cwe.mitre.org/data/definitions/834.html) | Excessive Iteration | CWE-691 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-835](https://cwe.mitre.org/data/definitions/835.html) | Loop with Unreachable Exit Condition | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-836](https://cwe.mitre.org/data/definitions/836.html) | Use of Password Hash Instead of Password for Authentication | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-837](https://cwe.mitre.org/data/definitions/837.html) | Improper Enforcement of a Single, Unique Action | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-838](https://cwe.mitre.org/data/definitions/838.html) | Inappropriate Encoding for Output Context | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) | Numeric Range Comparison Without Minimum Check | CWE-697, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Improper Enforcement of Behavioral Workflow | CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-842](https://cwe.mitre.org/data/definitions/842.html) | Placement of User into Incorrect Group | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 실행 관찰 자료 검토; 소스 검토 |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-909](https://cwe.mitre.org/data/definitions/909.html) | Missing Initialization of Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-910](https://cwe.mitre.org/data/definitions/910.html) | Use of Expired File Descriptor | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-911](https://cwe.mitre.org/data/definitions/911.html) | Improper Update of Reference Count | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-913](https://cwe.mitre.org/data/definitions/913.html) | Improper Control of Dynamically-Managed Code Resources | CWE-664 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) | Improper Control of Dynamically-Identified Variables | CWE-664, CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Improperly Controlled Modification of Dynamically-Determined Object Attributes | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use of Password Hash With Insufficient Computational Effort | CWE-693 | undetermined | undetermined | 컴파일 산출물 검토; 설계 자료 검토; 구현 자료 검토; 소스 검토 |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) | Improper Neutralization of Special Elements used in an Expression Language Statement | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-920](https://cwe.mitre.org/data/definitions/920.html) | Improper Restriction of Power Consumption | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-921](https://cwe.mitre.org/data/definitions/921.html) | Storage of Sensitive Data in a Mechanism without Access Control | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | Insecure Storage of Sensitive Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-923](https://cwe.mitre.org/data/definitions/923.html) | Improper Restriction of Communication Channel to Intended Endpoints | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-924](https://cwe.mitre.org/data/definitions/924.html) | Improper Enforcement of Message Integrity During Transmission in a Communication Channel | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) | Improper Verification of Intent by Broadcast Receiver | CWE-284, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-926](https://cwe.mitre.org/data/definitions/926.html) | Improper Export of Android Application Components | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-927](https://cwe.mitre.org/data/definitions/927.html) | Use of Implicit Intent for Sensitive Communication | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | Improper Authorization in Handler for Custom URL Scheme | CWE-284, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) | Improper Verification of Source of a Communication Channel | CWE-284, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-941](https://cwe.mitre.org/data/definitions/941.html) | Incorrectly Specified Destination in a Communication Channel | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Security Policy with Untrusted Domains | CWE-284, CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | Improper Neutralization of Special Elements in Data Query Logic | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without 'HttpOnly' Flag | CWE-284, CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) | Insufficient Visual Distinction of Homoglyphs Presented to User | CWE-664, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Improper Restriction of Rendered UI Layers or Frames | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html) | Use of Web Link to Untrusted Target with window.opener Access | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1023](https://cwe.mitre.org/data/definitions/1023.html) | Incomplete Comparison with Missing Factors | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1024](https://cwe.mitre.org/data/definitions/1024.html) | Comparison of Incompatible Types | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html) | Comparison Using Wrong Factors | CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code | CWE-435, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | CWE-435, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | CWE-693, CWE-697 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) | Use of Redundant Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1042](https://cwe.mitre.org/data/definitions/1042.html) | Static Member Data Element outside of a Singleton Class Element | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html) | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) | Architecture with Number of Horizontal Layers Outside of Expected Range | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) | Creation of Immutable Text Using String Concatenation | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) | Modules with Circular Dependencies | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) | Invokable Control Element with Large Number of Outward Calls | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1049](https://cwe.mitre.org/data/definitions/1049.html) | Excessive Data Query Operations in a Large Data Table | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1050](https://cwe.mitre.org/data/definitions/1050.html) | Excessive Platform Resource Consumption within a Loop | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1051](https://cwe.mitre.org/data/definitions/1051.html) | Initialization with Hard-Coded Network Resource Configuration Data | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) | Excessive Use of Hard-Coded Literals in Initialization | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html) | Missing Documentation for Design | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1055](https://cwe.mitre.org/data/definitions/1055.html) | Multiple Inheritance from Concrete Classes | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1056](https://cwe.mitre.org/data/definitions/1056.html) | Invokable Control Element with Variadic Parameters | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1057](https://cwe.mitre.org/data/definitions/1057.html) | Data Access Operations Outside of Expected Data Manager Component | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | Insufficient Technical Documentation | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1060](https://cwe.mitre.org/data/definitions/1060.html) | Excessive Number of Inefficient Server-Side Data Accesses | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) | Insufficient Encapsulation | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1062](https://cwe.mitre.org/data/definitions/1062.html) | Parent Class with References to Child Class | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1063](https://cwe.mitre.org/data/definitions/1063.html) | Creation of Class Instance within a Static Code Block | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1064](https://cwe.mitre.org/data/definitions/1064.html) | Invokable Control Element with Signature Containing an Excessive Number of Parameters | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1065](https://cwe.mitre.org/data/definitions/1065.html) | Runtime Resource Management Control Element in a Component Built to Run on Application Servers | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1066](https://cwe.mitre.org/data/definitions/1066.html) | Missing Serialization Control Element | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1067](https://cwe.mitre.org/data/definitions/1067.html) | Excessive Execution of Sequential Searches of Data Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1068](https://cwe.mitre.org/data/definitions/1068.html) | Inconsistency Between Implementation and Documented Design | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1069](https://cwe.mitre.org/data/definitions/1069.html) | Empty Exception Block | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1070](https://cwe.mitre.org/data/definitions/1070.html) | Serializable Data Element Containing non-Serializable Item Elements | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1071](https://cwe.mitre.org/data/definitions/1071.html) | Empty Code Block | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1072](https://cwe.mitre.org/data/definitions/1072.html) | Data Resource Access without Use of Connection Pooling | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1073](https://cwe.mitre.org/data/definitions/1073.html) | Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1074](https://cwe.mitre.org/data/definitions/1074.html) | Class with Excessively Deep Inheritance | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1075](https://cwe.mitre.org/data/definitions/1075.html) | Unconditional Control Flow Transfer outside of Switch Block | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1076](https://cwe.mitre.org/data/definitions/1076.html) | Insufficient Adherence to Expected Conventions | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) | Floating Point Comparison with Incorrect Operator | CWE-691, CWE-697 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1078](https://cwe.mitre.org/data/definitions/1078.html) | Inappropriate Source Code Style or Formatting | CWE-710 | undetermined | undetermined | 구현 자료 검토; 소스 검토 |
| [CWE-1079](https://cwe.mitre.org/data/definitions/1079.html) | Parent Class without Virtual Destructor Method | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1080](https://cwe.mitre.org/data/definitions/1080.html) | Source Code File with Excessive Number of Lines of Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1082](https://cwe.mitre.org/data/definitions/1082.html) | Class Instance Self Destruction Control Element | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1083](https://cwe.mitre.org/data/definitions/1083.html) | Data Access from Outside Expected Data Manager Component | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1084](https://cwe.mitre.org/data/definitions/1084.html) | Invokable Control Element with Excessive File or Data Access Operations | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1085](https://cwe.mitre.org/data/definitions/1085.html) | Invokable Control Element with Excessive Volume of Commented-out Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1086](https://cwe.mitre.org/data/definitions/1086.html) | Class with Excessive Number of Child Classes | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1087](https://cwe.mitre.org/data/definitions/1087.html) | Class with Virtual Method without a Virtual Destructor | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) | Synchronous Access of Remote Resource without Timeout | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1089](https://cwe.mitre.org/data/definitions/1089.html) | Large Data Table with Excessive Number of Indices | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1090](https://cwe.mitre.org/data/definitions/1090.html) | Method Containing Access of a Member Element from Another Class | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) | Use of Object without Invoking Destructor Method | CWE-664, CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1092](https://cwe.mitre.org/data/definitions/1092.html) | Use of Same Invokable Control Element in Multiple Architectural Layers | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1093](https://cwe.mitre.org/data/definitions/1093.html) | Excessively Complex Data Representation | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1094](https://cwe.mitre.org/data/definitions/1094.html) | Excessive Index Range Scan for a Data Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1095](https://cwe.mitre.org/data/definitions/1095.html) | Loop Condition Value Update within the Loop | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) | Singleton Class Instance Creation without Proper Locking or Synchronization | CWE-664, CWE-691 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1097](https://cwe.mitre.org/data/definitions/1097.html) | Persistent Storable Data Element without Associated Comparison Control Element | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1098](https://cwe.mitre.org/data/definitions/1098.html) | Data Element containing Pointer Item without Proper Copy Control Element | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1099](https://cwe.mitre.org/data/definitions/1099.html) | Inconsistent Naming Conventions for Identifiers | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1100](https://cwe.mitre.org/data/definitions/1100.html) | Insufficient Isolation of System-Dependent Functions | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1101](https://cwe.mitre.org/data/definitions/1101.html) | Reliance on Runtime Component in Generated Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1102](https://cwe.mitre.org/data/definitions/1102.html) | Reliance on Machine-Dependent Data Representation | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1103](https://cwe.mitre.org/data/definitions/1103.html) | Use of Platform-Dependent Third Party Components | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | Use of Unmaintained Third Party Components | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1105](https://cwe.mitre.org/data/definitions/1105.html) | Insufficient Encapsulation of Machine-Dependent Functionality | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1106](https://cwe.mitre.org/data/definitions/1106.html) | Insufficient Use of Symbolic Constants | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1107](https://cwe.mitre.org/data/definitions/1107.html) | Insufficient Isolation of Symbolic Constant Definitions | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1108](https://cwe.mitre.org/data/definitions/1108.html) | Excessive Reliance on Global Variables | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1109](https://cwe.mitre.org/data/definitions/1109.html) | Use of Same Variable for Multiple Purposes | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1110](https://cwe.mitre.org/data/definitions/1110.html) | Incomplete Design Documentation | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1111](https://cwe.mitre.org/data/definitions/1111.html) | Incomplete I/O Documentation | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1112](https://cwe.mitre.org/data/definitions/1112.html) | Incomplete Documentation of Program Execution | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1113](https://cwe.mitre.org/data/definitions/1113.html) | Inappropriate Comment Style | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1114](https://cwe.mitre.org/data/definitions/1114.html) | Inappropriate Whitespace Style | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1115](https://cwe.mitre.org/data/definitions/1115.html) | Source Code Element without Standard Prologue | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1116](https://cwe.mitre.org/data/definitions/1116.html) | Inaccurate Source Code Comments | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1117](https://cwe.mitre.org/data/definitions/1117.html) | Callable with Insufficient Behavioral Summary | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1118](https://cwe.mitre.org/data/definitions/1118.html) | Insufficient Documentation of Error Handling Techniques | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1119](https://cwe.mitre.org/data/definitions/1119.html) | Excessive Use of Unconditional Branching | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1120](https://cwe.mitre.org/data/definitions/1120.html) | Excessive Code Complexity | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html) | Excessive McCabe Cyclomatic Complexity | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1122](https://cwe.mitre.org/data/definitions/1122.html) | Excessive Halstead Complexity | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1123](https://cwe.mitre.org/data/definitions/1123.html) | Excessive Use of Self-Modifying Code | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1124](https://cwe.mitre.org/data/definitions/1124.html) | Excessively Deep Nesting | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1125](https://cwe.mitre.org/data/definitions/1125.html) | Excessive Attack Surface | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1126](https://cwe.mitre.org/data/definitions/1126.html) | Declaration of Variable with Unnecessarily Wide Scope | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) | Compilation with Insufficient Warnings or Errors | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html) | Irrelevant Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1173](https://cwe.mitre.org/data/definitions/1173.html) | Improper Use of Validation Framework | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1174](https://cwe.mitre.org/data/definitions/1174.html) | ASP.NET Misconfiguration: Improper Model Validation | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1176](https://cwe.mitre.org/data/definitions/1176.html) | Inefficient CPU Computation | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1177](https://cwe.mitre.org/data/definitions/1177.html) | Use of Prohibited Code | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | Initialization of a Resource with an Insecure Default | CWE-664, CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | CWE-664, CWE-693, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1190](https://cwe.mitre.org/data/definitions/1190.html) | DMA Device Enabled Too Early in Boot Phase | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) | On-Chip Debug and Test Interface With Improper Access Control | CWE-284 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1192](https://cwe.mitre.org/data/definitions/1192.html) | Improper Identifier for IP Block used in System-On-Chip (SOC) | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1193](https://cwe.mitre.org/data/definitions/1193.html) | Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html) | Generation of Weak Initialization Vector (IV) | CWE-693 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1209](https://cwe.mitre.org/data/definitions/1209.html) | Failure to Disable Reserved Bits | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1220](https://cwe.mitre.org/data/definitions/1220.html) | Insufficient Granularity of Access Control | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1221](https://cwe.mitre.org/data/definitions/1221.html) | Incorrect Register Defaults or Module Parameters | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1222](https://cwe.mitre.org/data/definitions/1222.html) | Insufficient Granularity of Address Regions Protected by Register Locks | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) | Race Condition for Write-Once Attributes | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1224](https://cwe.mitre.org/data/definitions/1224.html) | Improper Restriction of Write-Once Bit Fields | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1229](https://cwe.mitre.org/data/definitions/1229.html) | Creation of Emergent Resource | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1230](https://cwe.mitre.org/data/definitions/1230.html) | Exposure of Sensitive Information Through Metadata | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1231](https://cwe.mitre.org/data/definitions/1231.html) | Improper Prevention of Lock Bit Modification | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) | Improper Lock Behavior After Power State Transition | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | CWE-284, CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) | Hardware Internal or Debug Modes Allow Override of Locks | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1235](https://cwe.mitre.org/data/definitions/1235.html) | Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) | Improper Neutralization of Formula Elements in a CSV File | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1239](https://cwe.mitre.org/data/definitions/1239.html) | Improper Zeroization of Hardware Register | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) | Use of a Cryptographic Primitive with a Risky Implementation | CWE-693 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html) | Use of Predictable Algorithm in Random Number Generator | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1242](https://cwe.mitre.org/data/definitions/1242.html) | Inclusion of Undocumented Features or Chicken Bits | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1243](https://cwe.mitre.org/data/definitions/1243.html) | Sensitive Non-Volatile Information Not Protected During Debug | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1244](https://cwe.mitre.org/data/definitions/1244.html) | Internal Asset Exposed to Unsafe Debug Access Level or State | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1245](https://cwe.mitre.org/data/definitions/1245.html) | Improper Finite State Machines (FSMs) in Hardware Logic | CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1246](https://cwe.mitre.org/data/definitions/1246.html) | Improper Write Handling in Limited-write Non-Volatile Memories | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1247](https://cwe.mitre.org/data/definitions/1247.html) | Improper Protection Against Voltage and Clock Glitches | CWE-703 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1248](https://cwe.mitre.org/data/definitions/1248.html) | Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1249](https://cwe.mitre.org/data/definitions/1249.html) | Application-Level Admin Tool with Inconsistent View of Underlying Operating System | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1250](https://cwe.mitre.org/data/definitions/1250.html) | Improper Preservation of Consistency Between Independent Representations of Shared State | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1251](https://cwe.mitre.org/data/definitions/1251.html) | Mirrored Regions with Different Values | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1252](https://cwe.mitre.org/data/definitions/1252.html) | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1253](https://cwe.mitre.org/data/definitions/1253.html) | Incorrect Selection of Fuse Values | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) | Incorrect Comparison Logic Granularity | CWE-664, CWE-697 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1255](https://cwe.mitre.org/data/definitions/1255.html) | Comparison Logic is Vulnerable to Power Side-Channel Attacks | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1256](https://cwe.mitre.org/data/definitions/1256.html) | Improper Restriction of Software Interfaces to Hardware Features | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 실행 관찰 자료 검토 |
| [CWE-1257](https://cwe.mitre.org/data/definitions/1257.html) | Improper Access Control Applied to Mirrored or Aliased Memory Regions | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1258](https://cwe.mitre.org/data/definitions/1258.html) | Exposure of Sensitive System Information Due to Uncleared Debug Information | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1259](https://cwe.mitre.org/data/definitions/1259.html) | Improper Restriction of Security Token Assignment | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1260](https://cwe.mitre.org/data/definitions/1260.html) | Improper Handling of Overlap Between Protected Memory Ranges | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1261](https://cwe.mitre.org/data/definitions/1261.html) | Improper Handling of Single Event Upsets | CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1262](https://cwe.mitre.org/data/definitions/1262.html) | Improper Access Control for Register Interface | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 설계 자료 검토; 형식 검증 자료 검토; 실행 관찰 자료 검토; 시뮬레이션 자료 검토 |
| [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) | Improper Physical Access Control | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1266](https://cwe.mitre.org/data/definitions/1266.html) | Improper Scrubbing of Sensitive Data from Decommissioned Device | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1267](https://cwe.mitre.org/data/definitions/1267.html) | Policy Uses Obsolete Encoding | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1268](https://cwe.mitre.org/data/definitions/1268.html) | Policy Privileges are not Assigned Consistently Between Control and Data Agents | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1269](https://cwe.mitre.org/data/definitions/1269.html) | Product Released in Non-Release Configuration | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1270](https://cwe.mitre.org/data/definitions/1270.html) | Generation of Incorrect Security Tokens | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1271](https://cwe.mitre.org/data/definitions/1271.html) | Uninitialized Value on Reset for Registers Holding Security Settings | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1272](https://cwe.mitre.org/data/definitions/1272.html) | Sensitive Information Uncleared Before Debug/Power State Transition | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1273](https://cwe.mitre.org/data/definitions/1273.html) | Device Unlock Credential Sharing | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1274](https://cwe.mitre.org/data/definitions/1274.html) | Improper Access Control for Volatile Memory Containing Boot Code | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | Sensitive Cookie with Improper SameSite Attribute | CWE-284 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1276](https://cwe.mitre.org/data/definitions/1276.html) | Hardware Child Block Incorrectly Connected to Parent System | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) | Firmware Not Updateable | CWE-664, CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1278](https://cwe.mitre.org/data/definitions/1278.html) | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) | Cryptographic Operations are Run Before Supporting Units are Ready | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) | Access Control Check Implemented After Asset is Accessed | CWE-284, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1281](https://cwe.mitre.org/data/definitions/1281.html) | Sequence of Processor Instructions Leads to Unexpected Behavior | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1282](https://cwe.mitre.org/data/definitions/1282.html) | Assumed-Immutable Data is Stored in Writable Memory | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1283](https://cwe.mitre.org/data/definitions/1283.html) | Mutable Attestation or Measurement Reporting Data | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1284](https://cwe.mitre.org/data/definitions/1284.html) | Improper Validation of Specified Quantity in Input | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1285](https://cwe.mitre.org/data/definitions/1285.html) | Improper Validation of Specified Index, Position, or Offset in Input | CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html) | Improper Validation of Syntactic Correctness of Input | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html) | Improper Validation of Specified Type of Input | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1288](https://cwe.mitre.org/data/definitions/1288.html) | Improper Validation of Consistency within Input | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1289](https://cwe.mitre.org/data/definitions/1289.html) | Improper Validation of Unsafe Equivalence in Input | CWE-707 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1290](https://cwe.mitre.org/data/definitions/1290.html) | Incorrect Decoding of Security Identifiers | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1291](https://cwe.mitre.org/data/definitions/1291.html) | Public Key Re-Use for Signing both Debug and Production Code | CWE-693 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1292](https://cwe.mitre.org/data/definitions/1292.html) | Incorrect Conversion of Security Identifiers | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1293](https://cwe.mitre.org/data/definitions/1293.html) | Missing Source Correlation of Multiple Independent Data | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1294](https://cwe.mitre.org/data/definitions/1294.html) | Insecure Security Identifier Mechanism | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html) | Debug Messages Revealing Unnecessary Information | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1296](https://cwe.mitre.org/data/definitions/1296.html) | Incorrect Chaining or Granularity of Debug Components | CWE-284 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1297](https://cwe.mitre.org/data/definitions/1297.html) | Unprotected Confidential Information on Device is Accessible by OSAT Vendors | CWE-284 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) | Hardware Logic Contains Race Conditions | CWE-664, CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1299](https://cwe.mitre.org/data/definitions/1299.html) | Missing Protection Mechanism for Alternate Hardware Interface | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1300](https://cwe.mitre.org/data/definitions/1300.html) | Improper Protection of Physical Side Channels | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1301](https://cwe.mitre.org/data/definitions/1301.html) | Insufficient or Incomplete Data Removal within Hardware Component | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1302](https://cwe.mitre.org/data/definitions/1302.html) | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | CWE-664, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1304](https://cwe.mitre.org/data/definitions/1304.html) | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) | Missing Ability to Patch ROM Code | CWE-664, CWE-710 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1311](https://cwe.mitre.org/data/definitions/1311.html) | Improper Translation of Security Attributes by Fabric Bridge | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1312](https://cwe.mitre.org/data/definitions/1312.html) | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | CWE-284 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1313](https://cwe.mitre.org/data/definitions/1313.html) | Hardware Allows Activation of Test or Debug Logic at Runtime | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1314](https://cwe.mitre.org/data/definitions/1314.html) | Missing Write Protection for Parametric Data Values | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1315](https://cwe.mitre.org/data/definitions/1315.html) | Improper Setting of Bus Controlling Capability in Fabric End-point | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1316](https://cwe.mitre.org/data/definitions/1316.html) | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | CWE-284 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1317](https://cwe.mitre.org/data/definitions/1317.html) | Improper Access Control in Fabric Bridge | CWE-284 | undetermined | undetermined | 형식 검증 자료 검토; 시뮬레이션 자료 검토 |
| [CWE-1318](https://cwe.mitre.org/data/definitions/1318.html) | Missing Support for Security Features in On-chip Fabrics or Buses | CWE-693 | undetermined | undetermined | 설계 자료 검토; 소스 검토 |
| [CWE-1319](https://cwe.mitre.org/data/definitions/1319.html) | Improper Protection against Electromagnetic Fault Injection (EM-FI) | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1320](https://cwe.mitre.org/data/definitions/1320.html) | Improper Protection for Outbound Error Messages and Alert Signals | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | Improperly Controlled Modification of Object Prototype Attributes | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1322](https://cwe.mitre.org/data/definitions/1322.html) | Use of Blocking Code in Single-threaded, Non-blocking Context | CWE-691 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1323](https://cwe.mitre.org/data/definitions/1323.html) | Improper Management of Sensitive Trace Data | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1325](https://cwe.mitre.org/data/definitions/1325.html) | Improperly Controlled Sequential Memory Allocation | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) | Missing Immutable Root of Trust in Hardware | CWE-693 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) | Binding to an Unrestricted IP Address | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1328](https://cwe.mitre.org/data/definitions/1328.html) | Security Version Number Mutable to Older Versions | CWE-284 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) | Reliance on Component That is Not Updateable | CWE-664, CWE-710 | undetermined | undetermined | 설계 자료 검토 |
| [CWE-1330](https://cwe.mitre.org/data/definitions/1330.html) | Remanent Data Readable after Memory Erase | CWE-664 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | CWE-664, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1332](https://cwe.mitre.org/data/definitions/1332.html) | Improper Handling of Faults that Lead to Instruction Skips | CWE-703 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 시뮬레이션 자료 검토 |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | Inefficient Regular Expression Complexity | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1334](https://cwe.mitre.org/data/definitions/1334.html) | Unauthorized Error Injection Can Degrade Hardware Redundancy | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1335](https://cwe.mitre.org/data/definitions/1335.html) | Incorrect Bitwise Shift of Integer | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | CWE-664, CWE-707 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1338](https://cwe.mitre.org/data/definitions/1338.html) | Improper Protections Against Hardware Overheating | CWE-703 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1339](https://cwe.mitre.org/data/definitions/1339.html) | Insufficient Precision or Accuracy of a Real Number | CWE-682 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1341](https://cwe.mitre.org/data/definitions/1341.html) | Multiple Releases of Same Resource or Handle | CWE-710 | undetermined | undetermined | 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1342](https://cwe.mitre.org/data/definitions/1342.html) | Information Exposure through Microarchitectural State after Transient Execution | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1351](https://cwe.mitre.org/data/definitions/1351.html) | Improper Handling of Hardware Behavior in Exceptionally Cold Environments | CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | Reliance on Insufficiently Trustworthy Component | CWE-710 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1384](https://cwe.mitre.org/data/definitions/1384.html) | Improper Handling of Physical or Environmental Conditions | CWE-703 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets | CWE-284, CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1386](https://cwe.mitre.org/data/definitions/1386.html) | Insecure Operation on Windows Junction / Mount Point | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1389](https://cwe.mitre.org/data/definitions/1389.html) | Incorrect Parsing of Numbers with Different Radices | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) | Weak Authentication | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) | Use of Weak Credentials | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | Use of Default Credentials | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1393](https://cwe.mitre.org/data/definitions/1393.html) | Use of Default Password | CWE-284 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1394](https://cwe.mitre.org/data/definitions/1394.html) | Use of Default Cryptographic Key | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Dependency on Vulnerable Third-Party Component | CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1419](https://cwe.mitre.org/data/definitions/1419.html) | Incorrect Initialization of Resource | CWE-664 | undetermined | undetermined | 구현 자료 검토 |
| [CWE-1420](https://cwe.mitre.org/data/definitions/1420.html) | Exposure of Sensitive Information during Transient Execution | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1421](https://cwe.mitre.org/data/definitions/1421.html) | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 실행 관찰 자료 검토 |
| [CWE-1422](https://cwe.mitre.org/data/definitions/1422.html) | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 구현 자료 검토 |
| [CWE-1423](https://cwe.mitre.org/data/definitions/1423.html) | Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화 |
| [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) | Improper Validation of Generative AI Output | CWE-707 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) | Improper Neutralization of Input Used for LLM Prompting | CWE-707 | undetermined | undetermined | 설계 자료 검토; 실행 관찰 자료 검토 |
| [CWE-1428](https://cwe.mitre.org/data/definitions/1428.html) | Reliance on HTTP instead of HTTPS | CWE-693 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1429](https://cwe.mitre.org/data/definitions/1429.html) | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | CWE-664 | undetermined | undetermined | 소스 검토 |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | CWE-664, CWE-693, CWE-710 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 형식 검증 자료 검토; 시뮬레이션 자료 검토; 소스 검토 |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) | Insecure Setting of Generative AI/ML Model Inference Parameters | CWE-664, CWE-710 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1461](https://cwe.mitre.org/data/definitions/1461.html) | Hardware Simulation / Synthesis Mismatch | CWE-435 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 형식 검증 자료 검토; 실행 관찰 자료 검토; 시뮬레이션 자료 검토; 소스 검토 |
| [CWE-1462](https://cwe.mitre.org/data/definitions/1462.html) | Improper Session Management | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html) | Insufficient Session Timeout Value | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html) | Improper Session Invalidation | CWE-284 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1465](https://cwe.mitre.org/data/definitions/1465.html) | Improper Session Invalidation after User Logout | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1466](https://cwe.mitre.org/data/definitions/1466.html) | Improper Session Invalidation after Authentication Credential Change | CWE-284 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1467](https://cwe.mitre.org/data/definitions/1467.html) | Use of Singular Authentication Artifact for Multiple User Sessions | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1469](https://cwe.mitre.org/data/definitions/1469.html) | Improper Check for Credential Expiration | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1470](https://cwe.mitre.org/data/definitions/1470.html) | Improper External Identity Verification | CWE-284 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1471](https://cwe.mitre.org/data/definitions/1471.html) | Insufficiently Controlled Parser Differential | CWE-435 | undetermined | undetermined | 실행 관찰 자료 검토 |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) | Generation of Credential with Long Expiration | CWE-284, CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 실행 관찰 자료 검토 |
| [CWE-1473](https://cwe.mitre.org/data/definitions/1473.html) | Improper Expiration of Cached Data | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1474](https://cwe.mitre.org/data/definitions/1474.html) | Non-Equivalent Data Transformation | CWE-664 | undetermined | undetermined | CVE·벤더 근거로 검토 자료 구체화; 실행 관찰 자료 검토 |
| [CWE-1475](https://cwe.mitre.org/data/definitions/1475.html) | Incomplete Data/State Propagation | CWE-664 | undetermined | undetermined | CVE·벤더 메커니즘 우선 확인 |
| [CWE-1476](https://cwe.mitre.org/data/definitions/1476.html) | Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | CWE-691 | undetermined | undetermined | 설계 자료 검토; 형식 검증 자료 검토; 시뮬레이션 자료 검토 |
