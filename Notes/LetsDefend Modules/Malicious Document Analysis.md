[15/12/2025]
### What are Macros?
- They are small programs written to automate repetitive task in MS Office applications.
- Usually written in Visual Basic for Applications (VBA)
	- Used over all MS Office products.

---
### Useful Tools/Commands for Analyzing a File

| Linux Command           | Function                                                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| md5sum __               | Displays the MD5 hash for the file                                                                                          |
| sha256sum __            | Displays the SHA256 hash for the file                                                                                       |
| exiftool __             | Displays the file metadata                                                                                                  |
| strings __              | Displays the contents of the file, can use [-n (number)] to filter words above a certain character length                   |
| grep [word] [file]      | Filters and searches for specified word in specified file                                                                   |
|                         | Use [ strings \| grep ] to display contents and filter by lines with a specific word.                                       |
| xorsearch [file] [word] | Searches for encrypted strings that (when decrypted) show the inserted word. Use -p to search for any embedded executables. |

---
### Oletools Commands [oletools GitHub](https://github.com/decalage2/oletools)
GitHub repository package of python tools to analyze several legacy files such as Microsoft Office 97-2003 documents, MSI files or Outlook messages. These are otherwise known as Microsoft OLE2 files.

To install oletools in Linux:
[$sudo -H pip install -U oletools]

To install oletools in Windows:
[#pip install -U oletools]

**Note: will need python installed**

| Command    | Function                                                                                                                                                                      |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| olemeta __ | Displays the file metadata (prettier format)                                                                                                                                  |
| oleid __   | Displays several indicators for the user to analyze for characteristics usually present in malicious files (will show suspicion values/risk level for applicable indicators). |
| olevba __  | Extracts and scans VBA macros. Will highlight suspicious code. Has many options for filtering.                                                                                |
| mraptor __ | Detects malicious macros. Will return an exit code based on the analysis result.                                                                                              |

#### Common Options (from GitHub)

| Option        | Function                                                                                                 |
| ------------- | -------------------------------------------------------------------------------------------------------- |
| -r            | Find files recursively in subdirectories                                                                 |
| -z [password] | Open a password-protected zip file                                                                       |
| -f __         | Files to be processed within a zip file. Wildcards supported. <br>Default: ** (all) \| Ex: -f word/*.bin |
| -h            | Show help                                                                                                |

#### OLEVBA Options (from GitHub)

| Option            | Function                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| -a <br>--analysis | Display only analysis results, not the macro source code                                                 |
| -c<br>--code      | Display only VBA source code, do not analyze it                                                          |
| --decode          | Display all the obfuscated strings with their decoded content (Hex, Base64, StrReverse, Dridex, VBA)<br> |
| --attr            | Display the attribute lines at the beginning of VBA source code                                          |
| --reveal          | Display the macro source code after replacing all the obfuscated strings by their decoded content        |
| --deobf           | Attempt to deobfuscate VBA expressions (slow)                                                            |
| -j<br>--json      | Displays in JSON mode, detailed in JSON format                                                           |
