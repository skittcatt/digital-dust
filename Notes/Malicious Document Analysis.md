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
| olemeta __              | Displays the file metadata (prettier format)                                                                                |
| strings __              | Displays the contents of the file, can use [-n (number)] to filter words above a certain character length                   |
| grep [word] [file]      | Filters and searches for specified word in specified file                                                                   |
|                         | Use [ strings \| grep ] to display contents and filter by lines with a specific word.                                       |
| xorsearch [file] [word] | Searches for encrypted strings that (when decrypted) show the inserted word. Use -p to search for any embedded executables. |


---


