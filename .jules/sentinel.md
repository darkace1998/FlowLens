## 2023-10-25 - Prevent Path Traversal in File Downloads
**Vulnerability:** Path Traversal
**Learning:** Even if helper methods (like `PcapFilePath`) use `filepath.Base` internally, directly trusting a user-supplied filename parameter when constructing file paths for download via `http.ServeFile` creates a defense-in-depth risk if the internal function changes or is bypassed.
**Prevention:** Always independently verify the resolved absolute path (`filepath.Abs`) starts with the expected absolute directory path using `strings.HasPrefix(absPath, absDir+string(filepath.Separator))`.

## 2024-06-14 - Hardcode SQL identifiers to prevent injection
**Vulnerability:** SQL Injection
**Learning:** Constructing SQL queries using string formatting (`fmt.Sprintf`) with user input as column or table names introduces a SQL injection risk, even when protected by a whitelist. If the whitelist is compromised or changed in the future, the application becomes vulnerable.
**Prevention:** Instead of using user input directly, map the allowed user input values to hardcoded string literals via a map (`map[string]string`) or switch statement. Use the resolved string literal in the query string to completely break the data flow from user input to the query.
