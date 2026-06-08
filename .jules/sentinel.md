## 2023-10-25 - Prevent Path Traversal in File Downloads
**Vulnerability:** Path Traversal
**Learning:** Even if helper methods (like `PcapFilePath`) use `filepath.Base` internally, directly trusting a user-supplied filename parameter when constructing file paths for download via `http.ServeFile` creates a defense-in-depth risk if the internal function changes or is bypassed.
**Prevention:** Always independently verify the resolved absolute path (`filepath.Abs`) starts with the expected absolute directory path using `strings.HasPrefix(absPath, absDir+string(filepath.Separator))`.
