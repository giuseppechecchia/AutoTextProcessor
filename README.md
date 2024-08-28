# AutoTextProcessor
An example of a poorly written documents parser in C to demonstrate that it could be done

## TODO

- [ ] **Securely Handle API Keys**
  - Remove hardcoded API keys from the source code. Load the API key from environment variables or a configuration file to enhance security.

- [ ] **Fix `strncpy` Usage**
  - Ensure strings are properly null-terminated when using `strncpy`. Consider switching to `snprintf` or manually adding a `\0` after copying.

- [ ] **Optimize JSON String Escaping**
  - Improve the memory allocation in the `escape_json_string` function by calculating the exact required buffer size before allocation.

- [ ] **Improve Thread Safety**
  - Add mutex protection to all SQLite database operations to prevent race conditions and ensure consistent access to shared resources.

- [ ] **Memory Management**
  - Review and improve memory management practices to prevent leaks, especially in functions where dynamic memory allocation is used.

- [ ] **Enhance Error Logging**
  - Direct error messages to `stderr` instead of `stdout` and provide more informative error messages for better debugging.

- [ ] **Replace `system()` Calls**
  - Replace the use of `system()` with safer alternatives, such as specific libraries or functions like `exec`, to avoid security vulnerabilities.

- [ ] **Refine Text Processing Logic**
  - Improve the logic in `process_and_summarize_text` to handle different sentence delimiters correctly and ensure robust text tokenization.

- [ ] **Enhance `inotify` Event Handling**
  - Implement a system to avoid race conditions when files are modified while being processed. Consider version control or file locking mechanisms.

- [ ] **Use a More Robust Hashing Algorithm**
  - Replace the simple hash function with a more robust algorithm like SHA-256 to avoid potential hash collisions in scenarios with many files.

- [ ] **Strengthen UTF-8 Validation**
  - Ensure the `validate_utf8` function correctly handles text encoding and conversion, especially for international texts from various sources.
