# SKILL: review-file-boundaries

## Contract

**Trigger:** Phase 4. Run for any service handling file upload, download, or path construction.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, file handling library
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path

## Procedure
1. search_code(pattern="File.Read|File.Write|Path.Combine|Directory.Get|File.Exists|StreamReader|multer|formidable|upload") to find file operations.
2. For each file operation taking a user-supplied path or filename: is the path normalized and validated?
3. Check path traversal: does Path.Combine or equivalent reject "../" segments? Is there a canonicalization check?
4. Check file upload: is file type validated by content (magic bytes) or only by extension/MIME header?
5. Check upload destination: is the file stored in a publicly accessible directory? Can it be executed?
6. Check archive extraction (zip, tar): is there path traversal prevention for archive member paths?
7. Check symlink following: does the operation follow symlinks that could point outside the allowed directory?
8. Check temporary file creation: are temp files created with predictable names? In a shared temp directory?
9. Check file deletion: can a user delete an arbitrary file by controlling the path?
10. Check download endpoints: does the file serve endpoint restrict to allowed directories?
11. Check overwrite: can a user overwrite an existing file (e.g., overwrite application files)?

## Required evidence
- File path construction: source of path components, normalization applied
- Upload type validation method (extension-only vs. magic bytes)
- Archive extraction traversal protection
- Download endpoint directory restriction
- Temp file predictability

## Counterchecks
- Path.Combine in .NET does not sanitize ".." — only GetFullPath + StartsWith check is sufficient.
- MIME type from request Content-Type header is user-controlled — only magic bytes are trusted.
- A publicly accessible upload directory is only a finding if the file type allows execution (PHP, ASP, etc.) or sensitive data access.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: path traversal to read/write outside allowed dir, uploaded script executable from web, zip slip, arbitrary file deletion.

## Stop condition
When all file path construction and upload handling code is classified with their validation approach.

## Forbidden inferences
- Do not report path traversal without confirming the traversal sequences are not normalized before the path is used.
- Do not report upload vulnerability without confirming the uploaded file is accessible from a web-reachable path.
