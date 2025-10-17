# Tatou Lightweight Python Fuzzer Configuration

## Overview
The goal is to test the robustness and input validation of the Tatou web API.
This lightweight fuzzer targets the main JSON endpoints and the file-upload handler.

## Fuzzer Implementation
- **Tool:** Custom Python fuzzer (`fuzz/simple_fuzzer.py`)
- **Library dependencies:** `requests`, `random`, `string`
- **Language:** Python 3.12
- **Execution command:**
  ```bash
  TATOU_BASE=http://localhost:5000 python3 fuzz/simple_fuzzer.py
