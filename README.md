# alu-regex-data-extraction_froches2025
Using regular expressions in Python, I extracted data from a messy dataset, created sorting criteria, and carefully crafted regex patterns to match 4 different types of data. I also handled security, preventing malicious pieces of data from being sorted in the first place.

Data Types:
- Email Addresses (with ALU classification)
- Phone Numbers
- Hashtags
- Currency

## How to Run:
First, clone the Repo:
```
git clone https://github.com/froches2025/alu-regex-data-extraction_froches2025.git
cd alu-regex-data-extraction_froches2025
```

Then check your python version. Here's the version I use:
```Python Version: Python 3.12.3```


In your terminal, run:
```python3 src/main.py```

Check ```output```, and you should see the `sample-output.json` file created and containing cleaned, sorted data.

Directory Structure from the root:
```
.
├── README.md
├── input
│   └── raw-text.txt
├── output
│   └── sample-output.json
└── src
    └── main.py

4 directories, 4 files
```

## Security
The program scans input for hostile patterns before extraction begins.
These are the threats that are detected and flagged:

- XSS (<script> tags): can execute malicious code in a browser
- SQL injection (SELECT...FROM, OR 1=1): can manipulate database queries
- Path traversal (../..): can access files outside the intended directory
- Null byte injection (%00): can truncate strings and bypass validation
- XSS event handlers (onerror=): can trigger scripts through HTML attributes

Credit card numbers are masked in output, showing only the last 4 digits.
Email addresses exceeding 254 characters are rejected.