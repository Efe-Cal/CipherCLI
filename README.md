# Crypto File Encryptor

A command-line tool for encrypting and decrypting files using symmetric encryption (Fernet). Supports filename encryption, key management, and interactive file selection.

## Features

- Encrypt and decrypt files with a secure key.
- Optionally encrypt/decrypt filenames.
- Key file management: auto-detect, create new, or select manually.
- Works with single or multiple files, or entire directories.
- Interactive prompts for all operations.

## Requirements

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- [psutil](https://pypi.org/project/psutil/)
- [InquirerPy](https://pypi.org/project/InquirerPy/)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script:
```bash
python main.py [file_or_directory ...]
```

If no files are provided as arguments, you will be prompted to select files interactively.

### Operations

- **Encrypt**: Encrypt files and optionally their filenames.
- **Decrypt**: Decrypt files and optionally their filenames.
- **Decrypt & Encrypt**: Temporarily decrypt a file for editing, then re-encrypt after closing the editor.

### Key Management

- The tool searches for `.key` files on removable drives and prompts you to select or create a key.
- You can also manually specify a key file.

## Notes

- Encrypted filenames are not human-readable.
- Keep your key file safe! Losing it means you cannot decrypt your files.
