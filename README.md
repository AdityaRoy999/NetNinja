# NetNinja Security Toolkit

NetNinja is an all-in-one security toolkit for the digital age, designed to help users protect, encrypt, and secure their digital assets with ease. This Streamlit-based web application offers a suite of cybersecurity tools for various security-related tasks.

## Features

1. **Phishing Link Scanner**: Scan URLs for potential phishing threats using VirusTotal's API.
2. **Message Encrypter/Decrypter**: Encrypt and decrypt sensitive messages for secure communication. Now includes QR code generation for encrypted messages and keys.
3. **File Integrity Checker**: Calculate and verify file hashes to ensure data integrity.
4. **Password Generator**: Create strong, unique passwords to enhance your online security.
5. **File Encrypter/Decrypter**: Secure your files with strong encryption and decrypt them when needed.
6. **Password Strength Analyzer**: Analyze the strength of your passwords and get improvement suggestions.
7. **QR Code Generator**: Generate QR codes for easy sharing of information.

## Prerequisites

- Python 3.7+
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/netninja-security-toolkit.git
   cd netninja-security-toolkit
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up your VirusTotal API key:
   - Sign up for a VirusTotal account and obtain an API key
   - Replace the `VIRUSTOTAL_API_KEY` variable in the script with your actual API key

## Usage

1. Run the Streamlit app:
   ```
   streamlit run netninja_app.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`)

3. Use the sidebar to navigate between different tools or click on the tool cards on the home page

4. Follow the on-screen instructions for each tool to perform various security-related tasks

## Tools Overview

### Phishing Link Scanner
- Enter a URL to scan it for potential phishing threats. The tool uses VirusTotal's API to check the URL against multiple security engines and provides a detailed analysis of the results.

### Message Encrypter/Decrypter
- Encrypt sensitive messages for secure communication or decrypt encrypted messages. You can provide your own encryption key or let the tool generate one for you. 

- New feature: After encryption, you can now generate a QR code containing both the encrypted message and the encryption key. This QR code can be scanned to easily share the encrypted information securely.

### File Integrity Checker
- Upload a file to calculate its SHA-256 hash. You can also verify the file's integrity by comparing it against a known hash. Additionally, you can scan the file using VirusTotal for potential threats.

### Password Generator
- Generate strong, unique passwords based on your specified criteria, including length and character types (letters, numbers, symbols).

### File Encrypter/Decrypter
- Encrypt files to secure them or decrypt previously encrypted files. The tool uses the Fernet symmetric encryption scheme for file encryption and decryption.

### Password Strength Analyzer
- Enter a password to analyze its strength. The tool provides a score and feedback on how to improve the password's security.

### QR Code Generator
- Generate QR codes for easy sharing of information. Enter the data you want to encode, and the tool will create a downloadable QR code image.

## Security Considerations

- Always use secure and private networks when working with sensitive information.
- Do not share encryption keys or passwords through insecure channels.
- When using the QR code feature for encrypted messages, ensure that you share the QR code securely, as it contains both the encrypted message and the key.
- Regularly update the application and its dependencies to ensure you have the latest security patches.

## Contributing

Contributions to the NetNinja Security Toolkit are welcome! Please feel free to submit pull requests, report bugs, or suggest new features through the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This toolkit is provided for educational and informational purposes only. Always ensure you have the right to scan, encrypt, or analyze any data or URLs you input into the toolkit. The developers are not responsible for any misuse or damage caused by this toolkit.
