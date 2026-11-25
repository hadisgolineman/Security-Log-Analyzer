# Security Log Analyzer

A Python-based security log analysis tool designed to inspect web server logs, identify suspicious requests, and detect potential security threats.

This project is developed as a practical cybersecurity learning project and includes two versions: a basic log analyzer and an advanced analyzer.

## Project Versions

### Version 1 – Basic Log Analyzer

The basic version provides essential log analysis capabilities.

**Features:**
- Read and analyze web server log files.
- Extract IP addresses, HTTP methods, URLs, and status codes.
- Count total requests.
- Detect unauthorized requests (HTTP 401).
- Identify IP addresses with repeated unauthorized requests.
- Generate a basic security report.
- Handle invalid log entries.

### Version 2 – Advanced Log Analyzer

The advanced version introduces basic pattern-based detection of common web attack indicators.

**Features:**
- All core log parsing capabilities.
- SQL Injection pattern detection.
- Cross-Site Scripting (XSS) pattern detection.
- Regular expression-based detection.
- URL decoding and normalization.
- Suspicious IP tracking.
- Advanced security reporting.

## Project Structure

```text
Security-Log-Analyzer/
│
├── v1-basic/
│   ├── main.py
│   └── security.log
│
├── v2-advanced/
│   ├── Security-Log-Analyzer.py
│   └── security.log
│
└── README.md
```

## Requirements

- Python 3.x
- No external Python libraries required.

The project uses Python standard library modules.

## Installation

Clone the repository:

```bash
git clone https://github.com/hadisgolineman/Security-Log-Analyzer.git
```

Navigate to the project directory:

```bash
cd Security-Log-Analyzer
```

## Usage

### Run Version 1

```bash
cd v1-basic
python main.py
```

### Run Version 2

```bash
cd ../v2-advanced
python Security-Log-Analyzer.py
```

Make sure the `security.log` file is in the same directory as the Python script.

## Detection Capabilities

The advanced version checks URLs for configured indicators such as:

**SQL Injection**
- UNION SELECT
- OR-based conditions
- DROP TABLE
- SELECT statements

**Cross-Site Scripting (XSS)**
- Script tags
- JavaScript URLs
- Event handler attributes
- Alert function patterns

## Limitations

- Detection is based on predefined patterns and regular expressions.
- Pattern matches are potential attack indicators, not proof of a successful attack.
- The current implementation analyzes URLs, not HTTP request bodies.
- The tool is intended for learning and basic log analysis, not as a replacement for professional security monitoring systems.

## Future Improvements

- More advanced attack detection.
- Better log parsing and validation.
- Export security reports to JSON or CSV.
- Improved detection accuracy.
- Additional security analysis features.

## Author

**Hadis Gholine Man**

GitHub: [@hadisgolineman](https://github.com/hadisgolineman)

## License

This project is available for educational and learning purposes.
