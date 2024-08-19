# Website Analyzer



This project analyzes a list of websites and generates a comprehensive PDF report containing various details about each site, including WHOIS information, DNS records, SSL certificates, and more.

## Features

- Concurrent processing of multiple websites
- Detailed analysis including WHOIS, DNS, SSL, headers, and more
- Integration with Shodan for additional information
- PDF report generation
- JSON output for further processing

## Requirements

- Python 3.7+
- Required Python packages (listed in `requirements.txt`)
- Shodan API key

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/website-analyzer.git
   cd website-analyzer
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Create a `secrets.json` file in the project root directory with your list of websites and Shodan API key:
   ```json
   {
     "websites": [
       "https://example.com",
       "https://another-example.com"
     ],
     "shodan_api_key": "YOUR_SHODAN_API_KEY_HERE"
   }
   ```

## Usage

Run the script:

python research.py

This will generate a `website_report.pdf` file with the analysis results and a `website_info.json` file with the raw data.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
