# Musashi  

Musashi is a Python 3 tool designed for rapid triage of logs using SIGMA rules. It supports various log formats, including Azure, Defender, Cortex, CarbonBlack, and more. Musashi also extracts Indicators of Compromise (IOCs) to assist in quick threat detection and incident response.

below is sample demo of EDR logs from Defender Musashi demonstrates the use case of EDR logs from Defender detecting Lumma Stealer through a fake CAPTCHA.

## Demo: Detecting Lumma Stealer
Below is a sample demo showcasing Musashi analyzing EDR logs from Defender, successfully detecting Lumma Stealer delivered via a fake CAPTCHA attack.
[![asciicast](https://asciinema.org/a/JjkU9hEM6xW40SqCgWuTi8YAb.svg)](https://asciinema.org/a/JjkU9hEM6xW40SqCgWuTi8YAb)

## Why Use Musashi?
When responding to security incidents, time is critical. Instead of manually querying an endpoint for suspicious activity, you can quickly dump endpoint logs (such as EDR logs) and use Musashi to efficiently analyze them for threat detection and IOC extraction—helping you identify potential threats in seconds.

1. Extract logs from the endpoint’s EDR solution (e.g., Defender, CarbonBlack, Cortex).
2. Run Musashi on the logs to apply SIGMA rules and detect potential threats.
3. Extract IOCs (IPs, domains, hashes) for further investigation.
4. Quickly determine if the endpoint is compromised—without manually searching through logs.

## What Musashi Does:
- Rapid Log Triage – Quickly process logs for threat detection
- SIGMA Rule Matching – Identify malicious activity based on SIGMA queries
- IOC Extraction – Extract IPs, domains, file hashes, and other indicators
- Log Slicing – Splits logs into SIGMA query results and extracted IOCs for easy analysis

## Installation  

1. Clone the repository:  
   ```bash
   git clone https://github.com/aj-tap/musashi
   cd musashi
   ```  

2. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```  

## Usage  

### Running Musashi  
```bash
python musashi.py -i /path/to/logs -o /path/to/output -lf defender
```  

Arguments
-i, --input_path → (Required) Path to the log directory
-o, --output_path → (Required) Path to the output directory for results
-lf, --log_format → (Required) Log format (e.g., azure, defender, cortex, carbonblack)

### Output
After execution, Musashi provides:
- Detected threats based on SIGMA rules
- Extracted IOCs (IPs, domains, file hashes)

## Contributing
Contributions are welcome! Open an issue or submit a pull request.


## License
Musashi is licensed under the GNU General Public License v3.0 (GPL-3.0).
