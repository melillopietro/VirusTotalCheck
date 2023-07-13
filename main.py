import requests

# Set your VirusTotal API key
API_KEY = "YOUR_API_KEY"

# Set the URL for the VirusTotal API
SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"

# Function to scan a file with VirusTotal
def scan_file(file_path):
    with open(file_path, "rb") as file:
        files = {"file": file}
        params = {"apikey": API_KEY}
        response = requests.post(SCAN_URL, files=files, params=params)
        return response.json()

# Example usage
file_path = "path/to/your/file.exe"
result = scan_file(file_path)
print(result)
