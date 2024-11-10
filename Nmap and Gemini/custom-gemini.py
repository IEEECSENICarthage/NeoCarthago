#!/var/ossec/framework/python/bin/python3
# Modified to use Gemini API
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
try:
    import requests
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = True  # Enable for debugging
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    debug("# File location")
    debug(alert_file_location)
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
    # Request Gemini API info
    msg = request_gemini_info(json_alert, apikey)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(log_file, "a") as f:
            f.write(str(msg))

def request_gemini_info(alert, apikey):
    alert_output = {}
    # If there is no port service present in the alert, exit.
    if not "nmap_port_service" in alert["data"]:
        return 0
    nmap_port_service = alert["data"]["nmap_port_service"]
    # Request info using Gemini API
    data = query_api(nmap_port_service, apikey)
    # Create alert
    alert_output["gemini"] = {}
    alert_output["integration"] = "custom-gemini"
    alert_output["gemini"]["found"] = 1  # Assuming we always get a response
    alert_output["gemini"]["source"] = {}
    alert_output["gemini"]["source"]["alert_id"] = alert["id"]
    alert_output["gemini"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["gemini"]["source"]["description"] = alert["rule"]["description"]
    alert_output["gemini"]["source"]["full_log"] = alert["full_log"]
    alert_output["gemini"]["source"]["nmap_port_service"] = nmap_port_service
    # Info about the port service from Gemini API
    alert_output["gemini"]["nmap_port_service"] = nmap_port_service
    alert_output["gemini"]["analysis"] = data.get('analysis', '')
    debug(alert_output)
    return alert_output

def query_api(nmap_port_service, apikey):
    import requests
    # API Endpoint
    api_url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={apikey}'
    headers = {
        'Content-Type': 'application/json',
    }
    # Request Payload
    json_data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"In 4 or 5 sentences, tell me about this service and if there are past vulnerabilities: {nmap_port_service}"
                    }
                ]
            }
        ]
    }
    # Make the API Request
    response = requests.post(api_url, headers=headers, json=json_data)
    try:
        json_response = response.json()
    except ValueError:
        debug("# Error: Response is not in JSON format.")
        debug(f"# Response Content: {response.text}")
        sys.exit(1)
    debug(f"# API Response: {json.dumps(json_response, indent=2)}")
    # Parse the Response
    if response.status_code == 200:
        candidates = json_response.get('candidates', [])
        if candidates:
            content = candidates[0].get('content', {})
            parts = content.get('parts', [])
            if parts:
                generated_text = parts[0].get('text', '')
            else:
                generated_text = ''
                debug("# Warning: No parts found in the content.")
        else:
            generated_text = ''
            debug("# Warning: No candidates found in the response.")
        data = {
            'nmap_port_service': nmap_port_service,
            'analysis': generated_text
        }
        return data
    else:
        error_message = json_response.get('error', {}).get('message', 'Unknown error')
        error_code = response.status_code
        debug(f"# Error: The API returned an error ({error_code}): {error_message}")
        sys.exit(1)

def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = '1:gemini:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->gemini:{3}'.format(agent["id"], agent["name"], agent.get("ip", "any"), json.dumps(msg))
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Read arguments
        if len(sys.argv) >= 3:
            debug_enabled = True  # Enable debugging
        else:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)
        # Main function
        main(sys.argv)
    except Exception as e:
        debug(str(e))
        raise
