# scanner.py
import subprocess
import re
from datetime import datetime

def scan_networks():
    """
    Run `netsh wlan show networks mode=bssid` and parse the output.
    Returns a list of dicts: {SSID, BSSID, Auth, Encryption, Signal, Channel}
    """
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True, encoding="utf-8", errors="ignore"
        )
    except Exception as e:
        # Return empty on error — GUI should show message
        return {"error": str(e), "networks": []}

    networks = []
    # Split by SSID blocks: keep the leading "SSID 1 : name" separated
    blocks = re.split(r"\r?\nSSID \d+ \: ", out)
    for block in blocks[1:]:
        lines = block.splitlines()
        ssid_line = lines[0].strip()
        ssid = ssid_line

        # defaults
        bssid = ""
        auth = ""
        enc = ""
        signal = ""
        channel = ""

        # parse known fields
        for line in lines[1:]:
            line = line.strip()
            m_bssid = re.match(r"BSSID \d+ \: (.+)", line)
            m_auth = re.match(r"Authentication\s+\:\s+(.+)", line)
            m_enc  = re.match(r"Encryption\s+\:\s+(.+)", line)
            m_signal = re.match(r"Signal\s+\:\s+(\d+)%", line)
            m_channel = re.match(r"Channel\s+\:\s+(\d+)", line)

            if m_bssid and not bssid:
                bssid = m_bssid.group(1).strip()
            if m_auth and not auth:
                auth = m_auth.group(1).strip()
            if m_enc and not enc:
                enc = m_enc.group(1).strip()
            if m_signal and not signal:
                signal = m_signal.group(1).strip()
            if m_channel and not channel:
                channel = m_channel.group(1).strip()

        networks.append({
            "SSID": ssid,
            "BSSID": bssid,
            "Auth": auth,
            "Encryption": enc,
            "Signal": signal,
            "Channel": channel,
            "first_seen": datetime.now().isoformat(timespec='seconds')
        })

    return {"error": None, "networks": networks}

def demo_data():
    """Return safe demo networks for recruiters/testers."""
    return {
        "error": None,
        "networks": [
            {"SSID":"CoffeeShop_FreeWiFi","BSSID":"AA:BB:CC:DD:EE:01","Auth":"Open","Encryption":"None","Signal":"78","Channel":"6","first_seen": datetime.now().isoformat(timespec='seconds')},
            {"SSID":"HomeRouter_123","BSSID":"AA:BB:CC:DD:EE:02","Auth":"WPA2-Personal","Encryption":"AES","Signal":"62","Channel":"11","first_seen": datetime.now().isoformat(timespec='seconds')},
            {"SSID":"OldRouter_WEP","BSSID":"AA:BB:CC:DD:EE:03","Auth":"Open","Encryption":"WEP","Signal":"41","Channel":"1","first_seen": datetime.now().isoformat(timespec='seconds')},
            {"SSID":"WPS_Vuln_AP","BSSID":"AA:BB:CC:DD:EE:04","Auth":"WPA2-Personal","Encryption":"TKIP","Signal":"35","Channel":"9","first_seen": datetime.now().isoformat(timespec='seconds')}
        ]
    }
