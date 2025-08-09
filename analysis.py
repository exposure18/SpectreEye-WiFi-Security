# analysis.py

def analyze_network(network):
    """
    Input: network dict with keys "Auth" and "Encryption"
    Returns: (severity_str, suggestion_str)
    Severity: "Low", "Medium", "High"
    """
    auth = (network.get("Auth") or "").lower()
    enc  = (network.get("Encryption") or "").lower()
    ssid = (network.get("SSID") or "")

    # defaults
    severity = "Low"
    suggestion = "No major issues detected. Maintain strong passphrase and firmware."

    # Open / no encryption
    if "open" in auth or enc in ("none", "open", ""):
        severity = "High"
        suggestion = ("Network is open (no encryption). "
                      "Enable WPA2/WPA3 with a strong passphrase immediately.")
        return severity, suggestion

    # WEP
    if "wep" in enc:
        severity = "High"
        suggestion = ("WEP is insecure and can be cracked easily. "
                      "Upgrade AP to WPA2/WPA3 (AES) and set a strong passphrase.")
        return severity, suggestion

    # TKIP (often WPA-TKIP)
    if "tkip" in enc:
        severity = "Medium"
        suggestion = ("TKIP is outdated. Switch encryption to AES (WPA2-AES) or WPA3 if supported.")
        return severity, suggestion

    # WPA2-AES or WPA3
    if "wpa2" in auth or "wpa3" in auth or "aes" in enc:
        severity = "Low"
        suggestion = "Good: WPA2-AES/WPA3 detected. Use a strong random passphrase and update firmware."

    # weak SSID heuristic (default vendor names)
    default_ssids = ["linksys", "netgear", "tplink", "dlink", "default", "home", "xfinity"]
    if any(ds in ssid.lower() for ds in default_ssids):
        severity = "Medium" if severity == "Low" else severity
        suggestion += " Avoid default SSID names; change SSID to something unique to reduce information leakage."

    return severity, suggestion
