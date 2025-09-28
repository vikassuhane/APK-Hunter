import os
import re
import argparse
import math
import subprocess
import sys
import tempfile
import requests
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'rich'])
    from rich.console import Console
    from rich.table import Table

console = Console()

ENTROPY_THRESHOLD = 4.5
TEXT_EXTENSIONS = ('.xml', '.json', '.txt', '.ini', '.js', '.cfg', '.env')

STRICT_KEY_PATTERNS = {
    "Google Maps API Key": rb"AIza[0-9A-Za-z\-_]{33,40}",
    "Firebase Server Key": rb"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Stripe Live Secret": rb"sk_live_[0-9a-zA-Z]{24}",
    "Mailgun API Key": rb"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key": rb"SG\.[a-zA-Z0-9._-]{22}\.[a-zA-Z0-9._-]{43}",
    "Twilio Account SID": rb"AC[a-z0-9]{32}",
    "Slack Webhook": rb"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+",
    "S3 Bucket URL": rb"s3://[a-zA-Z0-9._-]+/[a-zA-Z0-9._/-]*",
    "Firebase Dashboard URL": rb"https://[a-z0-9_.-]+\.firebaseio\.com",
    "Internal IP Address": rb"\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))(\.\d{1,3}){2}\b",
    "Email Address": rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Base64 Encoded Secret": rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "Private RSA Key": rb"-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\n\r]+-----END RSA PRIVATE KEY-----",
    "JWT Token": rb"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Generic Bearer Token": rb"(?i)bearer\s+[A-Za-z0-9\-_.=]+",
    "Backup Flag (true/false)": rb"android:allowBackup=\"(true|false)\"",
    "Debuggable Flag (true/false)": rb"android:debuggable=\"(true|false)\"",
    "Exported Activity": rb"<activity[^>]+android:name=\"([^\"]+)\"[^>]+exported=\"(true|false)\"",
    "Exported Service": rb"<service[^>]+android:name=\"([^\"]+)\"[^>]+exported=\"(true|false)\"",
    "Exported Receiver": rb"<receiver[^>]+android:name=\"([^\"]+)\"[^>]+exported=\"(true|false)\""
}

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def check_google_maps_key(key: str) -> str:
    try:
        response = requests.get(
            "https://maps.googleapis.com/maps/api/geocode/json",
            params={"address": "New York", "key": key},
            timeout=5
        )
        if response.status_code == 200:
            return f"✅ Vulnerable | https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key={key}"
        elif response.status_code == 403:
            return "🔒 Restricted"
        else:
            return f"❓ Unknown ({response.status_code})"
    except Exception as e:
        return f"❌ Error ({e})"

def extract_matches(data: bytes, filename: str, label_match_tracker):
    results = []
    for label, pattern in STRICT_KEY_PATTERNS.items():
        matches = re.findall(pattern, data)
        if not matches and label not in label_match_tracker:
            label_match_tracker[label] = (label, filename, "Not Found", "❌")
        for match in matches:
            if isinstance(match, tuple):
                match = " ".join(m.decode(errors="ignore") if isinstance(m, bytes) else str(m) for m in match)
            else:
                match = match.decode(errors="ignore") if isinstance(match, bytes) else str(match)
            entropy = shannon_entropy(match)
            if entropy > ENTROPY_THRESHOLD or label.startswith("Backup Flag") or label.startswith("Debuggable") or label.startswith("Exported"):
                exploitable = check_google_maps_key(match) if label == "Google Maps API Key" else "-"
                label_match_tracker[label] = (label, filename, match, exploitable)
    return results

def analyze_decompiled_folder(folder_path: str):
    findings = []
    label_match_tracker = {}
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if not file_path.endswith(TEXT_EXTENSIONS):
                continue
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    extract_matches(data, file_path, label_match_tracker)
            except:
                continue
    findings = list(label_match_tracker.values())
    return findings

def decompile_apk(apk_path: str) -> str:
    temp_dir = tempfile.mkdtemp()
    try:
        console.print(f"[blue]📦 Decompiling APK using apktool...[/blue]")
        subprocess.check_call(["apktool", "d", apk_path, "-o", temp_dir, "-f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return temp_dir
    except Exception as e:
        console.print(f"[red]❌ Failed to decompile APK: {e}[/red]")
        sys.exit(1)

def print_results(findings):
    table = Table(title="Scan Results", show_lines=True)
    table.add_column("Pattern")
    table.add_column("File")
    table.add_column("Value")
    table.add_column("Exploitable")
    for label, file, value, exploitable in findings:
        table.add_row(label, file, value, exploitable)
    console.print(table)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Strict API Key, Credential, and Manifest Security Flag Scanner")
    parser.add_argument("path", help="Path to APK or decompiled folder")
    args = parser.parse_args()

    console.print(f"📦 [bold]Scanning:[/bold] {args.path}\n")
    if os.path.isdir(args.path):
        folder_to_scan = args.path
    elif args.path.endswith(".apk"):
        folder_to_scan = decompile_apk(args.path)
    else:
        console.print("[red]❌ Invalid path: Provide a .apk file or decompiled folder path.[/red]")
        sys.exit(1)

    results = analyze_decompiled_folder(folder_to_scan)
    if results:
        print_results(results)
    else:
        console.print("✅ [bold green]No high-confidence secrets, credentials, or risky configurations found.[/bold green]")
