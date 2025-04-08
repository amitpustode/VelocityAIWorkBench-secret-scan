import os
import argparse
import zipfile
from datetime import datetime

def detect_secrets_scan(repo_path):
    print(f"\n[+] Starting detect-secrets scan for {repo_path}")

    if not os.path.isdir(repo_path):
        print(f"[-] Error: Directory '{repo_path}' does not exist.")
        return

    os.chdir(repo_path)

    try:
        os.system("detect-secrets scan > .secrets.baseline")
        print("[*] Successfully ran detect-secrets scan")

        repo_name = os.path.basename(os.path.abspath(repo_path.rstrip('/')))
        result_file = os.path.abspath(os.path.join("..", f"{repo_name}-detect-secrets-result.txt"))

        audit_command = f"yes y | detect-secrets audit .secrets.baseline | tee {result_file}"
        os.system(audit_command)

        print(f"[+] Audit saved to {result_file}")
    except Exception as e:
        print(f"[-] detect-secrets error: {e}")
    finally:
        os.chdir("..")


def trivy_scan(repo_path):
    print(f"\n[+] Starting Trivy scan for {repo_path}")

    if not os.path.isdir(repo_path):
        print(f"[-] Error: Directory '{repo_path}' does not exist.")
        return

    repo_name = os.path.basename(os.path.abspath(repo_path.rstrip('/')))
    output_file = f"{repo_name}-trivy.json"

    try:
        cmd = f"trivy fs {repo_path} --format json --output {output_file}"
        os.system(cmd)
        print(f"[+] Trivy scan completed. Output saved to {output_file}")
    except Exception as e:
        print(f"[-] Trivy scan error: {e}")


def semgrep_scan(repo_path):
    print(f"\n[+] Starting Semgrep SAST scan for {repo_path}")

    if not os.path.isdir(repo_path):
        print(f"[-] Error: Directory '{repo_path}' does not exist.")
        return

    repo_name = os.path.basename(os.path.abspath(repo_path.rstrip('/')))
    output_file = f"{repo_name}-semgrep.json"

    try:
        cmd = f"semgrep scan {repo_path} --json > {output_file}"
        os.system(cmd)
        print(f"[+] Semgrep scan completed. Output saved to {output_file}")
    except Exception as e:
        print(f"[-] Semgrep scan error: {e}")


def zip_scan_results(repo_path):
    print("\n[+] Zipping all scan result files...")

    repo_name = os.path.basename(os.path.abspath(repo_path.rstrip('/')))
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_filename = f"{repo_name}-scan-results-{timestamp}.zip"

    result_files = [
        f"{repo_name}-trivy.json",
        f"{repo_name}-semgrep.json",
        f"{repo_name}-detect-secrets-result.txt"
    ]

    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for file in result_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"[+] Added to zip: {file}")
            else:
                print(f"[-] Not found, skipping: {file}")

    print(f"[+] Results zipped into {zip_filename}")


def main():
    parser = argparse.ArgumentParser(description="Run detect-secrets, Trivy and Semgrep on cloned repo")
    parser.add_argument("--path", "-p", required=True, help="Path to the cloned repository")
    parser.add_argument("--mode", "-m", help="Scan mode: all, trivy, secrets, semgrep", default="all")
    args = parser.parse_args()

    repo_path = args.path.strip()
    mode = args.mode.strip().lower()

    if mode == "trivy":
        trivy_scan(repo_path)
    elif mode == "secrets":
        detect_secrets_scan(repo_path)
    elif mode == "semgrep":
        semgrep_scan(repo_path)
    else:
        trivy_scan(repo_path)
        detect_secrets_scan(repo_path)
        semgrep_scan(repo_path)

    # Zip only if full scan was run
    if mode == "all":
        zip_scan_results(repo_path)


if __name__ == "__main__":
    main()
