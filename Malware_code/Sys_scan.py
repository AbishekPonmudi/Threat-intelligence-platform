import argparse
import hashlib
import os
import sys
import logging
import time
import yara
import pefile
from win32comext.shell import shell
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
logging.basicConfig(filename='scan_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Use a ThreadPoolExecutor for parallel processing
THREAD_COUNT = 8

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="File Scanner")
    parser.add_argument("scan_type", choices=["normal", "full", "custom"], help="--> Mention the specific Mode")
    parser.add_argument("--directory", help="Please! Declare --directory and <Folder path>")
    args = parser.parse_args()

    # Elevate to admin if not already elevated and scan type is not custom
    if args.scan_type != "custom" and sys.argv[-1] != "Isadmin":
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:] + ["Isadmin"])
        shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
        
    # Start timing the scan
    start_time = time.time()
    logging.info(f"Starting {args.scan_type} scan")

    # Load YARA rules
    rules_path = r"hash_rules\Rules_yara.yar"
    try:
        rules = yara.compile(filepath=rules_path)
    except yara.SyntaxError as e:
        logging.error(f"Rules syntax error: {e}")
        exit(1)

    # Load malicious hashes
    malicious_hashes = load_malicious_hashes()

    # Define root directories to scan
    root_dirs = [args.directory] if args.scan_type == "custom" and args.directory else ['C:\\'] if os.name == 'nt' else ['/']

    # Scan directories and gather file paths
    file_paths = []
    for root in root_dirs:
        file_paths.extend(scan_directory(root))
    total_files = len(file_paths)

    # Scan files in parallel
    malicious_files = []
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        futures = {executor.submit(scan_file, file_path, rules, malicious_hashes): file_path for file_path in file_paths}
        with tqdm(total=total_files, desc="Scanning Files", unit="file") as pbar:
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    results = future.result()
                    if results:
                        malicious_files.extend(results)
                except Exception as e:
                    logging.error(f"Error scanning file {file_path}: {e}")
                pbar.update(1)

    # Calculate the elapsed time
    elapsed_time = time.time() - start_time
    elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    logging.info(f"Scanning complete. {len(malicious_files)} malicious files detected.")
    logging.info(f"Scanning Time: {elapsed_time_str}")
    logging.info(f"Completed {args.scan_type} scan on : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    logging.info(f"Elapsed Time: {elapsed_time_str}")
    logging.info(f"Scanned Mode: {args.scan_type}")
    
    if malicious_files:
        logging.info("\nMalicious file paths:")
        for result in malicious_files:
            logging.info(result)

    print(f"\nScanning complete. {len(malicious_files)} malicious files detected.")
    print(f"Current Scanning Time: {elapsed_time_str}")
    print(f"Completed {args.scan_type} on : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    print(f"Scanned Mode: {args.scan_type}")
    if malicious_files:
        print("\nMalicious file paths:")
        for result in malicious_files:
            print(result)

def load_malicious_hashes(file_path=r"hashes\full_sha256.txt"):
    malicious_hashes = set()
    try:
        with open(file_path, mode='r') as f:
            for line in f:
                hash_value = line.split('|')[0].strip()
                if hash_value:
                    malicious_hashes.add(hash_value)
    except FileNotFoundError:
        logging.error(f"Database not found in this location {file_path}, Please ensure the file exists.")
    return malicious_hashes

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        logging.warning(f"Skipping the System files : {file_path}: {e}")
        return None

def scan_with_yara(file_path, rules):
    try:
        matches = rules.match(file_path)
        return matches
    except yara.Error as e:
        logging.error(f"System File Error code 2 {file_path}: {e}")
        return None

def analyze_with_pefile(file_path):
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                return "Packed_Malware_Generic"
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            suspicious_imports = {'LoadLibraryA', 'GetProcAddress', 'VirtualAlloc', 'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                                  'CreateProcess','GetCurrentProcess','GetCurrentProcessId','Subprocess','ReadProcessMemory','WriteProcessMemory','RegCreateKeyEx',
                                  'RegSetValueEx','NtQueueApcThread','SuspendThread','ResumeThread'}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
                        return f"Suspicious API: {imp.name.decode('utf-8', 'ignore')}"
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip()
            if section_name not in {'.text', '.data', '.rdata'}:
                return "Obfuscated_Malware_Generic"
        return None
    except pefile.PEFormatError:
        return None
    except PermissionError:
        logging.warning(f"Permission denied: {file_path}")
        return None
    except Exception as e:
        logging.error(f"System Files >>  {file_path}: {e}")
        return None

def scan_file(file_path, rules, malicious_hashes):
    results = []
    file_hash = calculate_hash(file_path)
    if file_hash and file_hash in malicious_hashes:
        results.append(f"File : {file_path} - {file_hash}")
    yara_matches = scan_with_yara(file_path, rules)
    if yara_matches:
        for match in yara_matches:
            results.append(f"File : {file_path} - {match}")
    pefile_analysis = analyze_with_pefile(file_path)
    if pefile_analysis:
        results.append(f"File : {file_path} - {pefile_analysis}")
    return results  

def scan_directory(root):
    file_paths = []
    try:
        with os.scandir(root) as it:
            for entry in it:
                if entry.is_file():
                    file_paths.append(entry.path)
                elif entry.is_dir():
                    file_paths.extend(scan_directory(entry.path))
    except PermissionError:
        logging.warning(f"Permission denied: {root}")
    except Exception as e:
        logging.error(f"Error accessing directory {root}: {e}")
    return file_paths

if __name__ == "__main__":
    main()
