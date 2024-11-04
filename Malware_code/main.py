import os
import subprocess
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Path to your yara_testing.py script
YARA_SCRIPT_PATH = r'C:\Users\Abishek\Downloads\TIP_module-master\Malware_code\yara_testing.py'

# List of directories to monitor
WATCHED_DIRECTORIES = [
    os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Documents'),
    os.path.expanduser('~/Music'),
    os.path.expanduser('~/Videos')

]

class CustomFileEventHandler(FileSystemEventHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processed_files = set()  # Track processed files

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, file_path):
        if file_path not in self.processed_files:
            print(f"New or modified file detected: {file_path}. Running custom scan.")
            run_yara_test('custom', file_path)
            self.processed_files.add(file_path)

def run_yara_test(mode, file_path=None):
    if mode == 'custom' and file_path:
        command = ['python', YARA_SCRIPT_PATH, mode, '--directory', file_path]
    else:
        command = ['python', YARA_SCRIPT_PATH, mode]
    
    print(f"Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Output: {result.stdout}")
    if result.stderr:
        print(f"Error: {result.stderr}")

def start_monitoring():
    event_handler = CustomFileEventHandler()
    observer = Observer()
    
    # Schedule monitoring for each directory
    for directory in WATCHED_DIRECTORIES:
        observer.schedule(event_handler, path=directory, recursive=True)
        print(f"Monitoring started on {directory}")
    
    observer.start()
    print("Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
