# Process- child process, Modules, API Enumeration

## Overview

This project is a Windows-based tool written in C++ to enumerate processes, their modules, and child processes, and log the information into a structured JSON file. It leverages Windows APIs like `EnumProcesses`, `EnumProcessModules`, and `CreateToolhelp32Snapshot` to gather detailed process information. 

## Features

- Enumerates all running processes on the system.
- Retrieves the name and modules associated with each process.
- Identifies and logs child processes for each parent process.
- Outputs the gathered data into a JSON file for easy analysis.
- Includes error handling for common issues like privilege errors or missing system APIs.

## Why This Tool?

This tool is designed for system administrators, developers, and cybersecurity professionals who need a detailed overview of system processes for tasks like debugging, monitoring, or security analysis. The JSON output allows for easy integration with other tools or workflows.

## How It Works

1. **Process Enumeration**:
   - The program uses `EnumProcesses` to list all running processes and retrieves their IDs.

2. **Process Details**:
   - For each process, it opens a handle and fetches the process name using `GetModuleBaseName`.
   - The loaded modules for each process are enumerated using `EnumProcessModules`.

3. **Child Process Identification**:
   - Uses `CreateToolhelp32Snapshot` and `Process32First/Process32Next` to find child processes of each parent process.

4. **Logging**:
   - All information is logged into a JSON file named `Process_info.json` in a structured format.

## Example Output

The JSON file generated looks like this:

```json
{
    "Process Logs": [
        {
            "PID": 1234,
            "Name": "example.exe",
            "Modules Loaded by Process": [
                "C:\\Windows\\System32\\example.dll"
            ],
            "Child Process PID": 5678
        },
        {
            "PID": 5678,
            "Name": "child.exe",
            "Modules Loaded by Process": [
                "C:\\Windows\\System32\\childmodule.dll"
            ],
            "Child Process PID": "None"
        }
    ]
}
```

REFERENCE :

## Demonstration

<iframe width="560" height="315" src="https://www.youtube.com/embed/kxjjvpQIr-c" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
