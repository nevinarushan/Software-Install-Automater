# Automated Software Deployment Tool for Windows

This project provides a robust and automated solution for deploying software on Windows systems. It's designed to streamline the installation process, especially for environments requiring consistent software setups.

## Features

*   **Automated Installation:** Installs a predefined list of software based on a JSON configuration file.
*   **GUI Automation (PyAutoGUI):** Utilizes `pyautogui` to interact with graphical installers (like Chrome, FortiClient VPN, Microsoft Office) by simulating keyboard presses and mouse clicks, enabling automation of non-silent installers.
*   **Dynamic Installation Monitoring:** Intelligently monitors the installation progress by:
    *   Waiting for installer processes to complete.
    *   Checking for the presence of installed software files/executables.
    *   Dynamically waiting for background processes (e.g., `msiexec.exe`) spawned by installers.
*   **Comprehensive Pre-flight Checks:** Performs essential system checks before installation, including:
    *   Operating System verification (Windows only).
    *   Sufficient disk space.
    *   Internet connectivity.
    *   Status of critical Windows services (e.g., MSI Installer, BITS).
    *   Warnings for long file paths and security considerations (UAC, Antivirus).
*   **Integrity Verification:** Supports SHA256 hash verification for installer files to ensure they haven't been corrupted or tampered with.
*   **Pre-install Cleanup:** Allows defining paths to clean up before an installation, removing remnants of previous failed attempts.
*   **Conflict Management:** Checks for conflicting running processes and can stop specified Windows services to prevent installation issues.
*   **Detailed Logging:** All actions, successes, and failures are meticulously logged to a single, consolidated `install_log.txt` file for easy troubleshooting.
*   **Portable Executable:** Packaged into a single executable (`installer.exe`) using PyInstaller, making it easy to distribute and run on target Windows machines without requiring Python installation.

## Project Structure

*   `installer.py`: The main script that orchestrates the entire installation process. It reads the configuration, performs checks, and calls other scripts or executes installers directly.
*   `scripts/`: Directory containing specialized Python scripts for GUI automation.
    *   `chrome_installer.py`: Automates the installation of Google Chrome.
    *   `forticlient_installer.py`: Automates the installation of FortiClient VPN.
    *   `office_installer.py`: Automates the installation of Microsoft Office.
*   `software_config.json`: The JSON configuration file that defines all the software to be installed and their specific parameters.
*   `installer.spec`: The PyInstaller specification file used to build the executable.
*   `Softwares/`: This directory (expected to be alongside the `installer.exe`) contains all the actual software installer files (e.g., `.exe`, `.msi`).
*   `logs/`: This directory (created alongside the `installer.exe`) stores the `install_log.txt` file, which records the entire installation process.

## Prerequisites

*   **Target System:** Windows Operating System (Windows 10/11 recommended).
*   **Python (for Development/Building only):** Python 3.x and `pip` are required on the machine used to build the executable. Not required on the target deployment machine.

## How to Use (Deployment)

1.  **Obtain the Executable:** Get the `installer.exe` file (found in the `dist` folder after building).
2.  **Prepare the `Softwares` Folder:** Ensure you have a `Softwares` folder containing all your installer files (e.g., `ChromeSetup.exe`, `FortiClientVPNInstaller.exe`, `OfficeSetup.exe`, etc.).
3.  **Place Files Together:** Copy both the `installer.exe` and the `Softwares` folder into the *same directory* on the target Windows machine.
    ```
    C:\DeploymentFolder\
    ├───installer.exe
    ├───Softwares/
    │   ├───ChromeSetup.exe
    │   ├───FortiClientVPNInstaller.exe
    │   └───... (other software installers)
    └───... (other files)
    ```
4.  **Run as Administrator:** Right-click on `installer.exe` and select "Run as administrator" to ensure it has the necessary permissions to install software.
5.  **Monitor Progress:** The script will open a console window to display real-time logs. A detailed `install_log.txt` will be generated in the `logs` subdirectory (created next to the `installer.exe`).

## Configuration (`software_config.json`)

The `software_config.json` file is a JSON array where each object represents a software to be installed.

**Important:** All backslashes in file paths within this JSON must be **escaped** (e.g., `C:\Program Files\` instead of `C:\Program Files\`).

Here are the common properties for each software object:

*   `name` (string, required): The display name of the software.
*   `check_path` (string, optional): An absolute path to a file or directory that, if it exists, indicates the software is already installed. If omitted, the installation will always proceed.
*   `installer` (string, required): The filename of the installer executable (e.g., `ChromeSetup.exe`). This file must be present in the `Softwares` directory.
*   `expected_hash` (string, optional): The SHA256 hash of the installer file. If provided, the script will verify the installer's integrity before running it. Leave empty (`""`) to skip hash verification.
*   `args_list` (array of arrays, optional): A list of argument sets to try for silent installation. The script will attempt each set until one succeeds.
    *   Example: `[["/s", "/qn"], ["/quiet", "/norestart"]]`
    *   Placeholders like `{SOFTWARE_DIR}` and `{RUNTIME_PATH}` can be used and will be replaced at runtime.
*   `cleanup_paths` (array of strings, optional): A list of absolute file or directory paths to delete before attempting the installation. Useful for cleaning up remnants of previous failed installations.
*   `native_log_paths` (array of strings, optional): A list of absolute paths to native installer log files or directories. The script will attempt to read these logs and embed their content into the main `install_log.txt` for better diagnostics. Environment variables like `%TEMP%` are supported.
*   `process_name_to_watch` (string, optional): The name of a background process executable (e.g., `msiexec.exe`, `Sophos Endpoint Installer.exe`) that the script should wait for to start and then finish. Useful for installers that launch a background process and exit quickly.
*   `process_timeout` (integer, optional): The maximum time in seconds to wait for the `process_name_to_watch` to finish. Defaults to 900 seconds (15 minutes).
*   `processes_to_check` (array of strings, optional): A list of process executable names to check for conflicts before installation. A warning will be logged if any are found running.
*   `services_to_stop` (array of strings, optional): A list of Windows service names to attempt to stop before installation. Useful for preventing conflicts with services.
*   `requires_reboot` (boolean, optional): Set to `true` if the software requires a system reboot to function correctly after installation. Defaults to `false`.

**Example `software_config.json` Entry:**

```json
[
  {
    "name": "Google Chrome",
    "check_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "installer": "ChromeSetup.exe",
    "expected_hash": "YOUR_CHROME_INSTALLER_SHA256_HASH_HERE"
  },
  {
    "name": "SAP GUI 8.0",
    "check_path": "C:\\Program Files (x86)\\SAP\\FrontEnd\\SAPgui",
    "installer": "SCCC_SAPGUI_8.0_20230823_1623.exe",
    "expected_hash": "",
    "args_list": [
      ["/Silent", "/Product=SAPGUI800", "/Package=SAPGUIPackage"]
    ],
    "native_log_paths": ["%PROGRAMFILES%\\SAP\\SAPSetup\\Setup\\LOGs"]
  },
  {
    "name": "Sophos",
    "check_path": "C:\\Program Files\\Sophos\\Sophos UI",
    "installer": "SophosSetup.exe",
    "expected_hash": "",
    "cleanup_paths": [
      "C:\\ProgramData\\Sophos",
      "C:\\Program Files\\Sophos"
    ],
    "args_list": [
      ["--quiet", "--competitorremoval=enabled"],
      ["--force", "--competitorremoval=enabled"]
    ],
    "native_log_paths": [
      "C:\\ProgramData\\Sophos\\AutoUpdate\\Logs\\SophosUpdate.log",
      "C:\\ProgramData\\Sophos\\Endpoint Defense\\Logs",
      "C:\\ProgramData\\Sophos\\Management Communications System\\Logs"
    ],
    "process_name_to_watch": "Sophos Endpoint Installer.exe",
    "services_to_stop": ["Sophos AutoUpdate Service"],
    "requires_reboot": true
  }
]
```

## Building the Executable

To build the `installer.exe` from the source code:

1.  **Install PyInstaller:**
    ```bash
    pip install pyinstaller
    ```
2.  **Navigate to Project Root:** Open your terminal or command prompt and navigate to the root directory of this project (where `installer.spec` is located).
3.  **Run PyInstaller:**
    ```bash
    pyinstaller installer.spec
    ```
    This command uses the `installer.spec` file, which defines how the project should be bundled. It will create a `dist` folder containing the `installer.exe` and its dependencies. The `Softwares` folder is intentionally *not* bundled and must be placed alongside the executable manually.

## Dependencies (Python Libraries)

The project uses the following Python libraries:

*   `pyautogui`: For GUI automation (simulating mouse/keyboard input).
*   `psutil`: For system and process information (checking running processes, service status, disk space).
*   `pathlib`: For object-oriented filesystem paths.
*   `logging`: For robust logging.
*   `json`: For parsing the configuration file.
*   `subprocess`: For running external commands and installers.
*   `hashlib`: For calculating file hashes.
*   `socket`: For internet connectivity checks.
*   `platform`, `os`, `sys`, `ctypes`, `time`, `shutil`, `datetime`: Standard Python libraries for various system interactions.

## License

This project is licensed under the MIT License.
