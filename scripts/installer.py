import os
import subprocess
import ctypes
import time
import shutil
from pathlib import Path
from datetime import datetime
import sys
import logging
import platform
import psutil
import json
import socket
import hashlib

# --- Global Constants and Paths ---

if getattr(sys, 'frozen', False):
    # Running as a bundled executable
    RUNTIME_PATH = Path(sys.executable).parent
    BUNDLE_PATH = Path(sys._MEIPASS)
    CONFIG_FILE = BUNDLE_PATH / "software_config.json"
    # When bundled, scripts are in the root of the temporary directory
    CHROME_INSTALLER_SCRIPT = BUNDLE_PATH / "scripts" / "chrome_installer.py"
    OFFICE_INSTALLER_SCRIPT = BUNDLE_PATH / "scripts" / "office_installer.py"
    FORTICLIENT_INSTALLER_SCRIPT = BUNDLE_PATH / "scripts" / "forticlient_installer.py"
else:
    # Running as a standard Python script
    RUNTIME_PATH = Path(__file__).parent.parent # Go up one level from /scripts
    CONFIG_FILE = RUNTIME_PATH / "software_config.json"
    CHROME_INSTALLER_SCRIPT = RUNTIME_PATH / "scripts" / "chrome_installer.py"
    OFFICE_INSTALLER_SCRIPT = RUNTIME_PATH / "scripts" / "office_installer.py"

# --- Path Definitions ---
SOFTWARE_DIR = RUNTIME_PATH / "Softwares"
LOG_DIR = RUNTIME_PATH / "logs"
LOG_DIR.mkdir(exist_ok=True) # Ensure the log directory exists
LOG_PATH = LOG_DIR / "install_log.txt"

# EXTRACTION_PATH is kept for compatibility with the rest of the script, pointing to the runtime path.
EXTRACTION_PATH = RUNTIME_PATH

OFFICE_CONFIG_XML_CONTENT = """<Configuration>
  <Add OfficeClientEdition="64" Channel="Current">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us" />
    </Product>
  </Add>
  <Updates Enabled="TRUE" Channel="Current" />
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
</Configuration>"""

def is_internet_available(hosts=[("8.8.8.8", 53), ("1.1.1.1", 53)], timeout=10):
    """
    Checks if an internet connection is available by trying to connect to a list of reliable hosts.
    """
    for host, port in hosts:
        try:
            logger.debug(f"Attempting to connect to {host}:{port} with a {timeout} second timeout...")
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            logger.debug(f"Successfully connected to {host}:{port}.")
            return True
        except socket.error as ex:
            logger.warning(f"Connection attempt to {host}:{port} failed: {ex}")
    return False

# --- Comprehensive Logging Setup ---
# This section configures the logging system to output to both a file and the console.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set the lowest level to capture all messages

# Clear any previous log file to ensure a clean slate for the current run
if LOG_PATH.exists():
    LOG_PATH.unlink()

# Create a file handler to write detailed DEBUG messages to install_log.txt
file_handler = logging.FileHandler(LOG_PATH, mode='w')
file_handler.setLevel(logging.DEBUG)

# Create a stream handler to show INFO messages and higher on the console
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)

# Define a consistent format for all log messages
formatter = logging.Formatter('%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add both handlers to the main logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# --- System Information and Pre-flight Checks ---

def log_system_info():
    """
    Logs a minimal header to indicate the start of the process.
    Detailed system information has been removed to reduce log verbosity.
    """
    logger.debug("="*20 + " System Information " + "="*20)
    # Detailed logging removed as per user request.
    logger.debug("="*58)

def log_processes(moment):
    """
    Logs a list of all running processes at a specific moment (e.g., pre-install).
    This helps diagnose conflicts where an existing process might block an installation.

    Args:
        moment (str): A description of when the snapshot is taken (e.g., "pre-install").
    """
    logger.debug(f"--- Process List Snapshot ({moment}) ---")
    # Detailed process logging removed to reduce verbosity.
    logger.debug("--- End Process List ---")

def check_windows_service(service_name):
    """
    Checks if a critical Windows service is disabled. If it's stopped, it attempts
    to start it. This prevents installers from hanging on disabled services.

    Args:
        service_name (str): The system name of the service (e.g., 'msiserver').

    Returns:
        bool: True if the service is not disabled, False otherwise.
    """
    try:
        service = psutil.win_service_get(service_name)
        service_info = service.as_dict()
        logger.debug(f"Checking service '{service_name}': Status is '{service_info['status']}', Start type is '{service_info['start_type']}'.")
        if service_info['start_type'] == 'disabled':
            logger.critical(f"CRITICAL: Service '{service_name}' is disabled. Many installers will fail. Please enable it and retry.")
            return False
        if service_info['status'] == 'stopped':
            logger.debug(f"Service '{service_name}' is stopped. Attempting to start it...")
            try:
                subprocess.run(["sc", "start", service_name], check=True, capture_output=True)
                time.sleep(2) # Give the service time to start
                service = psutil.win_service_get(service_name)
                if service.status() == 'running':
                    logger.debug(f"Service '{service_name}' started successfully.")
                else:
                    logger.warning(f"Failed to start service '{service_name}'. Current status: '{service.status()}'.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to start service '{service_name}' using sc.exe: {e.stderr}")
    except psutil.NoSuchProcess:
        logger.warning(f"Service '{service_name}' not found.")
    except Exception as e:
        logger.error(f"An error occurred while checking service '{service_name}': {e}", exc_info=True)
    return True

def run_pre_flight_checks():
    """
    Executes a series of checks for common environmental issues that could cause
    installations to fail. This includes OS, disk space, internet,
    and critical services.

    Returns:
        bool: True if all checks pass, False if a critical issue is found.
    """
    logger.debug("--- Running Pre-flight System Checks ---")
    checks_passed = True

    # 1. Verify OS is Windows
    if platform.system() != "Windows":
        logger.critical(f"Unsupported OS: This script is designed for Windows, but found {platform.system()}.")
        checks_passed = False

    # 2. Check for sufficient disk space
    try:
        required_space_gb = 15
        required_space_bytes = required_space_gb * (1024**3)
        system_drive = Path(os.environ.get("SystemDrive", "C:"))
        disk_usage = psutil.disk_usage(str(system_drive))
        free_space_gb = disk_usage.free / (1024**3)
        logger.debug(f"Checking disk space on '{system_drive}': {free_space_gb:.2f} GB free.")
        if disk_usage.free < required_space_bytes:
            logger.critical(f"Insufficient Disk Space: Requires at least {required_space_gb} GB, but only {free_space_gb:.2f} GB is available.")
            checks_passed = False
    except Exception as e:
        logger.error(f"Could not check disk space: {e}", exc_info=True)
        checks_passed = False

    # 3. Check for an active internet connection
    try:
        logger.debug("Checking for internet connectivity...")
        socket.create_connection(("www.google.com", 80), timeout=5)
        logger.debug("Internet connection verified.")
    except OSError:
        logger.warning("No internet connection. Web-based installers (e.g., Chrome, Sophos) will likely fail.")

    # 4. Check critical Windows services needed by installers
    logger.debug("--- Checking status of critical Windows services ---")
    if not check_windows_service('msiserver'):
        checks_passed = False
    if not check_windows_service('BITS'):
        checks_passed = False

    # 5. Check for long path issues
    if len(str(RUNTIME_PATH)) > 100:
        logger.warning(f"The base path '{RUNTIME_PATH}' is very long. This may cause issues with installers that do not support paths over 260 characters. Consider moving the project to a shallower directory (e.g., C:\\Deploy).")

    # 6. Log warnings for manual security checks
    logger.warning("IMPORTANT: For Sophos or other AV installations, ensure Tamper Protection is DISABLED in the central dashboard before running.")
    logger.warning("IMPORTANT: Ensure this script is run from a trusted location or whitelisted in any existing security software to prevent it from being blocked.")
    logger.warning(f"IMPORTANT: This script extracts files to a temporary directory in %LOCALAPPDATA% ({Path(os.getenv('LOCALAPPDATA')) / 'AutomateSoftwares'}). Some security policies may block execution from this location. Please ensure the path is trusted.")

    if checks_passed:
        logger.info("--- Pre-flight System Checks Passed ---")
    else:
        logger.critical("--- Pre-flight System Checks Failed. Aborting installation. ---")

    return checks_passed


def verify_file_hash(filepath, expected_hash):
    """
    Verifies the SHA256 hash of a file to ensure its integrity.

    Args:
        filepath (Path): The path to the file to check.
        expected_hash (str): The expected SHA256 hash string.

    Returns:
        bool: True if the hash matches, False otherwise.
    """
    if not expected_hash:
        logger.warning(f"No hash provided for {filepath.name}. Cannot verify integrity.")
        return True # Skip check if no hash is defined

    logger.info(f"Verifying SHA256 hash for {filepath.name}...")
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            # Read the file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()

        if actual_hash.lower() == expected_hash.lower():
            logger.info(f"Hash verification successful for {filepath.name}.")
            return True
        else:
            logger.critical(f"HASH MISMATCH for {filepath.name}! Expected: {expected_hash}, Got: {actual_hash}")
            return False
    except Exception as e:
        logger.error(f"Could not calculate hash for {filepath.name}. Reason: {e}", exc_info=True)
        return False

# --- Core Utility Functions ---

def is_admin():
    """
    Checks if the script is running with Administrator privileges.

    Returns:
        bool: True if running as admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Failed to check for admin rights: {e}", exc_info=True)
        return False



def check_stop():
    """
    Checks for the existence of a 'stop.flag' file in the base directory.
    If found, the script will terminate gracefully. This provides a manual
    override to cancel a long sequence of installations.
    """
    stop_file = RUNTIME_PATH / "stop.flag"
    if stop_file.exists():
        logger.warning("Stop flag found. Installation cancelled by user.")
        try:
            stop_file.unlink()
        except OSError as e:
            logger.error(f"Failed to remove stop flag: {e}", exc_info=True)
        sys.exit(0)

def cleanup_before_install(paths_to_clean):
    """
    Deletes specified files and directories to clean up remnants of previous
    installations, preventing conflicts.

    Args:
        paths_to_clean (list[str]): A list of absolute file or directory paths to remove.
    """
    if not paths_to_clean:
        return
    logger.info("--- Running pre-install cleanup ---")
    for path_str in paths_to_clean:
        path = Path(path_str)
        if path.exists():
            try:
                if path.is_dir():
                    logger.info(f"Removing directory: {path}")
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    logger.info(f"Removing file: {path}")
                    path.unlink()
            except Exception as e:
                logger.error(f"Failed to remove {path}: {e}", exc_info=True)

def check_running_processes(process_names):
    """
    Checks if any processes in the provided list are currently running and logs a
    warning if they are. This is used to prevent conflicts during installation.

    Args:
        process_names (list[str]): A list of process executable names to check.
    """
    if not process_names:
        return
    logger.info(f"Checking for conflicting running processes: {process_names}")
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in process_names:
            logger.warning(f"Conflict: Process '{proc.info['name']}' is currently running. Installation may fail.")

def stop_windows_service(service_name):
    """
    Attempts to stop a specified Windows service to prevent conflicts during
    installation (e.g., stopping an auto-update service).

    Args:
        service_name (str): The system name of the service to stop.
    """
    try:
        service = psutil.win_service_get(service_name)
        service_info = service.as_dict()
        if service_info['status'] == 'running':
            logger.info(f"Attempting to stop service '{service_name}' to prevent conflicts...")
            service.stop()
            time.sleep(2) # Give the service time to stop
            service_info = service.as_dict() # Refresh info
            if service_info['status'] == 'stopped':
                logger.info(f"Service '{service_name}' stopped successfully.")
            else:
                logger.warning(f"Failed to stop service '{service_name}'. Current status: '{service_info['status']}'.")
    except psutil.NoSuchProcess:
        logger.info(f"Service '{service_name}' not found, no action needed.")
    except Exception as e:
        logger.error(f"An error occurred while stopping service '{service_name}': {e}", exc_info=True)

def wait_for_process_to_finish(process_name, timeout=900):
    """
    Monitors running processes and waits for a specific one to appear and then
    disappear. This is essential for installers that spawn a background process
    (like msiexec.exe) and exit immediately.

    Args:
        process_name (str): The name of the process executable to watch.
        timeout (int): The maximum time in seconds to wait for the process to finish.
    """
    logger.info(f"Watching for process '{process_name}' to start...")
    start_time = time.time()
    process_found = None

    # Wait up to 60 seconds for the process to appear
    while time.time() - start_time < 60:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() == process_name.lower():
                logger.info(f"Process '{process_name}' found with PID {proc.pid}. Now waiting for it to finish.")
                process_found = proc
                break
        if process_found:
            break
        time.sleep(1)
    
    if not process_found:
        logger.warning(f"Process '{process_name}' did not start within 60 seconds. The installation may have failed silently.")
        return

    # Now wait for the found process to exit
    try:
        process_found.wait(timeout=timeout)
        logger.info(f"Process '{process_name}' has finished.")
    except psutil.TimeoutExpired:
        logger.error(f"Process '{process_name}' did not finish within the timeout of {timeout} seconds. Terminating script.")
        raise Exception(f"{process_name} installation timed out.")

# --- Core Installation Logic ---

def wait_for_msi_to_finish(timeout=600):
    """
    Waits for the Windows Installer service (msiexec.exe) to finish.
    This prevents conflicts when running multiple MSI installers back-to-back.
    """
    logger.info("Checking if another MSI installation is in progress...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        if "msiexec.exe" not in (p.name() for p in psutil.process_iter()):
            logger.info("Windows Installer (msiexec.exe) is not running. Safe to proceed.")
            return
        logger.info("Another installation is still in progress. Waiting...")
        time.sleep(10)
    raise Exception("The previous MSI installation did not finish within the timeout period.")


def run_installer(filepath, args):
    """
    Executes a single installer command and captures its output. It uses
    `check=True` to automatically raise an exception if the installer returns a
    non-zero exit code, ensuring failures are not missed.

    Args:
        filepath (Path): The absolute path to the installer executable.
        args (list[str]): A list of command-line-arguments for the installer.

    Raises:
        subprocess.CalledProcessError: If the installer returns a non-zero exit code.
    """
    logger.debug(f"Preparing to run installer: {filepath} with args: {args}")
    
    # Process arguments to replace placeholders like {SOFTWARE_DIR}
    processed_args = []
    for arg in args:
        # Replace placeholder with the actual software directory path.
        # This makes config paths portable and resolves them at runtime.
        arg = arg.replace("{SOFTWARE_DIR}", str(SOFTWARE_DIR))
        arg = arg.replace("{RUNTIME_PATH}", str(RUNTIME_PATH))
        # Also handle environment variables like %TEMP%
        arg = os.path.expandvars(arg)
        processed_args.append(arg)

    full_command = []
    if str(filepath).lower().endswith('.msi'):
        full_command = ["msiexec.exe", "/i", str(filepath)] + [os.path.expandvars(arg) for arg in processed_args]
    else:
        full_command = [str(filepath)] + [os.path.expandvars(arg) for arg in processed_args]

    logger.info(f"Executing command: {' '.join(full_command)}")
    try:
        process = subprocess.run(
            full_command, check=True, capture_output=True, text=True, shell=False
        )
        logger.debug(f"Installer process completed for {filepath}.")
        logger.debug(f"Installer Return Code: {process.returncode}")
        if process.stdout:
            logger.debug(f"Installer Stdout:\n--- START ---\n{process.stdout.strip()}\n--- END ---")
        if process.stderr:
            logger.warning(f"Installer Stderr:\n--- START ---\n{process.stderr.strip()}\n--- END ---")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed for '{filepath}' with exit code {e.returncode}", exc_info=True)
        if e.stdout:
            logger.error(f"Command Stdout:\n--- START ---\n{e.stdout.strip()}\n--- END ---")
        if e.stderr:
            logger.error(f"Command Stderr:\n--- START ---\n{e.stderr.strip()}\n--- END ---")
        raise


def run_installer_with_retries(filepath, args_list):
    """
    Attempts to run an installer by trying a list of possible argument sets in
    sequence. It stops and succeeds on the first combination that works.

    Args:
        filepath (Path): The path to the installer executable.
        args_list (list): A list of argument lists to try.

    Raises:
        Exception: If all argument combinations fail.
    """
    last_exception = None
    for i, args in enumerate(args_list):
        logger.info(f"Attempting installation of {filepath.name} with argument set {i+1}/{len(args_list)}: {' '.join(args)}")
        try:
            run_installer(filepath, args)
            logger.info(f"Successfully ran installer {filepath.name} with argument set {i+1}.")
            return
        except subprocess.CalledProcessError as e:
            logger.warning(f"Argument set {i+1} for {filepath.name} failed with exit code {e.returncode}.")
            last_exception = e
    
    if last_exception:
        logger.error(f"All argument sets failed for {filepath.name}.")
        raise last_exception

def read_and_embed_logs(log_name, log_paths):
    """
    Reads content from specified native log files and embeds it into the main
    script log. This is crucial for diagnosing failures in complex installers.
    If a path is a directory, it finds and reads the most recent file.

    Args:
        log_name (str): The name of the software for context in the log.
        log_paths (list[str]): A list of file or directory paths to read from.
    """
    if not log_paths:
        return
    for log_path_str in log_paths:
        # Expand environment variables like %TEMP% in the path
        expanded_path_str = os.path.expandvars(log_path_str)
        log_path = Path(expanded_path_str)
        logger.info(f"\n{'-'*10} Reading {log_name} Log from {log_path} {'-'*10}")
        try:
            if log_path.exists():
                if log_path.is_dir():
                    # Find the most recently modified file in the directory
                    log_files = sorted(log_path.glob("**/*"), key=os.path.getmtime, reverse=True)
                    if not log_files:
                        logger.info(f"Log directory {log_path} is empty.")
                        continue
                    latest_log = log_files[0]
                    logger.info(f"Found latest log file in directory: {latest_log}")
                    log_path = latest_log

                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read(1024 * 20) # Read up to 20KB
                logger.debug(f"\n--- START {log_name} Log ---\n{log_content}\n--- END {log_name} Log ---")
            else:
                logger.info(f"{log_name} log not found at {log_path}.")
        except Exception as e:
            logger.error(f"Could not read {log_name} log from {log_path}. Reason: {e}", exc_info=True)

def install_software(name, check_path, installer, args_list, failed_installations, expected_hash=None, cleanup_paths=None, native_log_paths=None, process_name_to_watch=None, process_timeout=900, processes_to_check=None, services_to_stop=None, requires_reboot=False):
    """
    Orchestrates the entire installation process for a single piece of software,
    from pre-checks to execution, verification, and logging.

    Args:
        name (str): The display name of the software.
        check_path (str): The file or directory path to check for existing installations. Note: This path is absolute and assumes default installation locations. It might need adjustment for non-standard installations on different systems.
        installer (str): The filename of the installer in the SOFTWARE_DIR.
        args_list (list): A list of argument sets to try.
        failed_installations (list): A list to append the name to if installation fails.
        expected_hash (str, optional): The expected SHA256 hash of the installer file.
        cleanup_paths (list, optional): A list of paths to delete before installation.
        native_log_paths (list, optional): Paths to native log files to embed.
        process_name_to_watch (str, optional): A background process to wait for.
        process_timeout (int, optional): The timeout in seconds for the process watch.
        processes_to_check (list, optional): Conflicting processes to check for.
        services_to_stop (list, optional): Services to stop before installation.
        requires_reboot (bool, optional): Whether the software needs a reboot.
    """
    check_stop()
    logger.info("\n==================================================\nStarting installation for: {}\n==================================================\n".format(name))
    software_succeeded = False
    try:
        # Check for internet connection if required
        if name == "Google Chrome":
            if not CHROME_INSTALLER_SCRIPT.exists():
                logger.error(f"Chrome installer script not found at {CHROME_INSTALLER_SCRIPT}")
                raise FileNotFoundError(f"Chrome installer script not found at {CHROME_INSTALLER_SCRIPT}")

            logger.info("Handing off to chrome_installer.py for GUI-based installation.")
            try:
                # Ensure the script is run with the same Python executable from the venv
                python_executable = Path(sys.executable)
                process = subprocess.run(
                    [str(python_executable), str(CHROME_INSTALLER_SCRIPT)],
                    check=True, capture_output=True, text=True
                )
                logger.info("chrome_installer.py executed successfully.")
                logger.debug(f"chrome_installer.py stdout:\n{process.stdout}")
                if process.stderr:
                    logger.warning(f"chrome_installer.py stderr:\n{process.stderr}")
                software_succeeded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"chrome_installer.py failed with exit code {e.returncode}")
                logger.error(f"Stdout: {e.stdout}")
                logger.error(f"Stderr: {e.stderr}")
                raise
            return # End the function here for Chrome

        if name == "Microsoft Office":
            if not OFFICE_INSTALLER_SCRIPT.exists():
                logger.error(f"Office installer script not found at {OFFICE_INSTALLER_SCRIPT}")
                raise FileNotFoundError(f"Office installer script not found at {OFFICE_INSTALLER_SCRIPT}")

            logger.info("Handing off to office_installer.py for GUI-based installation.")
            try:
                # Ensure the script is run with the same Python executable from the venv
                python_executable = Path(sys.executable)
                process = subprocess.run(
                    [str(python_executable), str(OFFICE_INSTALLER_SCRIPT)],
                    check=True, capture_output=True, text=True
                )
                logger.info("office_installer.py executed successfully.")
                logger.debug(f"office_installer.py stdout:\n{process.stdout}")
                if process.stderr:
                    logger.warning(f"office_installer.py stderr:\n{process.stderr}")
                software_succeeded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"office_installer.py failed with exit code {e.returncode}")
                logger.error(f"Stdout: {e.stdout}")
                logger.error(f"Stderr: {e.stderr}")
                raise
            return # End the function here for Office

        if name == "FortiClient VPN":
            if not FORTICLIENT_INSTALLER_SCRIPT.exists():
                logger.error(f"FortiClient installer script not found at {FORTICLIENT_INSTALLER_SCRIPT}")
                raise FileNotFoundError(f"FortiClient installer script not found at {FORTICLIENT_INSTALLER_SCRIPT}")

            logger.info("Handing off to forticlient_installer.py for GUI-based installation.")
            try:
                python_executable = Path(sys.executable)
                process = subprocess.run(
                    [str(python_executable), str(FORTICLIENT_INSTALLER_SCRIPT)],
                    check=True, capture_output=True, text=True
                )
                logger.info("forticlient_installer.py executed successfully.")
                logger.debug(f"forticlient_installer.py stdout:\n{process.stdout}")
                if process.stderr:
                    logger.warning(f"forticlient_installer.py stderr:\n{process.stderr}")
                software_succeeded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"forticlient_installer.py failed with exit code {e.returncode}")
                logger.error(f"Stdout: {e.stdout}")
                logger.error(f"Stderr: {e.stderr}")
                raise
            return # End the function here for FortiClient VPN

        if name in ["FortiClient VPN"]:
            if not is_internet_available():
                logger.warning(f"Internet connection check failed for {name}. The installation will proceed, but may fail if the system is truly offline.")
        # --- Pre-install Verification ---
        # 1. Check if the installer file itself exists in the extraction directory.
        installer_path = SOFTWARE_DIR / installer
        if not installer_path.is_file():
            raise FileNotFoundError(f"Installer file not found: {installer_path}. The file may be missing from the bundle or failed to copy correctly.")

        # 2. Verify the installer file's integrity using its SHA256 hash.
        if not verify_file_hash(installer_path, expected_hash):
            raise Exception(f"Installer file {installer_path.name} is corrupted or has been tampered with. Aborting installation.")

        # 3. For installers that need a config file (like Office), check it exists too.
        office_config_path = None
        if name == "Microsoft Office" and "OfficeSetup.exe" in installer:
            office_config_path = SOFTWARE_DIR / "config.xml"
            with open(office_config_path, "w", encoding="utf-8") as f:
                f.write(OFFICE_CONFIG_XML_CONTENT)
            logger.info(f"Generated config.xml for Office at {office_config_path}")

        for args in args_list:
            for arg in args:
                if "{SOFTWARE_DIR}" in arg:
                    config_file_path = Path(arg.replace("{SOFTWARE_DIR}", str(SOFTWARE_DIR)))
                    if not config_file_path.is_file():
                        raise FileNotFoundError(f"Required configuration file not found: {config_file_path}")

        # If Office config was generated, ensure its path is used in args_list
        if office_config_path:
            for i, args_set in enumerate(args_list):
                for j, arg in enumerate(args_set):
                    if "/Configuration" in arg and "config.xml" in arg:
                        args_list[i][j] = f"/Configuration {office_config_path}"

        # Handle Chrome specific logging
        chrome_log_path = None
        if name == "Google Chrome" and "ChromeSetup.exe" in installer:
            chrome_log_path = RUNTIME_PATH / "chrome_install.log"
            logger.info(f"Setting Chrome installer log path to: {chrome_log_path}")
            # Inject --log-file argument into all arg sets for Chrome
            for i, args_set in enumerate(args_list):
                args_list[i].append(f"--log-file={chrome_log_path}")
            # Add the dynamic Chrome log path to native_log_paths for logging
            if native_log_paths is None:
                native_log_paths = []
            native_log_paths.append(str(chrome_log_path))

        # Always run cleanup first to remove remnants of failed installs.
        cleanup_before_install(cleanup_paths)

        if not check_path:
            logger.warning(f"No 'check_path' provided for '{name}'. Installation success cannot be reliably verified.")

        if check_path and (os.path.exists(check_path) or os.path.isdir(check_path)):
            logger.info(f"'{name}' is already installed (check path exists: {check_path}). Skipping.")
            return

        check_running_processes(processes_to_check)

        if services_to_stop:
            for service in services_to_stop:
                stop_windows_service(service)

        
        logger.info(f"Running installer for '{name}' from '{installer_path}'")

        log_processes("pre-install")
        run_installer_with_retries(installer_path, args_list)
        
        if process_name_to_watch:
            wait_for_process_to_finish(process_name_to_watch, timeout=process_timeout)

        # After any installation, wait for the MSI service to be free
        wait_for_msi_to_finish()

        log_processes("post-install")


        logger.info(f"Installer for '{name}' finished. Verifying installation...")
        if check_path:
            software_succeeded = False # Initialize for this branch
            retries = 12
            for i in range(retries):
                if os.path.exists(check_path) or os.path.isdir(check_path):
                    logger.info(f"VERIFIED: '{name}' installed successfully on attempt {i+1}. Check path '{check_path}' found.")
                    software_succeeded = True
                    break
                logger.debug(f"Verification attempt {i+1}/{retries} for '{name}' failed. Waiting 5 seconds.")
                time.sleep(5)
            if not software_succeeded: # If loop completed without success
                raise Exception(f"Post-install verification failed after {retries} attempts. Check path '{check_path}' not found.")
        else:
            logger.info(f"'{name}' installation process completed (no verification path provided).")
            software_succeeded = True # Always succeed if no check_path
    except FileNotFoundError as e:
        logger.error(f"File error during installation of {name}: {e}")
        raise # Re-raise the exception to be caught by the main loop
    except Exception as e:
        logger.error(f"An unexpected error occurred during installation of {name}: {e}")
        raise # Re-raise the exception to be caught by the main loop

# --- Main Execution Logic ---

def load_software_config(config_path):
    """
    Loads and validates the software installation list from the JSON config file.

    Args:
        config_path (Path): The path to the software_config.json file.

    Returns:
        list: A list of dictionaries, where each dictionary is a software item.
              Returns None if the file is not found or is invalid.
    """
    logger.info(f"Loading software configuration from {config_path}")
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info("Software configuration loaded successfully.")
        return config
    except FileNotFoundError:
        logger.critical(f"Configuration file not found at: {config_path}")
        return None
    except json.JSONDecodeError as e:
        logger.critical(f"Error decoding JSON from {config_path}: {e}")
        return None
    except Exception as e:
        logger.critical(f"An unexpected error occurred while reading the configuration file: {e}", exc_info=True)
        return None



# A global list to track which installed apps require a reboot
reboot_required_list = []

def main():
    """
    The main entry point for the script. It orchestrates the entire process:
    1. Logs system info.
    2. Runs all pre-flight checks.
    3. Ensures admin privileges.
    4. Loads the software configuration.
    5. Loops through and installs each piece of software.
    6. Reports a summary of successes, failures, and required reboots.
    """
    logger.info(f"==== Installation script started at {datetime.now()} ====")
    log_system_info()

    if not run_pre_flight_checks():
        sys.exit(1)

    logger.warning("Please ensure that User Account Control (UAC) is not blocking silent installations.")

    if not is_admin():
        logger.warning("Not running as admin. Attempting to relaunch with elevated privileges...")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        except Exception as e:
            logger.critical(f"Failed to relaunch as admin: {e}", exc_info=True)
        sys.exit(0)

    # Clean up any old stop flag before starting
    stop_file = RUNTIME_PATH / "stop.flag"
    if stop_file.exists():
        logger.info("Removing pre-existing stop flag.")
        stop_file.unlink()

    software_to_install = load_software_config(CONFIG_FILE)
    if not software_to_install:
        logger.critical("Could not load software configuration. Aborting.")
        sys.exit(1)

    failed_installations = []

    logger.info("Beginning software installation sequence...")

    for software in software_to_install:
        try:
            install_software(
                name=software.get("name"),
                check_path=software.get("check_path"),
                installer=software.get("installer"),
                args_list=software.get("args_list", []),
                failed_installations=failed_installations,
                expected_hash=software.get("expected_hash"),
                cleanup_paths=software.get("cleanup_paths"),
                native_log_paths=software.get("native_log_paths"),
                process_name_to_watch=software.get("process_name_to_watch"),
                process_timeout=software.get("process_timeout", 900),
                processes_to_check=software.get("processes_to_check"),
                services_to_stop=software.get("services_to_stop"),
                requires_reboot=software.get("requires_reboot", False)
            )
        except Exception as e:
            logger.error(f"Error installing {software.get('name')}: {e}")
            failed_installations.append(software.get("name"))

    logger.info("==== All installation tasks complete ====")
    if failed_installations:
        failed_list = ", ".join(failed_installations)
        logger.error(f"The following installations failed: {failed_list}")
        
    else:
        logger.info("All installations completed successfully.")
        

    if reboot_required_list:
        reboot_apps = ", ".join(reboot_required_list)
        logger.warning(f"The following applications require a reboot to function correctly: {reboot_apps}")
        

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Script interrupted by user (Ctrl+C).")
    except Exception:
        logger.critical("Uncaught exception", exc_info=True)
    