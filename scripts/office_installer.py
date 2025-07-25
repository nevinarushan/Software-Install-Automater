
import pyautogui
import time
import subprocess
from pathlib import Path
import logging
import psutil
import sys

# --- Configuration ---
if getattr(sys, 'frozen', False):
    # Running as a bundled executable
    BASE_DIR = Path(sys.executable).parent
else:
    # Running as a standard Python script
    BASE_DIR = Path(__file__).parent.parent # Go up to the root project directory

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
SOFTWARE_DIR = BASE_DIR / "Softwares"
INSTALLER_NAME = "OfficeSetup.exe"
INSTALLER_PATH = SOFTWARE_DIR / INSTALLER_NAME

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

# Key Office executables to verify installation
OFFICE_APPS = {
    "Word": Path("C:/Program Files/Microsoft Office/root/Office16/WINWORD.EXE"),
    "Excel": Path("C:/Program Files/Microsoft Office/root/Office16/EXCEL.EXE"),
    "PowerPoint": Path("C:/Program Files/Microsoft Office/root/Office16/POWERPNT.EXE")
}

# --- Main Functions ---

def launch_installer():
    """Launches the Office installer if it exists."""
    if not INSTALLER_PATH.exists():
        logging.error(f"Installer not found at: {INSTALLER_PATH}")
        raise FileNotFoundError(f"Installer not found at: {INSTALLER_PATH}")

    logging.info(f"Launching installer: {INSTALLER_PATH}")
    try:
        # Office setup requires admin rights and runs as a separate process
        subprocess.Popen([str(INSTALLER_PATH)], shell=True)
    except Exception as e:
        logging.error(f"Failed to launch installer: {e}")
        raise

def check_installation_complete(timeout=1800):
    """
    Checks if the installation is complete by looking for Office executables.
    Office installation is a lengthy background process.
    """
    logging.info("Installation in progress. This may take 20-30 minutes.")
    logging.info("The installer window may close, but setup continues in the background.")

    start_time = time.time()
    while time.time() - start_time < timeout:
        # Check if any of the key Office applications now exist
        for app, path in OFFICE_APPS.items():
            if path.exists():
                logging.info(f"Microsoft {app} installation verified successfully at: {path}")
                # Once one app is found, we can assume the suite is installed.
                return True
        
        # Provide periodic updates to the user/log
        if int(time.time() - start_time) % 60 == 0:
            logging.info("Still waiting for Office installation to complete...")
            
        time.sleep(10)

    logging.error("Installation check timed out. Office executables not found.")
    return False

def main():
    """Main function to orchestrate the Office installation."""
    try:
        # 1. Check if Office is already installed
        if any(path.exists() for path in OFFICE_APPS.values()):
            logging.info("Microsoft Office is already installed. Skipping.")
            pyautogui.alert("Microsoft Office is already installed.", "Installation Skipped")
            return

        # 2. Launch the installer
        installer_process = launch_installer()

        # 3. Wait for the installation to complete
        logging.info("Office setup runs in the background. Monitoring for completion...")
        if check_installation_complete(installer_process):
            pyautogui.alert("Microsoft Office has been installed successfully!")
        else:
            pyautogui.alert("Microsoft Office installation failed or timed out.", "Installation Failed")

    except FileNotFoundError:
        pyautogui.alert(f"Error: Office installer not found at {INSTALLER_PATH}", "File Not Found")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        pyautogui.alert(f"An unexpected error occurred: {e}", "Error")

if __name__ == "__main__":
    main()
