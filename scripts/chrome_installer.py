
import pyautogui
import time
import subprocess
from pathlib import Path
import logging
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
INSTALLER_NAME = "ChromeSetup.exe"
INSTALLER_PATH = BASE_DIR / "Softwares" / INSTALLER_NAME

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# --- Main Functions ---

def launch_installer():
    """Launches the Chrome installer if it exists."""
    if not INSTALLER_PATH.exists():
        logging.error(f"Installer not found at: {INSTALLER_PATH}")
        raise FileNotFoundError(f"Installer not found at: {INSTALLER_PATH}")
    
    logging.info(f"Launching installer: {INSTALLER_PATH}")
    try:
        # Using subprocess.Popen to run the installer asynchronously
        subprocess.Popen([str(INSTALLER_PATH)])
    except Exception as e:
        logging.error(f"Failed to launch installer: {e}")
        raise

def wait_for_window(title, timeout=30):
    """Waits for a window with a specific title to appear and become active."""
    logging.info(f"Waiting for window with title: '{title}'")
    start_time = time.time()
    while time.time() - start_time < timeout:
        # Get all windows with the specified title
        windows = pyautogui.getWindowsWithTitle(title)
        if windows:
            try:
                # Attempt to activate the window
                window = windows[0]
                window.activate()
                logging.info(f"Window '{title}' found and activated.")
                return window
            except Exception as e:
                logging.warning(f"Found window but could not activate: {e}")
        time.sleep(1)
    
    logging.error(f"Timeout: Window with title '{title}' did not appear within {timeout} seconds.")
    raise TimeoutError(f"Window '{title}' not found.")

def check_installation_complete(timeout=900):
    """
    Checks if the installation is complete by looking for chrome.exe.
    The online installer window closes automatically on completion.
    """
    logging.info("Installation in progress. The installer will close automatically when finished.")
    logging.info("This may take several minutes depending on your internet connection.")

    # Default installation path for Google Chrome
    chrome_path = Path("C:/Program Files/Google/Chrome/Application/chrome.exe")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        if chrome_path.exists():
            logging.info("Google Chrome installation verified successfully.")
            return True
        time.sleep(5)
        
    logging.error("Installation check timed out. Chrome executable not found.")
    return False

def main():
    """Main function to orchestrate the Chrome installation."""
    try:
        installer_process = launch_installer()
        
        # 2. Wait for the installer window to appear
        # Note: The online installer may not have a predictable window title initially.
        # We will rely on the installer closing as a sign of completion.
        logging.info("Chrome online installer runs in the background.")
        
        # 3. Wait for the installation to complete
        if check_installation_complete(installer_process):
            pyautogui.alert("Google Chrome has been installed successfully!")
        else:
            pyautogui.alert("Google Chrome installation failed or timed out.", "Installation Failed")

    except FileNotFoundError:
        pyautogui.alert(f"Error: Chrome installer not found at {INSTALLER_PATH}", "File Not Found")
    except TimeoutError as e:
        pyautogui.alert(f"Error: {e}", "Timeout Error")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        pyautogui.alert(f"An unexpected error occurred: {e}", "Error")

if __name__ == "__main__":
    main()
