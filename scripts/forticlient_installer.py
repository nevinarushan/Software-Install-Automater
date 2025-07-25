
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
    BASE_DIR = Path(__file__).parent.parent

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
INSTALLER_NAME = "FortiClientVPNInstaller.exe"
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
    """Launches the FortiClient installer if it exists."""
    if not INSTALLER_PATH.exists():
        logging.error(f"Installer not found at: {INSTALLER_PATH}")
        raise FileNotFoundError(f"Installer not found at: {INSTALLER_PATH}")
    
    logging.info(f"Launching installer: {INSTALLER_PATH}")
    try:
        subprocess.Popen([str(INSTALLER_PATH)])
    except Exception as e:
        logging.error(f"Failed to launch installer: {e}")
        raise

def wait_for_window(title, timeout=30):
    """Waits for a window with a specific title to appear and become active."""
    logging.info(f"Waiting for window with title: '{title}'")
    start_time = time.time()
    while time.time() - start_time < timeout:
        windows = pyautogui.getWindowsWithTitle(title)
        if windows:
            try:
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
    Checks if the installation is complete by looking for FortiClient.exe.
    """
    logging.info("Installation in progress. This may take several minutes.")

    # Default installation path for FortiClient
    forticlient_path = Path("C:/Program Files/Fortinet/FortiClient/FortiClient.exe")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        if forticlient_path.exists():
            logging.info("FortiClient installation verified successfully.")
            return True
        time.sleep(5)
        
    logging.error("Installation check timed out. FortiClient executable not found.")
    return False

def main():
    """Main function to orchestrate the FortiClient installation."""
    try:
        installer_process = launch_installer()
        
        # 2. Wait for the installer window to appear
        # NOTE: You may need to adjust the window title
        window_title = "FortiClient VPN Setup"
        installer_window = wait_for_window(window_title)
        
        # --- Installer Steps ---
        # These steps are based on a typical installer wizard.
        # You may need to adjust the logic, button text/images, and coordinates.

        # Example: Click "Next" on the welcome screen
        # Assumes a "Next" button is visible. You might need to use pyautogui.locateCenterOnScreen()
        # with an image of the button for more reliability.
        pyautogui.press('enter') # Assuming 'enter' works for the initial screen
        logging.info("Pressed Enter on the welcome screen.")
        time.sleep(2)

        # Example: Accept license agreement
        # This might involve clicking a checkbox and then "Next"
        # pyautogui.click(x=100, y=200) # Example coordinates for a checkbox
        pyautogui.press('tab') # Tab to the checkbox
        pyautogui.press('space') # Check the box
        logging.info("Accepted license agreement.")
        time.sleep(1)
        pyautogui.press('enter') # Click Next
        logging.info("Clicked 'Next' after accepting license.")
        time.sleep(2)

        # Example: Click "Install"
        pyautogui.press('enter')
        logging.info("Clicked 'Install'.")

        # 3. Wait for the installation to complete
        if check_installation_complete(installer_process):
            pyautogui.alert("FortiClient VPN has been installed successfully!")
        else:
            pyautogui.alert("FortiClient VPN installation failed or timed out.", "Installation Failed")

    except FileNotFoundError:
        pyautogui.alert(f"Error: FortiClient installer not found at {INSTALLER_PATH}", "File Not Found")
    except TimeoutError as e:
        pyautogui.alert(f"Error: {e}", "Timeout Error")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        pyautogui.alert(f"An unexpected error occurred: {e}", "Error")

if __name__ == "__main__":
    main()
