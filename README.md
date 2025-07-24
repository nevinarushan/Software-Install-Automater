# Software Installer

This project is a simple software installer for Windows that automates the process of downloading and installing a list of predefined software.

## Features

*   **Automated Installation:** Automatically downloads and installs a list of software from a JSON configuration file.
*   **Prerequisite Checks:** Checks if the software is already installed before attempting to install it.
*   **GUI Interface:** Provides a simple GUI to show the installation progress.
*   **Logging:** Logs the installation progress to a file.

## Prerequisites

*   Windows operating system
*   Python 3.x

## How to Use

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repository.git
    ```
2.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure the software to be installed:**
    Modify the `software_config.json` file to add the software you want to install.
4.  **Run the installer:**
    ```bash
    python installer.py
    ```

## Configuration

The `software_config.json` file contains a list of software to be installed. Each software is a JSON object with the following properties:

*   `name`: The name of the software.
*   `download_url`: The URL to download the installer.
*   `installer_path`: The path to the installer.
*   `install_check`: The path to the executable to check if the software is already installed.

**Example:**

```json
[
  {
    "name": "Notepad++",
    "download_url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.4.4/npp.8.4.4.Installer.x64.exe",
    "installer_path": "C:\Users\zkperera\Downloads\npp.8.4.4.Installer.x64.exe",
    "install_check": "C:\Program Files\Notepad++\notepad++.exe"
  }
]
```

## Dependencies

The project uses the following Python libraries:

*   `requests`: To download the installers.
*   `tkinter`: To create the GUI.
*   `psutil`: To check if a process is running.

## Building

To build the executable, you can use `pyinstaller`:

```bash
pyinstaller --onefile --windowed installer.py
```

## Known Issues

The project is currently facing some errors. If you would like to help solve them, the latest logs are available in the `install_log.txt` file.

## License

This project is licensed under the MIT License.