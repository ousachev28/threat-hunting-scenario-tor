
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ousachev28/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks like user “ousachev28” downloaded a tor installer. It resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at: `2026-03-07T23:17:51.7355462Z`


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "oleg-windows-pr"
| where InitiatingProcessAccountName == "ousachev28"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-07T23:17:51.7355462Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1135" height="358" alt="image" src="https://github.com/user-attachments/assets/4efb4912-3294-4028-b5a3-cc15b5e4a807" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommendLine` that contained the string `tor-browser-windows-x86_64-portable-15.0.7.exe`. Based on the logs returned at `2026-03-07T23:42:59.1424375Z`, user ousachev28 on the `oleg-windows-pr` device executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "oleg-windows-pr"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1162" height="183" alt="image" src="https://github.com/user-attachments/assets/3484e8cd-a712-45d1-9289-5c1a8285feb5" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “ousachev28” actually opened the tor browser. There was evidence that they did open it at `2026-03-07T23:43:43.6274951Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "oleg-windows-pr"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe", "start-tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath,SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1135" height="398" alt="image" src="https://github.com/user-attachments/assets/72bbffa9-a1ef-4609-892c-bf792aaf44b8" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At `2026-03-07T23:43:49.6232594Z`, user ousachev28 on `oleg-windows-pr` device successfully established connection to the remote IP address `15.204.223.128` on port `9001`. The connection was initiated by the process `tor.exe`, located in `C:\Users\ousachev28\Desktop\Tor Browser\Browser\firefox.exe`. There were a couple other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "oleg-windows-pr"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9060", "9061", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1161" height="360" alt="image" src="https://github.com/user-attachments/assets/8994f769-0c81-4d48-96a2-1c3fb5074eaa" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-03-07T23:17:51.7355462Z`
- **Event:** The user "ousache28" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ousachev28\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-03-07T23:42:59.1424375Z`
- **Event:** The user "ousachev28" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\ousachev28\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-07T23:43:43.6274951Z`
- **Event:** User "ousachev" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ousachev28\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-03-07T23:43:49.6232594Z`
- **Event:** A network connection to IP `15.204.223.128` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ousachev28\Desktop\Tor Browser\Browser\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-03-07T23:44:19.3620705Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-03-07T23:49:52.6232594Z`
- **Event:** The user "ousachev28" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ousachev28\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ousachev28" on the "oleg-windows-pr" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `oleg-windows-pr` by the user `ousachev28`. The device was isolated, and the user's direct manager was notified.

---
