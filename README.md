![image](https://github.com/Analyzer1x7000/Kestrel/assets/103800652/0565b017-9211-4a1f-91ab-97a03677fa3e)


# Kestrel
Kestrel is a PowerShell script designed to be used via CrowdStrike RTR as a `CloudFile`. Similar to KAPE, it pulls critical forensic artifacts from a target during IR, so that the artifacts can be analyzed on a separate forensic workstation.

Kestrel contains several modules that can be run individually, or all at once.

## Setup
Create a new script via `Configuration` -> `Response Scripts & Files` and name it "Kestrel"

![image](https://github.com/Analyzer1x7000/Kestrel/assets/103800652/b0b05280-712d-4aaa-bd32-8f8842a13691)

## Usage

To run Kestrel in your CrowdStrike RTR console:
```
  runscript -CloudFile='Kestrel' -CommandLine='-module all'
  OR 
  runscript -CloudFile='Kestrel' -CommandLine='-module Services'"
```

## FEATURES
```
PARAMETERS
  -module all           : run all modules
  -module <name>        : run specific module
  -folder <path>        : output folder [Default: C:\Windows\Temp\IR]
  -module help          : display usage

MODULES
  {Malware - Persistence}
    AutoRuns              : Gather files in common startup locations
    Services              : Gather Windows Services
    InstalledSoftware     : Gather Installed Software from Uninstall Key
    DNSCache              : Get clients local DNS cache
    RunningProcesses      : Get all running processes and hashes
  
  {Forensics - Evidence of Execution}
    Prefetch              : Get list of files in prefetch
    PEFiles               : Get list of PE files and hashes in user writeable locations
    Amcache               : Get a copy of Amcache.hve 
    JumpLists             : Get a copy of JumpLists (AutomaticDestinations & CustomDestinations)
    LastVisitedMRU        : Get a copy of LastVisitedPidlMRU from NTUSER.DAT hive
    UserAssist            : Get a copy of UserAssist from NTUSER.DAT hive
    SRUM                  : Get a copy of SRUDB.DAT
  
  {Forensics - Deleted Items & File Existence}
    RecycleBin            : Get a copy of the contents of $Recycle.Bin
    Shimcache             : Get a copy of AppCompatCache from SYSTEM hive
    Thumbcache            : Get a copy of the Thumbcache from user's %AppData% folder
    WordWheelQuery        : Get a copy of WordWheelQuery key from NTUSER.DAT hive
    UserTypedPaths        : Get a copy of TypedPaths from NTUSER.DAT hive
  
  {Forensics - Files & Folders Opened}
    LNKFiles              : Get LNK files on desktop and recent files list
    RecentFiles           : Get history of recent files
    OpenSaveMRU           : Get a copy of OpenSavePidlMRU from NTUSER.DAT hive
    OfficeRecentfiles     : Get Office file MRU lists from NTUSER.DAT hive
  
  {Malware - Miscellaneous}
    OfficeFiles           : Get list of office docs and hashes in user writeable locations
    ScriptFiles           : Get list of scripts and hashes in user writeable locations
  
  {Forensics - Miscellaneous}
    EventLogs             : Gather Event Logs
    HiddenFilesDirs       : Get hidden files and directories
    WindowsUpdates        : Get installed windows updates
    BrowserExtensions     : Get list of extensions for Chrome and Firefox
    KrbSessions           : Get list of kerberos sessions
```

## Example


