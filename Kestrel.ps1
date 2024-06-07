Param (
    [Parameter(Mandatory = $false)]
    [string] $module,

    [Parameter(Mandatory = $false)]
    [string] $folder = "C:\Windows\Temp\IR"
)

[string] $date = Get-Date -Format yyyyMMddHHmmss
[string] $ComputerName = $Env:COMPUTERNAME

function usage {
    Write-Output "
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
    JumpLists             : Get a copy of JumpLists (AutomaticDestinations & CustomDestinations)
    SRUM                  : Get a copy of SRUDB.DAT
  
  {Forensics - Deleted Items & File Existence}
    RecycleBin            : Get a copy of the contents of $Recycle.Bin
    Thumbcache            : Get a copy of the Thumbcache from user's %AppData% folder
    WordWheelQuery        : Get a copy of WordWheelQuery key from NTUSER.DAT hive
    UserTypedPaths        : Get a copy of TypedPaths from NTUSER.DAT hive
  
  {Forensics - Files & Folders Opened}
    LNKFiles              : Get LNK files on desktop and recent files list
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
	Recall				  : Gathers screenshots and other data from Microsoft's Recall feature"
}

# Ensure the output directory exists
if (-Not (Test-Path $folder)) {
    New-Item -Path $folder -Type Directory -Force | Out-Null
}
$Global:irPath = $folder

# [START] Malware - Persistence
function Get-AutoRuns {
    Write-Output "[+] Gathering Windows AutoRuns ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_AutoRuns.csv"
    $results = Get-CimInstance -Class Win32_StartupCommand | Select-Object Name, Caption, Description, Command, Location, User
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-Services {
    Write-Output "[+] Gathering Windows Services ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_Services.csv"
    $results = Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Caption, Description, DisplayName, Name, PathName, ProcessId, StartMode, State, Status
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-InstalledSoftware {
    Write-Output "[+] Gathering Installed Software ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_InstalledSoftware.csv"
    $regPaths = @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\*")

    $results = @()
    foreach ($path in $regPaths) {
        $results = $results + (Get-ItemProperty -Path "Registry::$path" | Where-Object DisplayName -ne $null | Select-Object Publisher, DisplayName, DisplayVersion, InstallDate, InstallSource, InstallLocation)
    }

    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-DNSCache {
    Write-Output "[+] Gathering DNS Client Cache ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_DNSClientCache.csv"
    Get-DnsClientCache | Select-Object TTL, Data, DataLength, Entry, Name, TimeToLive, Type | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-RunningProcesses {
    Write-Output "[+] Gathering Running Processes ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_Processes.csv"

    $procs = Get-Process -IncludeUserName

    foreach ($proc in $procs) {
        $procInfo = Get-CimInstance Win32_Process | Where-Object ProcessID -eq $proc.Id | Select-Object -Property Path, CommandLine
        $proc | Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $procInfo.CommandLine
        $proc | Add-Member -MemberType NoteProperty -Name "Hash" -Value $procInfo.Path
    }

    $results = Get-Process | Select-Object Id, Name, ProcessName, Path, Hash, FileVersion, CommandLine, Company, Product, Description, StartTime
    $results | Export-CSV -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}
# [END] Malware - Persistence 

# [START] Forensics - Evidence of Execution
function Get-Prefetch {
    Write-Output "[+] Gathering Prefetch Cache ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_Prefetch.csv"
    $results = Get-ChildItem -Path "C:\Windows\Prefetch\" -Filter *.pf -ErrorAction SilentlyContinue | Select-Object Name, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc

    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-PEFiles {
    Write-Output "[+] Gathering list of PE files in TEMP locations ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_PEFiles.csv"

    $PEExtPattern = ".exe|.dll|.sys"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match $PEExtPattern } |
                ForEach-Object {
                    $filePath = $_.FullName
                    $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                    $peFiles += New-Object PSObject -Property @{
                        Hash     = $hash
                        FilePath = $filePath
                    }
                }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-JumpLists {
    Write-Output "[+] Gathering JumpLists ..."
    $ir_jumplists_path = Join-Path $Global:irPath "${ComputerName}_JumpLists"
    New-Item -Path $ir_jumplists_path -Type Directory -Force | Out-Null

    $jumplist_paths = @("${env:APPDATA}\Microsoft\Windows\Recent\AutomaticDestinations", "${env:APPDATA}\Microsoft\Windows\Recent\CustomDestinations")

    foreach ($path in $jumplist_paths) {
        $jumplists = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $jumplists) {
            Copy-Item -Path $file.FullName -Destination $ir_jumplists_path -ErrorAction SilentlyContinue
        }
    }

    Write-Output "[ done ]"
}

function Get-SRUM {
    Write-Output "[+] Gathering SRUM data ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_SRUDB.DAT"

    $srum_path = "C:\Windows\System32\sru\SRUDB.dat"
    if (Test-Path $srum_path) {
        Copy-Item -Path $srum_path -Destination $outputFile
    }

    Write-Output "[ done ]"
}
# [END] Forensics - Evidence of Execution

# [START] Forensics - Deleted Items & File Existence
function Get-RecycleBin {
    Write-Output "[+] Gathering Recycle Bin contents ..."
    $ir_recyclebin_path = Join-Path $Global:irPath "${ComputerName}_RecycleBin"
    New-Item -Path $ir_recyclebin_path -Type Directory -Force | Out-Null

    $recycleBinPath = "C:\$Recycle.Bin\*"
    $recycleBinItems = Get-ChildItem -Path $recycleBinPath -Recurse -ErrorAction SilentlyContinue
    foreach ($item in $recycleBinItems) {
        Copy-Item -Path $item.FullName -Destination $ir_recyclebin_path -ErrorAction SilentlyContinue
    }

    Write-Output "[ done ]"
}

function Get-Thumbcache {
    Write-Output "[+] Gathering Thumbcache ..."
    $ir_thumbcache_path = Join-Path $Global:irPath "${ComputerName}_Thumbcache"
    New-Item -Path $ir_thumbcache_path -Type Directory -Force | Out-Null

    $thumbcachePath = "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*"
    $thumbcacheItems = Get-ChildItem -Path $thumbcachePath -Recurse -ErrorAction SilentlyContinue
    foreach ($item in $thumbcacheItems) {
        Copy-Item -Path $item.FullName -Destination $ir_thumbcache_path -ErrorAction SilentlyContinue
    }

    Write-Output "[ done ]"
}

function Get-WordWheelQuery {
    Write-Output "[+] Gathering WordWheelQuery from NTUSER.DAT ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_WordWheelQuery.txt"

    $ntuserPath = "C:\Users\*\NTUSER.DAT"
    $users = Get-ChildItem "C:\Users" | Where-Object { Test-Path "$($_.FullName)\NTUSER.DAT" }

    foreach ($user in $users) {
        $username = $user.Name
        $ntuser = "$($user.FullName)\NTUSER.DAT"
        if (Test-Path $ntuser) {
            reg.exe load HKU\TempHive $ntuser | Out-Null
            $wordWheelQuery = Get-ItemProperty -Path "HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
            reg.exe unload HKU\TempHive | Out-Null
            Add-Content -Path $outputFile -Value "[$username]"
            Add-Content -Path $outputFile -Value $wordWheelQuery
            Add-Content -Path $outputFile -Value ""
        }
    }

    Write-Output "[ done ]"
}

function Get-OfficeRecentFiles {
    Write-Output "[+] Gathering Office Recent Files from NTUSER.DAT ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_OfficeRecentFiles.csv"
    $results = @()

    $ntuserPath = "C:\Users\*\NTUSER.DAT"
    $users = Get-ChildItem "C:\Users" | Where-Object { Test-Path "$($_.FullName)\NTUSER.DAT" }

    foreach ($user in $users) {
        $username = $user.Name
        $ntuser = "$($user.FullName)\NTUSER.DAT"
        if (Test-Path $ntuser) {
            reg.exe load HKU\TempHive $ntuser | Out-Null
            $officeVersions = Get-ChildItem -Path "HKU\TempHive\Software\Microsoft\Office\" | Select-Object -ExpandProperty Name
            foreach ($version in $officeVersions) {
                $apps = Get-ChildItem -Path "HKU\TempHive\Software\Microsoft\Office\$version\" | Select-Object -ExpandProperty Name
                foreach ($app in $apps) {
                    $mruPath = "HKU\TempHive\Software\Microsoft\Office\$version\$app\File MRU"
                    $liveIdMruPath = "HKU\TempHive\Software\Microsoft\Office\$version\$app\LiveId_*\File MRU"
                    $adMruPath = "HKU\TempHive\Software\Microsoft\Office\$version\$app\AD_*\File MRU"

                    # Collect MRU entries
                    foreach ($path in @($mruPath, $liveIdMruPath, $adMruPath)) {
                        try {
                            $mruEntries = Get-ItemProperty -Path $path -ErrorAction Stop
                            foreach ($property in $mruEntries.PSObject.Properties) {
                                if ($property.Name -match "Item") {
                                    $results += [PSCustomObject]@{
                                        Username    = $username
                                        OfficeApp   = $app
                                        Version     = $version
                                        MRUPath     = $path
                                        MRUEntry    = $property.Value
                                    }
                                }
                            }
                        } catch {
                            # Handle the error if the path does not exist
                        }
                    }
                }
            }
            reg.exe unload HKU\TempHive | Out-Null
        }
    }

    $results | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
}

function Get-UserTypedPaths {
    Write-Output "[+] Gathering UserTypedPaths from NTUSER.DAT ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_UserTypedPaths.txt"

    $ntuserPath = "C:\Users\*\NTUSER.DAT"
    $users = Get-ChildItem "C:\Users" | Where-Object { Test-Path "$($_.FullName)\NTUSER.DAT" }

    foreach ($user in $users) {
        $username = $user.Name
        $ntuser = "$($user.FullName)\NTUSER.DAT"
        if (Test-Path $ntuser) {
            reg.exe load HKU\TempHive $ntuser | Out-Null
            $userTypedPaths = Get-ItemProperty -Path "HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
            reg.exe unload HKU\TempHive | Out-Null
            Add-Content -Path $outputFile -Value "[$username]"
            Add-Content -Path $outputFile -Value $userTypedPaths
            Add-Content -Path $outputFile -Value ""
        }
    }

    Write-Output "[ done ]"
}
# [END] Forensics - Deleted Items & File Existence

# [START] Forensics - Files & Folders Opened

function Get-LnkFiles {
    Write-Output "[+] Gathering LNK files ..."
    $ir_lnkfiles_path = Join-Path $Global:irPath "${ComputerName}_LnkFiles"
    New-Item -Path $ir_lnkfiles_path -Type Directory | Out-Null

    $lnkfiles_path = @("${env:LOCALAPPDATA}\Microsoft\Windows\Recent\", "${env:LOCALAPPDATA}\Microsoft\Office\Recent\", "C:\Users\*\Desktop\")

    foreach ($path in $lnkfiles_path) {
        $lnk_files = Get-ChildItem -Path $path -Filter *.lnk -Recurse -ErrorAction SilentlyContinue

        foreach ($file in $lnk_files) {
            Copy-Item -Path $file.FullName -Destination $ir_lnkfiles_path -ErrorAction SilentlyContinue
        }
    }
}

# [END] Forensics - Files & Folders Opened

# [START] Malware - Miscellaneous
function Get-OfficeFiles {
    Write-Output "[+] Gathering list of Office files in TEMP locations ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_OfficeFiles.csv"

    $PEExtPattern = ".docx|.docm|.xlsx|.xlsm|.pptx|.pptm"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match $PEExtPattern } |
                ForEach-Object {
                    $filePath = $_.FullName
                    $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                    $peFiles += New-Object PSObject -Property @{
                        Hash     = $hash
                        FilePath = $filePath
                    }
                }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}

function Get-ScriptFiles {
    Write-Output "[+] Gathering list of Script files in TEMP locations ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_ScriptFiles.csv"

    $PEExtPattern = ".bat|.vbs|.cmd|.js|.com|.ps1|.psm|.psm1|.psd"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match $PEExtPattern } |
                ForEach-Object {
                    $filePath = $_.FullName
                    $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                    $peFiles += New-Object PSObject -Property @{
                        Hash     = $hash
                        FilePath = $filePath
                    }
                }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}
# [END] Malware - Miscellaneous

# [START] Forensics - Miscellaneous
function Get-EventLogs {
    Write-Output "[+] Gathering Event Logs ..."
    $ir_evtx_path = Join-Path $Global:irPath "${ComputerName}_evtx"
    New-Item -Path $ir_evtx_path -Type Directory | Out-Null
    $evtx_files = Get-ChildItem -Path "C:\Windows\system32\winevt\logs\" -Filter *.evtx -ErrorAction SilentlyContinue

    foreach ($file in $evtx_files) {
        Copy-Item -Path $file.FullName -Destination $ir_evtx_path -ErrorAction SilentlyContinue
    }

    Write-Output "[ done ]"
}

function Get-Hidden {
    Write-Output "[+] Gathering hidden files and directories ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_HiddenFilesDirs.csv"

    Get-ChildItem C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
}

function Get-InstalledWindowsUpdates {
    Write-Output "[+] Gathering installed Windows Updates and Hotfixes ..."
    $outputFileHotFixes = Join-Path $Global:irPath "${ComputerName}_WinHotfixes.csv"
    $outputFileWinUpdates = Join-Path $Global:irPath "${ComputerName}_WinUpdates.csv"

    Get-HotFix | Select-Object InstalledOn, InstalledBy, HotFixID, Description | Export-Csv -NoTypeInformation -Path $outputFileHotFixes
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Search("IsInstalled=1").Updates | Select-Object Title | Export-Csv -NoTypeInformation -Path $outputFileWinUpdates
}

function Get-BrowserExtensions {
    Write-Output "[+] Gathering browser extensions for all users and major browsers ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_BrowserExtensions.csv"
    $chromePath = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions"
    $firefoxPath = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles"

    $extArray = @()

    # Chrome
    $chromeManifests = Get-ChildItem -Path $chromePath -Include manifest.json -Recurse -ErrorAction SilentlyContinue

    foreach ($manifest in $chromeManifests) {
        $info = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json
        $manifest.FullName -match 'users\\(.*?)\\appdata' | Out-Null

        if ($matches) {
            $username = $matches[1]
        }
        else {
            $username = "N/A"
        }

        $extObject = New-Object -TypeName psobject
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Application -Value "Google Chrome"
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Username -Value $username
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name ExtensionName -Value $info.name
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Description -Value ($info.description -replace "`n", " ")
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Version -Value $info.version
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Path -Value $manifest.FullName

        $extArray += $extObject
    }

    # Firefox
    $firefoxProfiles = Get-ChildItem -Path $firefoxPath -Include addons.json -Recurse -ErrorAction SilentlyContinue

    foreach ($profile in $firefoxProfiles) {
        $info = Get-Content -Path $profile.FullName -Raw | ConvertFrom-Json
        $profile.FullName -match 'users\\(.*?)\\appdata' | Out-Null

        if ($matches) {
            $username = $matches[1]
        }
        else {
            $username = "N/A"
        }

        foreach ($addon in $info.addons) {
            $extObject = New-Object -TypeName psobject
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Application -Value "Firefox"
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Username -Value $username
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name ExtensionName -Value $addon.name
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Description -Value ($addon.description -replace "`n", " ")
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Version -Value $addon.version
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Path -Value $profile.FullName

            $extArray += $extObject
        }
    }

    $extArray | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
}

function Get-KrbSessions {
    Write-Output "[+] Gathering klist sessions ..."
    $outputFile = Join-Path $Global:irPath "${ComputerName}_klistsessions.csv"

    $sessions = klist sessions
    $klistArray = @()

    foreach ($session in $sessions) {
        $listNumber = ($session.split(' ')[0] -replace "`n", "")
        $sessionNumber = ($session.split(' ')[2] -replace "`n", "")
        $logonId = ($session.split(' ')[3] -replace "0:", "" -replace "`n", "")
        $identity = ($session.split(' ')[4] -replace "`n", "")
        $authType = ($session.split(' ')[5] -replace "`n", "")

        $klistObject = New-Object -TypeName psobject
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name ListNumber -Value $listNumber
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name SessionNumber -Value $sessionNumber
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name LogonId -Value $logonId
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name Identity -Value $identity
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name AuthType -Value $authType

        $klistArray += $klistObject
    }

    $klistArray | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
    Write-Output "[*] Session List"
    $sessions
    Write-Output ""
    Write-Output "Kerberos sessions successfully obtained. To view further details run: klist -li [logon_id]"
}

function Get-Recall {
    param (
        [string]$FromDate = $null,
        [string]$ToDate = $null,
        [string]$SearchTerm = $null
    )
	
    Write-Output "[+] Gathering contents from Microsoft Recall ..."

    function Modify-Permissions {
        param (
            [string]$Path
        )
        try {
            icacls $Path /grant "$($env:USERNAME):(OI)(CI)F" /T /C /Q | Out-Null
            Write-Host "Permissions modified for $Path and all its subdirectories and files" -ForegroundColor Green
        } catch {
            Write-Host "Failed to modify permissions for $Path: $($_)" -ForegroundColor Red
        }
    }

    $username = $env:USERNAME
    $basePath = "C:\Users\$username\AppData\Local\CoreAIPlatform.00\UKP"

    if (-Not (Test-Path $basePath)) {
        Write-Host "[!] Base path does not exist."
        return
    }

    Modify-Permissions -Path $basePath

    $guidFolder = Get-ChildItem -Path $basePath -Directory | Select-Object -First 1

    if (-Not $guidFolder) {
        Write-Host "[!] Could not find the GUID folder."
        return
    }

    $guidFolderPath = $guidFolder.FullName
    Write-Host "[+] Recall folder found: $guidFolderPath"

    $dbPath = Join-Path -Path $guidFolderPath -ChildPath "ukg.db"
    $imageStorePath = Join-Path -Path $guidFolderPath -ChildPath "ImageStore"

    if (-Not (Test-Path $dbPath) -or -Not (Test-Path $imageStorePath)) {
        Write-Host "[!] Windows Recall feature not found. Nothing to extract."
        return
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd-HH-mm")
    $extractionFolder = Join-Path -Path $Global:irPath -ChildPath "${timestamp}_Recall_Extraction"
    New-Item -ItemType Directory -Path $extractionFolder -Force | Out-Null
    Write-Host "`nCreating extraction folder: $extractionFolder`n"

    Copy-Item -Path $dbPath -Destination $extractionFolder
    Copy-Item -Path $imageStorePath -Destination (Join-Path -Path $extractionFolder -ChildPath "ImageStore") -Recurse -Force

    Get-ChildItem -Path (Join-Path -Path $extractionFolder -ChildPath "ImageStore") | ForEach-Object {
        $imagePath = $_.FullName
        if (-Not ($imagePath -match "\.jpg$")) {
            Rename-Item -Path $imagePath -NewName ($imagePath + ".jpg")
        }
    }

    $dbExtractionPath = Join-Path -Path $extractionFolder -ChildPath "ukg.db"
    try {
        $conn = [System.Data.SQLite.SQLiteConnection]::new("Data Source=$dbExtractionPath")
        $conn.Open()
    } catch {
        Write-Host "[!] Failed to open SQLite database: $($_)" -ForegroundColor Red
        return
    }

    $cmd = $conn.CreateCommand()

    $fromDateTimestamp = if ($FromDate) { [int](([DateTime]::ParseExact($FromDate, "yyyy-MM-dd", $null).ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds * 1000) } else { $null }
    $toDateTimestamp = if ($ToDate) { [int](([DateTime]::ParseExact($ToDate, "yyyy-MM-dd", $null).AddDays(1).ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds * 1000) } else { $null }

    $query = "SELECT WindowTitle, TimeStamp, ImageToken FROM WindowCapture WHERE (WindowTitle IS NOT NULL OR ImageToken IS NOT NULL)"
    $cmd.CommandText = $query
    $reader = $cmd.ExecuteReader()

    $capturedWindows = @()
    $imagesTaken = @()

    while ($reader.Read()) {
        $windowTitle = $reader["WindowTitle"]
        $timestamp = [int]$reader["TimeStamp"]
        $imageToken = $reader["ImageToken"]
        $readableTimestamp = [datetime]'1970-01-01'.AddMilliseconds($timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")

        if (($null -eq $fromDateTimestamp -or $fromDateTimestamp -le $timestamp) -and ($null -eq $toDateTimestamp -or $timestamp -lt $toDateTimestamp)) {
            if ($windowTitle) {
                $capturedWindows += "[$readableTimestamp] $windowTitle"
            }
            if ($imageToken) {
                $imagesTaken += "[$readableTimestamp] $imageToken"
            }
        }
    }

    $reader.Close()
    $conn.Close()

    $capturedWindowsCount = $capturedWindows.Count
    $imagesTakenCount = $imagesTaken.Count
    $output = @(
        "Captured Windows: $capturedWindowsCount",
        "Images Taken: $imagesTakenCount"
    )

    if ($SearchTerm) {
        try {
            $conn.Open()
            $searchQuery = "SELECT c1, c2 FROM WindowCaptureTextIndex_content WHERE c1 LIKE '%$SearchTerm%' OR c2 LIKE '%$SearchTerm%'"
            $cmd.CommandText = $searchQuery
            $searchReader = $cmd.ExecuteReader()

            $searchResults = @()
            while ($searchReader.Read()) {
                $searchResults += "c1: $($searchReader["c1"]), c2: $($searchReader["c2"])"
            }

            $searchResultsCount = $searchResults.Count
            $output += "Search results for '$SearchTerm': $searchResultsCount"
            $searchReader.Close()
        } catch {
            Write-Host "[!] Failed to execute search query: $($_)" -ForegroundColor Red
        } finally {
            $conn.Close()
        }
    }

    $recallpath = Join-Path -Path $extractionFolder -ChildPath "Recall.txt"
    Set-Content -Path $recallpath -Value "Captured Windows:`n$($capturedWindows -join "`n")`n`nImages Taken:`n$($imagesTaken -join "`n")`n"

    if ($SearchTerm) {
        Add-Content -Path $recallpath -Value "`nSearch Results:`n$($searchResults -join "`n")"
    }

    $output | ForEach-Object { Write-Host $_ }

    Write-Host "`nSummary of the extraction is available in the file:"
    Write-Host "$($recallpath)" -ForegroundColor Yellow
    Write-Host "`nFull extraction folder path:"
    Write-Host "$($extractionFolder)" -ForegroundColor Yellow
    Write-Output "[ done ]"
}

# [END] Forensics - Miscellaneous

$outputLog = "C:\Windows\Temp\IR\0 - Kestrel_Output.txt"
Start-Transcript -Path $outputLog -Force

# Function to invoke all modules at once
function Invoke-AllIRModules {
    Write-Output "[+] Running all IR modules ..."
    # [Malware - Persistence]
    Get-AutoRuns
    Get-Services
    Get-InstalledSoftware
    Get-DNSCache
    Get-RunningProcesses

    # [Forensics - Evidence of Execution]
    Get-Prefetch
    Get-PEFiles
    Get-JumpLists
    Get-SRUM

    # [Forensics - Deleted Items & File Existence]
    Get-RecycleBin
    Get-Thumbcache
    Get-WordWheelQuery
    Get-OfficeRecentFiles

    # [Forensics - Files & Folders Opened]
    Get-LnkFiles
    Get-OfficeRecentFiles

    # [Malware - Miscellaneous]
    Get-OfficeFiles
    Get-ScriptFiles

    # [Forensics - Miscellaneous]
    Get-EventLogs
    Get-Hidden
    Get-InstalledWindowsUpdates
    Get-BrowserExtensions
    Get-KrbSessions
	Get-Recall
}

if ($module) {
    if (-Not (Test-Path $folder)) {
        New-Item -Path $folder -Type Directory -Force | Out-Null
    }
    $Global:irPath = $folder

    switch ($module.ToLower()) {
        all { Invoke-AllIRModules }

        # [Malware - Persistence]
        autoruns { Get-AutoRuns }
        services { Get-Services }
        installedsoftware { Get-InstalledSoftware }
        dnscache { Get-DNSCache }
        runningprocesses { Get-RunningProcesses }

        # [Forensics - Evidence of Execution]
        prefetch { Get-Prefetch }
        pefiles { Get-PEFiles }
        recyclebin { Get-RecycleBin }
        jumplists { Get-JumpLists }
        srum { Get-SRUM }

        # [Forensics - Deleted Items & File Existence]
        thumbcache { Get-Thumbcache }
        wordwheelquery { Get-WordWheelQuery }
        usertypedpaths { Get-UserTypedPaths }

        # [Forensics - Files & Folders Opened]
        lnkfiles { Get-LnkFiles }
        officerecentfiles { Get-OfficeRecentFiles }

        # [Malware - Miscellaneous]
        officefiles { Get-OfficeFiles }
        scriptfiles { Get-ScriptFiles }

        # [Forensics - Miscellaneous]
        eventlogs { Get-EventLogs }
        hiddenfilesdirs { Get-Hidden }
        windowsupdates { Get-InstalledWindowsUpdates }
        browserextensions { Get-BrowserExtensions }
        krbsessions { Get-KrbSessions }
		recall { Get-Recall } 

        # Usage instructions
        help { usage }
        default { usage }
    }
} else {
    usage
    exit
}

# Stop the transcript and inform the user
Stop-Transcript
Write-Host "IR artifacts saved in $Global:irPath" -ForegroundColor Yellow -BackgroundColor Black
Write-Host "See the console output in $outputLog" -ForegroundColor Yellow -BackgroundColor Black

# Compress the IR folder into a ZIP file
Write-Output "[+] Compressing the IR folder into IR.zip ..."
$zipFilePath = Join-Path $Global:irPath "IR.zip"

if (Test-Path $zipFilePath) {
    Remove-Item -Path $zipFilePath -Force
}

try {
    Compress-Archive -Path $Global:irPath\* -DestinationPath $zipFilePath
    Write-Output "[ done ]"
    Write-Host "IR folder compressed to $zipFilePath" -ForegroundColor Yellow -BackgroundColor Black
} catch {
    Write-Output "[!] Failed to compress IR folder: $($_)"
}
