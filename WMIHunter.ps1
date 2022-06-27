### Windows Management Instrumentation Hunter
# github.com/joeavanzato/wmih
# Utilize WMI via PowerShell to retrieve and filter information from remote hosts for IR/Hunting purposes.
# Requires execution as user account that has permissions to query WMI remotely - by default this is only Local Admins but other domain users can be added

### USAGE
# .\wmih.ps1 - Will execute with default parameters (16 threads, all data collection enabled, ADSI Searcher to find Computer Users, No IOC filtering)
# .\wmih.ps1 -max_threads 20 - Launch with default parameters but increase or decrease the max threads used in the Runspace CreateRunspacePool
# .\wmih.ps1 -data_types processes,connections - Only retrieve  running processes and network connections
# .\wmih.ps1 -computers_file 'C:\file.txt' - Supply a line-delimited list of hostnames for use in querying rather than using an ADSI searcher
# .\wmih.ps1 -ips 10.10.10.10,192.168.0.1 - Supply an array of IP Addresses that will be used to filter for specific Remote Connections


### AVAILABLE DATA TYPES
# processes - Retrieves information about running processes.
# connections - Retrieves information about TCP connections.
# services - Retrieves information about installed services.
# software - Retrieves information about installed software.
# tasks - Retrieved information about scheduled tasks.
# logons - Retrieves information about currently logged-on users.
# remote_cons - Retrieves information about active network connections.
# serv_sessions - Retrieves information about sessions established from remote computers.
# serv_connections - Retrieves information about remote connections to local shared resources.
# network_shares - Retrieves information about shared resources.
# startups - Retrieves information about commands run automatically at user logon.
# sys_accounts - Retrieves information about system accounts.




param(
     [Parameter()]
     [int]$max_threads,

     [Parameter()]
     [array]$data_types,

     [Parameter()]
     [string]$computers_file,

     [Parameter()]
     [array]$ip_addresses,

     [Parameter()]
     [array]$process_names,

     [Parameter()]
     [array]$service_names,

     [Parameter()]
     [switch] $gui
 )

if ($max_threads) {
} else {
    $max_threads = 16
}
if ($data_types) {
} else {
    $data_types = @('processes','connections','services','software','tasks','logons','remote_cons','serv_sessions','serv_connections','network_shares','startups','sys_accounts')
}


$StartTime = Get-Date


# $Configuration object is passed to all threads to allow access to variables from within the new thread
# This variable stores the locations of CSVs for each query-type as well as the count of computers that have already been scanned
$CurrentDir = Get-Location
$Configuration = [hashtable]::Synchronized(@{})
$Configuration.ProcessPath = "$CurrentDir\running_processes.csv"
$Configuration.NetworkPath = "$CurrentDir\network_connections.csv"
$Configuration.ServicePath = "$CurrentDir\installed_services.csv"
$Configuration.TaskPath = "$CurrentDir\scheduled_tasks.csv"
$Configuration.ProductPath = "$CurrentDir\installed_software.csv"
$Configuration.LogonUsers = "$CurrentDir\loggedon_users.csv"
$Configuration.RemoteCons = "$CurrentDir\remote_netcons.csv"
$Configuration.ServerSessions = "$CurrentDir\server_sessions.csv"
$Configuration.ServerConnections = "$CurrentDir\server_connections.csv"
$Configuration.NetworkShares = "$CurrentDir\network_shares.csv"
$Configuration.StartupItems = "$CurrentDir\startup_items.csv"
$Configuration.SystemAccounts = "$CurrentDir\system_accounts.csv"
$Configuration.FinishedCount = 0

# $query_table is a hash table (dictionary) which allows for dynamic building of the threaded script block
# This table is referenced in arguments to data_type and provides the appropriate script block for each piece of data
$query_table = @{
processes='Get-WmiObject Win32_Process -ComputerName $Computer -ErrorAction SilentlyContinue | Select-Object PSComputerName,ProcessId,ParentProcessId,ProcessName,ExecutablePath,CommandLine | Export-CSV -NoTypeInformation -Path $Configuration.ProcessPath -Append;';
connections='Get-WmiObject -Namespace ROOT\StandardCIMV2 -Class MSFT_NetTCPConnection -ComputerName $Computer -ErrorAction SilentlyContinue | Select-Object LocalAddress, RemoteAddress, LocalPort, RemotePort, OwningProcess, PSComputerName, State | Export-CSV -NoTypeInformation -Path $Configuration.NetworkPath -Append;';
services='Get-WmiObject Win32_Service -ComputerName $Computer -ErrorAction SilentlyContinue | Select PSComputerName,Name,StartMode,ServiceType,PathName,Caption,DisplayName,Description,Started,StartName,State | Export-CSV -NoTypeInformation -Path $Configuration.ServicePath -Append;';
software='Get-WmiObject  -Class Win32_Product -ComputerName $Computer -ErrorAction SilentlyContinue | Select Name,Vendor,Version,Caption,PSComputerName | Export-CSV -NoTypeInformation -Path $Configuration.ProductPath -Append;';
tasks='Get-WmiObject -Namespace Root\Microsoft\Windows\TaskScheduler -Class MSFT_ScheduledTask -ComputerName $Computer -ErrorAction SilentlyContinue | Select Author,Date,Description,State,TaskName,TaskPath,PSComputerName | Export-CSV -NoTypeInformation -Path $Configuration.TaskPath -Append;';
logons = 'Get-WmiObject Win32_LoggedOnUser -ComputerName $Computer -ErrorAction SilentlyContinue  | Select -Property PSComputerName, Antecedent | Select-String -AllMatches -Pattern "(.*)Domain=`"(.*)`",Name=`"(.*)`"" | ForEach-Object {$_.Matches} | Foreach-Object {New-Object PSObject -Property @{Domain=$_.Groups[2].Value;User=$_.Groups[3].Value;PSComputerName=$Computer}}| Export-CSV -NoTypeInformation -Path $Configuration.LogonUsers -Append;';
remote_cons = 'Get-WmiObject Win32_NetworkConnection -ComputerName $Computer -ErrorAction SilentlyContinue | Select -Property PSComputerName, ConnectionState, Persistent, LocalName, RemoteName,UserName | Export-CSV -NoTypeInformation -Path $Configuration.RemoteCons -Append;';
serv_sessions = 'Get-WmiObject Win32_ServerSession -ComputerName $Computer -ErrorAction SilentlyContinue | Select -Property PSComputerName, ActiveTime, Caption, ClientType, ComputerName, IdleTime, ResourcesOpened, SessionType, Status, UserName | Export-CSV -NoTypeInformation -Path $Configuration.ServerSessions -Append;';
serv_connections = 'Get-WmiObject Win32_ServerConnection -ComputerName $Computer -ErrorAction SilentlyContinue | Select -Property PSComputerName, ActiveTime, ComputerName, ConnectionID, NumberOfFiles, NumberOfUsers, ShareName, UserName | Export-CSV -NoTypeInformation -Path $Configuration.ServerConnections -Append;';
network_shares = 'Get-WmiObject Win32_Share -ComputerName $Computer -ErrorAction SilentlyContinue | Select -Property PSComputerName, Status, Type, Name, Caption, Description, Path | Export-CSV -NoTypeInformation -Path $Configuration.NetworkShares -Append;';
startups = 'Get-WmiObject Win32_StartupCommand -ComputerName $Computer -ErrorAction SilentlyContinue | Select -Property PSComputerName, Caption, Command, Description, Location, Name, User | Export-CSV -NoTypeInformation -Path $Configuration.StartupItems -Append;';
sys_accounts = 'Get-WmiObject Win32_SystemAccount -ErrorAction SilentlyContinue | Select -Property PSComputerName, Status, SIDType, Name, Domain,LocalAccount, SID | Export-CSV -NoTypeInformation -Path $Configuration.SystemAccounts -Append;'
}



function GetDomainComputers {
    # Identify and Retrieve Enabled Computer Users in Current AD Environment
    $DirectorySearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
    # This is an LDAP Query with a Bit Filter for only Enabled accounts - see https://ldapwiki.com/wiki/Filtering%20for%20Bit%20Fields
    $DirectorySearcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    # Max Results Returned - adjust appropriately if you have more than 100k Computer Accounts
    $DirectorySearcher.PageSize = 100000
    $DomainComputers = ($DirectorySearcher.Findall())
    [array]$ComputersArray = @()
    ForEach ($PC in $DomainComputers){
        $ComputersArray += $PC.Properties.dnshostname
    }
    return $ComputersArray
}


function ParseDataRequests ([array] $data_string){
    # Parse through the input array to identify data-types and dynamically build the script block component
    $ScriptBlock = {
    param($Computer, $Configuration);
    }
    ForEach ($type in $data_string) {
        Write-Host "Checking for Query using Key: "$type
        $data_value = $query_table[$type]
        if ($data_value){
            # If we find a corresponding value in the hashtable, add it to the script-in-progress
            Write-Host "Found WMI Query"
            #Write-Host $data_value
            $ScriptBlock = [ScriptBlock]::Create($ScriptBlock.ToString() + $data_value.ToString())
        }
        else {
            Write-Host "Could not find WMI query for key: "$type
        }
    }
    # Finalize the script with any closing statements (counter for completed hosts)
    $ScriptBlock = [ScriptBlock]::Create($ScriptBlock.ToString() + '$Configuration.FinishedCount ++;')
    return $ScriptBlock
}


function LoopAndStartJobs ([array] $Computers, [string] $script){
    # Loops through computers array, sets up Runspace Pool, Adds Jobs and Waits for Completion
    # Creating ScriptBlock from passed string
    $ScriptBlock = [ScriptBlock]::Create($script)

    # Setting up RunspacePool
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $max_threads, $SessionState, $Host)
    $RunspacePool.Open()

    $ComputerCount = $Computers.Count
    Write-Host "Identified Devices:" $ComputerCount
    $Jobs = New-Object System.Collections.ArrayList

    $Computers | ForEach {
        $PowerShell = [powershell]::Create()
	    $PowerShell.RunspacePool = $RunspacePool
        $CurrentComputer = $_
        $PowerShell.AddScript($ScriptBlock).AddArgument($CurrentComputer).AddArgument($Configuration) | Out-Null
        $Job = New-Object -TypeName PSObject -Property @{
            Runspace = $PowerShell.BeginInvoke()
            Powershell = $PowerShell
        }
        $Jobs.Add($Job) | Out-Null
    }

    while ($Jobs.Runspace.IsCompleted -contains $false) {
        if ($using_gui){
            [System.Windows.Forms.Application]::DoEvents()
            $progress_bar.Value = $Configuration.FinishedCount/$ComputerCount*100
            $x = $Configuration.FinishedCount
            $progress_label.Text = "Progress: $x/$ComputerCount"
        } else {
            Write-Progress -Activity "Waiting for Jobs to Finish..." -Status "Progress:" -PercentComplete ($Configuration.FinishedCount/$ComputerCount*100)
            $x = $Configuration.FinishedCount
            Write-Host (Get-date).Tostring() "Still running...[$x/$ComputerCount]"
        }
	    Sleep -Milliseconds 200
    }
    if ($using_gui){
            [System.Windows.Forms.Application]::DoEvents()
            $progress_bar.Value = 100
            $x = $Configuration.FinishedCount
            $progress_label.Text = "Progress: Complete - $x Devices Queries"
    }
    $End = Get-Date
    $TimeTaken = $End - $StartTime
    Write-Host "Total Time Taken: "$TimeTaken
    Write-Host "Devices Scanned: "$ComputerCount
}

function Main {
        if ($gui) {
        $Global:using_gui = $true
        ### GUI SETUP ###
        Add-Type -AssemblyName System.Windows.Forms
        $bold_font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
        $GUI = New-Object System.Windows.Forms.Form
        $GUI.ClientSize = '400,400'
        $GUI.text = 'WMIHunter'
        $GUI.BackColor = "#ffffff"

        $data_title = New-Object System.Windows.Forms.Label
        $data_title.text = "Data to Collect"
        $data_title.width = 120
        $data_title.height = 20
        $data_title.Location = New-Object System.Drawing.Point(20, 20)
        $data_title.Font = $bold_font
        $GUI.controls.Add($data_title)

        $thread_label = New-Object System.Windows.Forms.Label
        $thread_label.text = "Max Threads"
        $thread_label.width = 120
        $thread_label.height = 20
        $thread_label.Location = New-Object System.Drawing.Point(250, 60)
        $thread_label.Font = $bold_font
        $GUI.controls.Add($thread_label)


        $thread_value = New-Object System.Windows.Forms.TextBox
        $thread_value.text = 16
        $thread_value.width = 120
        $thread_value.height = 20
        $thread_value.Location = New-Object System.Drawing.Point(250, 80)
        $GUI.controls.Add($thread_value)

        $start_button = New-Object System.Windows.Forms.Button
        $start_button.BackColor = "#a4ba67"
        $start_button.text = "Start"
        $start_button.width = 90
        $start_button.height = 30
        $start_button.Location = New-Object System.Drawing.Point(150, 300)
        $start_button.Font = "Microsoft Sans Serif, 10"
        $start_button.ForeColor = "#ffffff"
        $GUI.controls.Add($start_button)

        $Global:progress_bar = New-Object System.Windows.Forms.ProgressBar
        $progress_bar.Width = 300
        $progress_bar.Height = 10
        $progress_bar.Location = New-Object System.Drawing.Point(50, 350)
        $GUI.controls.Add($progress_bar)

        $Global:progress_label = New-Object System.Windows.Forms.Label
        $progress_label.Width = 150
        $progress_label.Height = 20
        $progress_label.Location = New-Object System.Drawing.Point(50, 370)
        $progress_label.text = 'Progress:'
        $GUI.controls.Add($progress_label)

        $processes_check = New-Object System.Windows.Forms.CheckBox
        $processes_check.text = "Running Processes"
        $processes_check.Location = New-Object System.Drawing.Point(20, 40)
        $processes_check.Width = 150
        $processes_check.Checked = $true
        $processes_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($processes_check, "Query all Active Processes")
        })
        $GUI.controls.Add($processes_check)

        $netcons_check = New-Object System.Windows.Forms.CheckBox
        $netcons_check.text = "Network Connections"
        $netcons_check.Location = New-Object System.Drawing.Point(20, 60)
        $netcons_check.Width = 150
        $netcons_check.Checked = $true
        $netcons_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($netcons_check, "Query all Network Connections (TCP)")
        })

        $GUI.controls.Add($netcons_check)

        $services_check = New-Object System.Windows.Forms.CheckBox
        $services_check.text = "Installed Services"
        $services_check.Location = New-Object System.Drawing.Point(20, 80)
        $services_check.Width = 150
        $services_check.Checked = $true
        $services_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($services_check, "Query all Installed Windows Services")
        })
        $GUI.controls.Add($services_check)

        $software_check = New-Object System.Windows.Forms.CheckBox
        $software_check.text = "Installed Software"
        $software_check.Location = New-Object System.Drawing.Point(20, 100)
        $software_check.Width = 150
        $software_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($software_check, "Query all Installed Software/Applications")
        })
        $GUI.controls.Add($software_check)

        $task_check = New-Object System.Windows.Forms.CheckBox
        $task_check.text = "Scheduled Tasks"
        $task_check.Location = New-Object System.Drawing.Point(20, 120)
        $task_check.Width = 150
        $task_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($task_check, "Query all Configured Scheduled Tasks")
        })
        $GUI.controls.Add($task_check)

        $session_check = New-Object System.Windows.Forms.CheckBox
        $session_check.text = "User Sessions"
        $session_check.Location = New-Object System.Drawing.Point(20, 140)
        $session_check.Width = 150
        $session_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($session_check, "Query all Active User Sessions")
        })
        $GUI.controls.Add($session_check)

        $remcons_check = New-Object System.Windows.Forms.CheckBox
        $remcons_check.text = "Remote Connections"
        $remcons_check.Location = New-Object System.Drawing.Point(20, 160)
        $remcons_check.Width = 150
        $remcons_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($remcons_check, "Query all Active User Sessions")
        })
        $GUI.controls.Add($remcons_check)

        $servses_check = New-Object System.Windows.Forms.CheckBox
        $servses_check.text = "Server Sessions"
        $servses_check.Location = New-Object System.Drawing.Point(20, 180)
        $servses_check.Width = 150
        $servses_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($servses_check, "Query all Local Sessions established with users on Remote Computers")
        })
        $GUI.controls.Add($servses_check)

        $servcon_check = New-Object System.Windows.Forms.CheckBox
        $servcon_check.text = "Server Connections"
        $servcon_check.Location = New-Object System.Drawing.Point(20, 200)
        $servcon_check.Width = 150
        $servcon_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($servcon_check, "Query all Remote Connections to Local Shared Resources")
        })
        $GUI.controls.Add($servcon_check)

        $share_check = New-Object System.Windows.Forms.CheckBox
        $share_check.text = "Network Shares"
        $share_check.Location = New-Object System.Drawing.Point(20, 220)
        $share_check.Width = 150
        $share_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($share_check, "Query all Available Shared Resources (Disk Drivs, Printers, IPC, etc)")
        })
        $GUI.controls.Add($share_check)

        $startup_check = New-Object System.Windows.Forms.CheckBox
        $startup_check.text = "Startup Commands"
        $startup_check.Location = New-Object System.Drawing.Point(20, 240)
        $startup_check.Width = 150
        $startup_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($startup_check, "Query all Commands run Automatically at User Login")
        })
        $GUI.controls.Add($startup_check)

        $sysacc_check = New-Object System.Windows.Forms.CheckBox
        $sysacc_check.text = "System Accounts"
        $sysacc_check.Location = New-Object System.Drawing.Point(20, 260)
        $sysacc_check.Width = 150
        $sysacc_check.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($sysacc_check, "Query all System Accounts - used for internal logon activity within Windows")
        })
        $GUI.controls.Add($sysacc_check)

        $comp_search = New-Object System.Windows.Forms.CheckBox
        $comp_search.text = "Query AD for Computers"
        $comp_search.Location = New-Object System.Drawing.Point(250, 260)
        $comp_search.Width = 150
        $comp_search.Checked = $true
        $comp_search.Add_MouseHover({
            $tooltip = New-Object System.Windows.Forms.ToolTip
            $tooltip.SetToolTip($comp_search, "Query AD via LDAP for Enabled Computer Accounts")
        })
        $GUI.controls.Add($comp_search)

        $file_button = New-Object System.Windows.Forms.Button
        $file_button.text = "Computer List"
        $file_button.width = 100
        $file_button.height = 20
        $file_button.Location = New-Object System.Drawing.Point(250, 20)
        $file_button.Font = "Microsoft Sans Serif, 10"
        $GUI.controls.Add($file_button)

        $file_button.Add_Click({
            $ComputerFileSelector = New-Object System.Windows.Forms.OpenFileDialog
            $ComputerFileSelector.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $ComputerFileSelector.Filter = "TXT Files (*.txt) | *.txt"
            $null = $ComputerFileSelector.ShowDialog()
            $Global:File = $ComputerFileSelector.FileName
            $comp_search.Checked = $false
        })

        $start_button.Add_Click({
            $start_button.Enabled = $false
            $max_threads = [int]$thread_value.text
            Write-Host "Max Threads:"$max_threads
            if ($comp_search.CheckState -eq 'Checked') {
                $Computers = GetDomainComputers
            } else {
                Write-Host $File
                $Computers = Get-Content $File
            }
            $data_types = @()
            if ($processes_check.CheckState -eq 'Checked'){
                $data_types += 'processes'
            }
            if ($netcons_check.CheckState -eq 'Checked'){
                $data_types += 'connections'
            }
            if ($services_check.CheckState -eq 'Checked'){
                $data_types += 'services'
            }
            if ($software_check.CheckState -eq 'Checked'){
                $data_types += 'software'
            }
            if ($task_check.CheckState -eq 'Checked'){
                $data_types += 'tasks'
            }
            if ($session_check.CheckState -eq 'Checked'){
                $data_types += 'logons'
            }
            if ($remcons_check.CheckState -eq 'Checked'){
                $data_types += 'remote_cons'
            }
            if ($servses_check.CheckState -eq 'Checked'){
                $data_types += 'serv_sessions'
            }
            if ($servcon_check.CheckState -eq 'Checked'){
                $data_types += 'serv_connections'
            }
            if ($share_check.CheckState -eq 'Checked'){
                $data_types += 'network_shares'
            }
            if ($startup_check.CheckState -eq 'Checked'){
                $data_types += 'startups'
            }
            if ($sysacc_check.CheckState -eq 'Checked'){
                $data_types += 'sys_accounts'
            }
            $script = ParseDataRequests($data_types)
            LoopAndStartJobs $Computers $script.ToString()
            $start_button.Enabled = $true

        })

        [void]$GUI.ShowDialog()

        } else {
            Write-Host "Skipping GUI"

            $script = ParseDataRequests($data_types)
            if ($computers_file) {
                $Computers = Get-Content $computers_file
            } else {
                $Computers = GetDomainComputers
            }
            LoopAndStartJobs $Computers $script.ToString()
        }

}

Main