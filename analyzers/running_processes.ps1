# TODO - Break into Functions/Refactor


param(
     [Parameter()]
     [array]$evidence_array,
     [Parameter()]
     [string]$evidence_dir
 )

function LoadToArray ([string]$name) {
    #Load File from Evidence Dir into ArrayList
    $data_path = "$evidence_dir\$name"
    $array = New-Object System.Collections.ArrayList
    $data = @(Import-CSV -Path "$data_path")
    $array.AddRange($data)
    return [System.Collections.ArrayList]$array
}


Add-Type -AssemblyName System.Windows.Forms
$bold_font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
$NC = New-Object System.Windows.Forms.Form
$NC.ClientSize = '1600,800'
$NC.text = 'WMIH - Running Process Analyzer'
$NC.BackColor = "#ffffff"

# Build table if we fine network_connections.csv in evidence array

# We have to approach this differently because HOSTNAME_PID won't work as a key since a single PID can have multiple connections open - what we can do is append each data to an array and simply display array instead of individual items?
[hashtable]$conn_table = @{}
if ($evidence_array.Contains('TEST_network_connections.csv')) {
    Write-Host "Found network_connections.csv, Joining Network Connections on PID (This can take a few minutes)"
    $l = 0
    $o = 0
    Import-CSV "$evidence_dir\network_connections.csv" | ForEach-Object {
        $l++
        $temp_table = @($_.LocalPort, $_.RemotePort, $_.RemoteAddress, $_.State)
        $temp_key = $_.PSComputerName+$_.OwningProcess
        $conn_table.$temp_key = $temp_table
        if ($l -eq 1000){
            $l = 0
            $o += 1000
            Write-Host "Reading Network Connection Data - Done: "$o
        }
    }
    #[System.Collections.ArrayList]$connarray = LoadToArray('network_connections.csv')
    #ForEach ($conn in $connarray) {
    #    $temp_table = @($conn.LocalPort, $conn.RemotePort, $conn.RemoteAddress, $conn.State)
    #    $temp_key = $conn.PSComputerName+"_"+$conn.OwningProcess
    #    $conn_table.$temp_key = $temp_table
    #}
}

# Build the Data Table
$nc_table = New-Object System.Data.DataTable
#$StartTime = Get-Date
#Write-Host "Started Reading CSV: "$StartTime
#$nc_data = Import-CSV -Path "$evidence_dir\running_processes.csv"
#$FinishTime = Get-Date
#Write-Host "Finished Reading CSV: "$FinishTime
#Write-Host "Time Taken: "$FinishTime - $StartTime
#$nc_headers = $nc_data | Get-Member -MemberType NoteProperty
$nc_headers = @("ProcessId","ParentProcessId","ProcessName","ExecutablePath","CommandLine","PSComputerName")
$l = 0
ForEach ($header in $nc_headers) {
    $nc_table.Columns.Add($header) | Out-Null
}
if ($evidence_array.Contains('TEST_network_connections.csv')) {
    $nc_table.Columns.Add("LocalPort")  | Out-Null
    $nc_table.Columns.Add("RemotePort")  | Out-Null
    $nc_table.Columns.Add("RemoteAddress")  | Out-Null
    $nc_table.Columns.Add("State")  | Out-Null
    $nc_table.Columns.Add("StateTranslated")  | Out-Null
}

$state_translater = @{
"1" = "Closed";
"2" = "Listen";
"3" = "SynSent";
"4" = "SynReceivd";
"5" = "Established";
"6" = "FinWait1";
"7" = "FinWait2";
"8" = "CloseWait";
"9" = "Closing";
"10" = "LastAck";
"11" = "TimeWait";
"12" = "DeleteTCB"
}
$l = 0
$o = 0
Write-Host "Starting DataTable Population.."
$StartTime = Get-Date
Import-CSV -Path "$evidence_dir\running_processes.csv" | ForEach-Object {
    $new_row = $nc_table.NewRow()
    $row = $_
    $new_row.PSComputerName = $row.PSComputerName
    $new_row.ProcessId = $row.ProcessId
    $new_row.ParentProcessId = $row.ParentProcessId
    $new_row.ProcessName = $row.ProcessName
    $new_row.ExecutablePath = $row.ExecutablePath
    $new_row.CommandLine = $row.CommandLine
    $temp_key2 = $row.PSComputerName+$row.ProcessId


    #if ($conn_table.$temp_key2){
    #    $data = $conn_table.$temp_key2
    #    $new_row.LocalPort = $data[0]
    #    $new_row.RemotePort = $data[1]
    #    $new_row.RemoteAddress = $data[2]
    #    $new_row.State = $data[3]
    #    $new_row.StateTranslated = $state_translater[$data[3]]
    #} else {
    #    $new_row.LocalPort = "N/A"
    #    $new_row.RemotePort = "N/A"
    #    $new_row.RemoteAddress = "N/A"
    #    $new_row.State = "N/A"
    #    $new_row.StateTranslated = "N/A"
    #}
    if ($l -eq 1000){
        $l = 0
        $o += 1000
        Write-Host "Rows Added: "$o
    }
    $l++
    $nc_table.Rows.Add($new_row)
}
$FinishTime = Get-Date
$x= $FinishTime - $StartTime
Write-Host "Time Taken: "$x

$nc_table.CaseSensitive = $false

function ModFilter (){
    $filter_string = ""
    $i = 0
    $filter_table.GetEnumerator() | ForEach-Object {if ($i -eq 0){$filter_string += "("+$_.Value+")"} else {$filter_string += " AND ("+$_.Value+")"}$i++}
    Write-Host $filter_string
    $nc_table.DefaultView.RowFilter = $filter_string
}


$filter_list = [System.Collections.ArrayList]@()
$Global:filter_table = @{}

# Process Name Filter
$process_name_filter = New-Object System.Windows.Forms.TextBox
$process_name_filter.Width = 140
$process_name_filter.Height = 20
$process_name_filter.Text = "Process Name Filter"
$process_name_filter.Location = New-Object System.Drawing.Point (10, 640)
$filter_table.procfilter = "ProcessName LIKE '*'"
$process_name_filter.Add_TextChanged({
    $text = $process_name_filter.Text
    $filter_table.procfilter = "(ProcessName LIKE '$text' OR CommandLine LIKE '$text')"
    ModFilter
})
$process_name_filter.Anchor = 'Left, Bottom'
$NC.Controls.Add($process_name_filter)

# Custom Filter
$custom_filter = New-Object System.Windows.Forms.TextBox
$custom_filter.Width = 140
$custom_filter.Height = 20
$custom_filter.Text = "Custom Filter"
$custom_filter.Location = New-Object System.Drawing.Point (150, 640)
$custom_filter.Add_TextChanged({
    $filter_table.$customfilter = $custom_filter.Text
    $nc_table.DefaultView.RowFilter = $customfilter
})
$custom_filter.Anchor = 'Left, Bottom'
$NC.Controls.Add($custom_filter)

# Checkbox for Remote Administration Tools Process Name Filter
. ".\helpers\suspicious_process_keywords.ps1"
$rat_checkbox = New-Object System.Windows.Forms.CheckBox
$rat_checkbox.Text = "Common RATs"
$rat_checkbox.Width = 120
$rat_checkbox.Height = 20
$rat_checkbox.Location = New-Object System.Drawing.Point (10, 660)
$rat_checkbox.Anchor = 'Left, Bottom'
$NC.Controls.Add($rat_checkbox)
$rat_checkbox.add_CheckedChanged({
    if ($rat_checkbox.Checked){
        $Global:rat_filter = ""
        $rat_count = $suspicious_process_keywords_rat.Count
        $i = 1
        ForEach ($str in $suspicious_process_keywords_rat){
            $rat_filter += "ProcessName LIKE '%$str%' OR CommandLine LIKE '%$str%'"
            if ($i -ne $rat_count) {
                $rat_filter += " OR "
            }
            $i++
        }
        $filter_table.rat_filter = $rat_filter
        ModFilter
    }
    else {
        $filter_table.rat_filter = "ProcessName LIKE '%'"
        ModFilter
    }
})

# Checkbox for System Process Names
$system_procs_checkbox = New-Object System.Windows.Forms.CheckBox
$system_procs_checkbox.Text = "System Processes"
$system_procs_checkbox.Width = 120
$system_procs_checkbox.Height = 20
$system_procs_checkbox.Location = New-Object System.Drawing.Point (10, 680)
$system_procs_checkbox.Anchor = 'Left, Bottom'
$NC.Controls.Add($system_procs_checkbox)
$Global:system_filter = "ProcessName LIKE '%'"
$system_procs_checkbox.add_CheckedChanged({
    if ($system_procs_checkbox.Checked){
        $system_count = $windows_process_names.Count
        $i = 1
        ForEach ($str in $windows_process_names){
            $system_filter += "ProcessName LIKE '%$str%' OR CommandLine LIKE '%$str%'"
            if ($i -ne $system_count) {
                $system_filter += " OR "
            }
            $i++
        }
        $filter_table.system_filter = $system_filter
        ModFilter
    }
    else {
        $filter_table.system_filter = "ProcessName LIKE '%'"
        ModFilter
    }
})

# Remove Internal/Private/etc Addresses to only look at External
$private_ip_list = @(
    "10.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.20.*",
    "172.21.*",
    "172.22.*",
    "172.23.*",
    "172.24.*",
    "172.25.*",
    "172.26.*",
    "172.27.*",
    "172.28.*",
    "172.29.*",
    "172.30.*",
    "172.31.*",
    "192.168.*",
    "::",
    "::1",
    "0:0:0:0:0:0:0:1",
    "127.0.0.1",
    "0.0.0.0",
    "fc00:*",
    "fec0:*"
)
$private_address_checkbox = New-Object System.Windows.Forms.CheckBox
$private_address_checkbox.Text = "Remove Internal IPs"
$private_address_checkbox.Width = 200
$private_address_checkbox.Height = 20
$private_address_checkbox.Location = New-Object System.Drawing.Point (140, 680)
#$NC.Controls.Add($private_address_checkbox)
$Global:private_address_filter = "RemoteAddress LIKE '%'"
$private_address_checkbox.add_CheckedChanged({
    if ($private_address_checkbox.Checked){
        $private_address_filter = ""
        $private_address_count = $private_ip_list.Count
        $i = 1
        ForEach ($str in $private_ip_list){
            $private_address_filter += "NOT RemoteAddress LIKE '$str'"
            if ($i -ne $private_address_count){$private_address_filter += " AND "}
            $i++
        }
        $filter_table.private_address_filter = $private_address_filter
        ModFilter
    } else {
        $filter_table.private_address_filter = "RemoteAddress LIKE '%'"
        ModFilter
    }
})

. ".\helpers\system_binaries_with_locations.ps1"

# TODO - Case insensitive comparisons
$abnormal_bin_location_checkbox = New-Object System.Windows.Forms.CheckBox
$abnormal_bin_location_checkbox.Text = "Abnormal Binary Location"
$abnormal_bin_location_checkbox.Width = 200
$abnormal_bin_location_checkbox.Height = 20
$abnormal_bin_location_checkbox.Location = New-Object System.Drawing.Point (140, 660)
$abnormal_bin_location_checkbox.Anchor = 'Left, Bottom'
$NC.Controls.Add($abnormal_bin_location_checkbox)
$Global:abnormal_bin_location_checkbox = "ProcessName LIKE '%'"
$abnormal_bin_location_checkbox.add_CheckedChanged({
    if ($abnormal_bin_location_checkbox.Checked){
        $abnormal_bin_filter = ""
        $abnormal_bin_count = $system_binaries_with_locations.Count
        #Write-Host $abnormal_bin_count
        $i = 1
        $system_binaries_with_locations.GetEnumerator() | ForEach-Object {
            $temp_key = $_.Key
            #Write-Host $i
            # All items should be arrays
            $y = $_.Value.Count
            $z = 1
            $abnormal_bin_filter += "("
            ForEach ($item in $_.Value){
                $abnormal_bin_filter += "(ProcessName LIKE '$temp_key' AND NOT ExecutablePath LIKE '$item')"
                if ($z -ne $y){
                    $abnormal_bin_filter += " AND "
                }
                $z++
            }
            if ($i -ne $abnormal_bin_count){
                $abnormal_bin_filter += ") OR "
            }
            else {
                $abnormal_bin_filter += ")"
            }
            $i++
        }
        $filter_table.abnormal_bin_filter = $abnormal_bin_filter
        ModFilter
    } else {
        $filter_table.abnormal_bin_filter = "ProcessName LIKE '%'"
        ModFilter
    }
})

# Label for Filter Controls
$filter_label = New-Object System.Windows.Forms.Label
$filter_label.Width = 1000
$filter_label.Height = 20
$filter_label.Text = "Filter (Process Names or CommandLines) and (LocalAddress or RemoteAddress), State or enter Custom Filters such as `"PSComputerName LIKE 'COMPUTER*'`", %/* are wildcards"
$filter_label.Location = New-Object System.Drawing.Point (10,620)
$filter_label.Anchor = 'Left, Bottom'
$NC.Controls.Add($filter_label)


Write-Host "Loading DataGrid..."
#DataGrid GUI Element
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Width = 1500
$grid.Height = 600
$grid.DataBindings.DefaultDataSourceUpdateMode = 0
#$grid.HeaderForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
$grid.Name="Running Processes"
$grid.TabIndex = 0
$grid.Location = New-Object System.Drawing.Point (10,20)
#$grid.DataMember=""
$grid.DataSource=$nc_table
$grid.ColumnHeadersVisible = $true
$grid.AutoSize = $true
#$grid.AutoSizeColumnsMode = 'AllCells'
#$grid.AllowSorting = $true
$grid.ReadOnly = $true
$grid.Size = '1500, 600'
$grid.AutoSizeColumnsMode='Fill'
$grid.ScrollBars = 'Both'
$grid.Anchor = 'Left, Right, Top, Bottom'

#$grid.AllowUserToResizeColumns = $true

. ".\helpers\dataresize.ps1"
#$grid.Add_DatasourceChanged({AutoResizeColumns $grid})
#$grid.Add_VisibleChanged({AutoResizeColumns $grid})
$NC.Controls.Add($grid)

. ".\helpers\doublebuffer_grid.ps1"
Enable-DataGridViewDoubleBuffer $grid

. ".\helpers\console_manipulation.ps1"
#Hide-Console
Write-Host "Launching Window"
[void]$NC.ShowDialog()