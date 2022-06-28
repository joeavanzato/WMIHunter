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
$NC.text = 'WMIH - Network Connection Analyzer'
$NC.BackColor = "#ffffff"
[hashtable]$process_table = @{}
if ($evidence_array.Contains('running_processes.csv')) {
    Write-Host "Found running_processes.csv, Joining Network Connections on PID"
    $temp_path = "$evidence_dir\running_processes.csv"
    [System.Collections.ArrayList]$procarray = LoadToArray('running_processes.csv')
    ForEach ($process in $procarray) {
        $temp_table = @($process.ProcessName, $process.CommandLine, $process.ExecutablePath)
        $temp_key = $process.PSComputerName+"_"+$process.ProcessId
        $process_table.$temp_key = $temp_table
    }
}

# Build the Data Table
$nc_table = New-Object System.Data.DataTable
$nc_data = Import-CSV -Path "$evidence_dir\network_connections.csv"
$nc_headers = $nc_data | Get-Member -MemberType NoteProperty
ForEach ($header in $nc_headers) {
    $nc_table.Columns.Add($header.Name) | Out-Null
}

if ($evidence_array.Contains('running_processes.csv')) {
    $nc_table.Columns.Add("ProcessName")  | Out-Null
    $nc_table.Columns.Add("CommandLine")  | Out-Null
    $nc_table.Columns.Add("ExecutablePath")  | Out-Null
}

# Translate TCP State to English
# docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.tcpstate?view=net-6.0
# Anyone know what '100' is?
$nc_table.Columns.Add("StateTranslated")  | Out-Null
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

ForEach ($row in $nc_data) {
#"LocalAddress","RemoteAddress","LocalPort","RemotePort","OwningProcess","PSComputerName","State"
    $new_row = $nc_table.NewRow()
    $new_row.LocalAddress = $row.LocalAddress
    $new_row.RemoteAddress = $row.RemoteAddress
    $new_row.LocalPort = $row.LocalPort
    $new_row.RemotePort = $row.RemotePort
    $new_row.OwningProcess = $row.OwningProcess
    $new_row.PSComputerName = $row.PSComputerName
    $new_row.State = $row.State
    $temp_key2 = $row.PSComputerName+"_"+$row.OwningProcess
    if ($process_table.$temp_key2){
           $new_row.ProcessName = $process_table.$temp_key2[0]
           $new_row.CommandLine = $process_table.$temp_key2[1]
           $new_row.ExecutablePath = $process_table.$temp_key2[2]
    } else {
           $new_row.ProcessName = "N/A"
           $new_row.CommandLine = "N/A"
           $new_row.ExecutablePath = "N/A"
    }
    $state = $row.State
    $new_row.StateTranslated = $state_translater["$state"]
    $nc_table.Rows.Add($new_row)
}

# Process Name Filter
$process_name_filter = New-Object System.Windows.Forms.TextBox
$process_name_filter.Width = 140
$process_name_filter.Height = 20
$process_name_filter.Text = "Process Name Filter"
$process_name_filter.Location = New-Object System.Drawing.Point (10, 640)
$Global:procfilter = "ProcessName LIKE '*''"
$process_name_filter.Add_TextChanged({
$text = $process_name_filter.Text
$Global:procfilter = "(ProcessName LIKE '$text' OR CommandLine LIKE '$text')"
if ($ipfilter.Contains('LIKE') -or $statefilter.Contains('LIKE')) {
    $procfilter = $procfilter + " AND "+$ipfilter+ " AND "+$statefilter
}
$nc_table.DefaultView.RowFilter = $procfilter
})
$NC.Controls.Add($process_name_filter)

# IP Address Filter
$ipaddress_filter = New-Object System.Windows.Forms.TextBox
$ipaddress_filter.Width = 140
$ipaddress_filter.Height = 20
$ipaddress_filter.Text = "IP Address Filter"
$ipaddress_filter.Location = New-Object System.Drawing.Point (150, 640)
$Global:ipfilter = "LocalAddress LIKE '*'"
$ipaddress_filter.Add_TextChanged({
$text = $ipaddress_filter.Text
$Global:ipfilter = "(LocalAddress LIKE '$text' OR RemoteAddress LIKE '$text')"
if ($procfilter.Contains('LIKE') -or $statefilter.Contains('LIKE')) {
    $ipfilter = $ipfilter + " AND "+$procfilter+ " AND "+$statefilter
    Write-Host $ipfilter
}
$nc_table.DefaultView.RowFilter = $ipfilter
})
$NC.Controls.Add($ipaddress_filter)

# State Filter
$state_filter = New-Object System.Windows.Forms.TextBox
$state_filter.Width = 40
$state_filter.Height = 20
$state_filter.Text = "State"
$state_filter.Location = New-Object System.Drawing.Point (300, 640)
$Global:statefilter = "State LIKE '*'"
$state_filter.Add_TextChanged({
$text = $state_filter.Text
$Global:statefilter = "State LIKE '$text'"
if ($procfilter.Contains('LIKE') -or $ipfilter.Contains('LIKE')) {
    $statefilter = $statefilter + " AND "+$procfilter+ " AND "+$ipfilter
}
$nc_table.DefaultView.RowFilter = $statefilter
})
$NC.Controls.Add($state_filter)

# Custom Filter
$custom_filter = New-Object System.Windows.Forms.TextBox
$custom_filter.Width = 140
$custom_filter.Height = 20
$custom_filter.Text = "Custom Filter"
$custom_filter.Location = New-Object System.Drawing.Point (350, 640)
$Global:customfilter = ""
$custom_filter.Add_TextChanged({
$customfilter = $custom_filter.Text
$nc_table.DefaultView.RowFilter = $customfilter
})
$NC.Controls.Add($custom_filter)

# Checkbox for Remote Administration Tools Process Name Filter
. ".\helpers\suspicious_process_keywords.ps1"
$rat_checkbox = New-Object System.Windows.Forms.CheckBox
$rat_checkbox.Text = "Common RATs"
$rat_checkbox.Width = 200
$rat_checkbox.Height = 20
$rat_checkbox.Location = New-Object System.Drawing.Point (10, 660)
$NC.Controls.Add($rat_checkbox)
$rat_checkbox.add_CheckedChanged({
    if ($rat_checkbox.Checked){
        $rat_filter = ""
        $rat_count = $suspicious_process_keywords_rat.Count
        $i = 1
        ForEach ($str in $suspicious_process_keywords_rat){
            $rat_filter += "ProcessName LIKE '%$str%' OR CommandLine LIKE '%$str%'"
            if ($i -ne $rat_count) {
                $rat_filter += " OR "
            }
            $i++
        }
        $process_name_filter.Text = $rat_filter
        $nc_table.DefaultView.RowFilter = $rat_filter
    }
    else {
        $process_name_filter.Text = "*"
    }
})

# Checkbox for System Process Names
$system_procs_checkbox = New-Object System.Windows.Forms.CheckBox
$system_procs_checkbox.Text = "System Processes"
$system_procs_checkbox.Width = 200
$system_procs_checkbox.Height = 20
$system_procs_checkbox.Location = New-Object System.Drawing.Point (10, 680)
$NC.Controls.Add($system_procs_checkbox)
$system_procs_checkbox.add_CheckedChanged({
    if ($system_procs_checkbox.Checked){
        $system_filter = ""
        $system_count = $windows_process_names.Count
        $i = 1
        ForEach ($str in $windows_process_names){
            $system_filter += "ProcessName LIKE '%$str%' OR CommandLine LIKE '%$str%'"
            if ($i -ne $system_count) {
                $system_filter += " OR "
            }
            $i++
        }
        $process_name_filter.Text = $system_filter
        $nc_table.DefaultView.RowFilter = $system_filter
    }
    else {
        $process_name_filter.Text = "*"
    }
})

# Label for Filter Controls
$filter_label = New-Object System.Windows.Forms.Label
$filter_label.Width = 1000
$filter_label.Height = 20
$filter_label.Text = "Filter (Process Names or CommandLines) and (LocalAddress or RemoteAddress), State or enter Custom Filters such as `"PSComputerName LIKE 'COMPUTER*'`", %/* are wildcards"
$filter_label.Location = New-Object System.Drawing.Point (10,620)
$NC.Controls.Add($filter_label)



#DataGrid GUI Element
$grid = New-Object System.Windows.Forms.DataGrid
$grid.Width = 1500
$grid.Height = 600
$grid.DataBindings.DefaultDataSourceUpdateMode = 0
$grid.HeaderForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
$grid.Name="TCP Connections"
$grid.TabIndex = 0
$grid.Location = New-Object System.Drawing.Point (10,20)
$grid.DataMember=""
$grid.DataSource=$nc_table
$grid.ColumnHeadersVisible = $true
$grid.AutoSize = $true
$grid.AllowSorting = $true
$grid.ReadOnly = $true
. ".\helpers\dataresize.ps1"
$grid.Add_DatasourceChanged({AutoResizeColumns $grid})
$grid.Add_VisibleChanged({AutoResizeColumns $grid})
$NC.Controls.Add($grid)

. ".\helpers\console_manipulation.ps1"
#Hide-Console

[void]$NC.ShowDialog()