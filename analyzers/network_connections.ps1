# TODO - Break into Functions/Refactor


param(
     [Parameter()]
     [array]$evidence_array,
     [Parameter()]
     [string]$evidence_dir
 )

function LoadToArray ([string]$name) {
    #Loading Data
    Write-Host $name
    $data_path = "$evidence_dir\$name"
    $array = New-Object System.Collections.ArrayList
    $data = @(Import-CSV -Path "$data_path")
    $array.AddRange($data)
    return [System.Collections.ArrayList]$array
}

Add-Type -AssemblyName System.Windows.Forms
$bold_font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
$NC = New-Object System.Windows.Forms.Form
$NC.ClientSize = '1200,800'
$NC.text = 'WMIH - Network Connection Explorer'
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

$nc_table = New-Object System.Data.DataTable
$nc_data = Import-CSV -Path "$evidence_dir\network_connections.csv"
$nc_headers = $nc_data | Get-Member -MemberType NoteProperty
ForEach ($header in $nc_headers) {
    $nc_table.Columns.Add($header.Name)
}

if ($evidence_array.Contains('running_processes.csv')) {
    $nc_table.Columns.Add("ProcessName")
    $nc_table.Columns.Add("CommandLine")
    $nc_table.Columns.Add("ExecutablePath")
}
# Translate TCP State to English
# docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.tcpstate?view=net-6.0
# Anyone know what '100' is?
$nc_table.Columns.Add("StateTranslated")
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
$process_name_filter.Add_TextChanged({
$text = $process_name_filter.Text
$filter = "ProcessName LIKE '$text' OR CommandLine LIKE '$text'"
$nc_table.DefaultView.RowFilter = $filter
})
$NC.Controls.Add($process_name_filter)

# IP Address Filter
$ipaddress_filter = New-Object System.Windows.Forms.TextBox
$ipaddress_filter.Width = 140
$ipaddress_filter.Height = 20
$ipaddress_filter.Text = "IP Address Filter"
$ipaddress_filter.Location = New-Object System.Drawing.Point (150, 640)
$ipaddress_filter.Add_TextChanged({
$text = $ipaddress_filter.Text
$filter = "LocalAddress LIKE '$text' OR RemoteAddress LIKE '$text'"
$nc_table.DefaultView.RowFilter = $filter
})
$NC.Controls.Add($ipaddress_filter)

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
        Write-Host $rat_filter
    }
    else {
        $process_name_filter.Text = "*"
    }
})

# Label for Filter Controls
$filter_label = New-Object System.Windows.Forms.Label
$filter_label.Width = 600
$filter_label.Height = 20
$filter_label.Text = "Filter (Process Names or CommandLines) and (LocalAddress or RemoteAddress), % or * is wildcard"
$filter_label.Location = New-Object System.Drawing.Point (10,620)
$NC.Controls.Add($filter_label)

#DataGrid GUI Element
$grid = New-Object System.Windows.Forms.DataGrid
$grid.Width = 1200
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
$NC.Controls.Add($grid)

. ".\helpers\console_manipulation.ps1"
Hide-Console

[void]$NC.ShowDialog()