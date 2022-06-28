

param(
     [Parameter()]
     [string]$evidence_dir
 )

if ($evidence_dir) {
} else {
    $evidence_dir = Get-Location
}

function GetEvidenceArray {
    $data_files = @(Get-ChildItem -Path $evidence_dir -Filter *.csv -Name)
    $known_list = @(
    'installed_services.csv',
    'running_processes.csv',
    'installed_software.csv',
    'loggedon_users.csv',
    'network_connections.csv',
    'network_shares.csv',
    'remote_netcons.csv',
    'scheduled_tasks.csv',
    'server_connections.csv',
    'server_sessions.csv',
    'startup_items.csv',
    'system_accounts.csv'
    )
    ForEach ($f in $data_files){
        if (-not $known_list.Contains($f)){
            $data_files = $data_files -ne $f
        }
    }
    return $data_files
}



function Main {
    $Global:evidence_array = GetEvidenceArray
    ForEach ($file in $evidence_array) {
        Write-Host "Found File: "$file
    }
    BuildGUI
}


function LoadToArray ([string]$name) {
    #Loading Data
    Write-Host $name
    $data_path = "$evidence_dir\$name"
    $array = New-Object System.Collections.ArrayList
    $data = @(Import-CSV -Path "$data_path")
    $array.AddRange($data)
    return [System.Collections.ArrayList]$array
}

function network_connections.csv {
    .\analyzers\network_connections.ps1 -evidence_array $evidence_array -evidence_dir $evidence_dir
}

function BuildGUI {
    Add-Type -AssemblyName System.Windows.Forms
    $bold_font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
    $G = New-Object System.Windows.Forms.Form
    $G.ClientSize = '300,400'
    $G.text = 'WMIH Data Explorer'
    $G.BackColor = "#ffffff"

    $data_title = New-Object System.Windows.Forms.Label
    $data_title.text = "Evidence Found"
    $data_title.width = 120
    $data_title.height = 20
    $data_title.Location = New-Object System.Drawing.Point(20, 20)
    $data_title.Font = $bold_font
    $G.controls.Add($data_title)

    # i starts at 2 because we want to start at 40 Y position
    $i = 2
    ForEach ($file in $evidence_array) {
        #Write-Host "Making Button for: "$file
        $thisButton = $null
        $thisButton = New-Object System.Windows.Forms.Button
        $thisButton.Location = New-Object System.Drawing.Point(10, $(20*$i))
        $thisButton.Size = New-Object System.Drawing.Size(200, 20)
        $thisButton.Text = $file
        $thisButton.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
        $thisButton.Add_Click([scriptblock]::Create("$file"))
        $G.Controls.Add($thisButton)
        $i += 1
    }

    [void]$G.ShowDialog()

}

Main
