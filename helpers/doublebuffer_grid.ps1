# Courtesy of https://www.sapien.com/forums/viewtopic.php?t=9477

function Enable-DataGridViewDoubleBuffer {
    param ([Parameter(Mandatory = $true)]
        [System.Windows.Forms.DataGridView]$grid,
        [switch]$Disable)

    $type = $grid.GetType();
    $propInfo = $type.GetProperty("DoubleBuffered", ('Instance','NonPublic'))
    $propInfo.SetValue($grid, $Disable -eq $false, $null)
}