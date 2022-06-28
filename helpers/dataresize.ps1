
# https://stackoverflow.com/questions/18553746/powershell-dataviewgrid-column-autosize
Function AutoResizeColumns([System.Windows.Forms.DataGrid] $dg1){
    [System.Reflection.BindingFlags] $F = 'static','nonpublic','instance'
    $ColAutoResizeMethod = $dg1.GetType().GetMethod('ColAutoResize', $F)
    If($ColAutoResizeMethod) {
        For ([int]$i = $dg1.FirstVisibleColumn; $i -lt $dg1.VisibleColumnCount; $i++){
            $ColAutoResizeMethod.Invoke($dg1, $i) | Out-Null
        }
    }
}