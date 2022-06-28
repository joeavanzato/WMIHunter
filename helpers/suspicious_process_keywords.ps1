
# suspicious_process_keywords.ps1
$suspicious_process_keywords_rat = @(
    #Remote Access Tool Process Indicators
    "teamviewer",
    "screenconnect",
    "vnc",
    "zoho",
    "bomgar",
    "dwservice",
    "dwagent",
    "getscreen",
    "mstsc",
    "ultravnc",
    "distant",
    "anydesk",
    "aeroadmin",
    "iperius",
    "anyviewer",
    "quickassist",
    "litemanager",
    "desktopnow",
    "showmypc"
)

$windows_process_names = @(
    'microsoft.workflow.compiler',
    'bginfo.exe',
    'cdb.exe',
    'cmstp.exe',
    'csi.exe',
    'dnx.exe',
    'fsi.exe',
    'ieexec.exe',
    'iexpress.exe',
    'odbcconf.exe',
    'rcsi.exe',
    'xwizard.exe',
    'lsass.exe',
    'svchost.exe',
    'smss.exe',
    'wininit.exe',
    'taskhost.exe'
)