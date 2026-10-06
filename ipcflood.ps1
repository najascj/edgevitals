# ipcflood.ps1 - abuse the EdgeVitals IPC pipe while the agent runs.
#
#   .\ipcflood.ps1                 run every case once
#   .\ipcflood.ps1 -Soak 300       keep hammering for 300 seconds
#
# This is the test that matters most, because the pipe is the ONE surface
# a non-administrative process on the terminal can reach. Everything else
# needs write access to the config directory or the ability to start a
# process with a chosen name.
#
# Run the agent in another window first:   edgevitals.exe --console
#
# What to watch while this runs, in Task Manager or a second EdgeVitals:
#   - edgevitals.exe stays alive          (no crash)
#   - working set stays near 6 MB         (no growth)
#   - CPU stays near 0                    (no spin)
#   - logs\telemetry-*.csv keeps growing  (sampling not blocked)
#
# A PASS is boring. If nothing visible happens, the agent handled it.

param(
    [string]$Pipe = "edgevitals",
    [int]$Soak = 0
)

$ErrorActionPreference = "Continue"

function Send-Frame {
    param([string]$Label, [string]$Payload, [switch]$NoNewline)
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream(
                 ".", $Pipe, [System.IO.Pipes.PipeDirection]::InOut)
        $c.Connect(2000)
        $w = New-Object System.IO.StreamWriter($c)
        if ($NoNewline) { $w.Write($Payload) } else { $w.WriteLine($Payload) }
        $w.Flush()
        Start-Sleep -Milliseconds 120
        $c.Dispose()
        "{0,-34} sent {1,10:N0} bytes  OK" -f $Label, $Payload.Length
    } catch {
        "{0,-34} {1}" -f $Label, $_.Exception.Message
    }
}

Write-Host "`nIPC flood against \\.\pipe\$Pipe`n" -ForegroundColor Cyan

# --- 1. the crash case, at the size the pipe actually admits ----------
Send-Frame "deep nesting 262144"   ("[" * 262144)
Send-Frame "deep nesting 10000"    ("[" * 10000)
Send-Frame "deep objects 5000"     (("{""a"":" * 5000))

# --- 2. size --------------------------------------------------------
Send-Frame "just under the 256 KB cap" ('{"role":"ui","state":"' + ("x" * 260000) + '"}')
Send-Frame "over the cap, 1 MB"        ('{"role":"ui","state":"' + ("x" * 1048576) + '"}')

# --- 3. no newline, ever ---------------------------------------------
# The read loop splits on '\n'. A sender that never sends one must not be
# able to grow the buffer without bound -- the cap should clear it.
Send-Frame "1 MB with no newline" ("x" * 1048576) -NoNewline

# --- 4. malformed and hostile content ---------------------------------
Send-Frame "truncated object"    '{"role":"ui","state":'
Send-Frame "unterminated string" '{"role":"ui","state":"abc'
Send-Frame "binary garbage"      ([string][char]0 + [string][char]255 + [string][char]1)
Send-Frame "not json at all"     'GET / HTTP/1.1'
Send-Frame "empty line"          ''
Send-Frame "200k keys"           ('{' + (( 0..200000 | ForEach-Object { """k$_"":1" }) -join ',') + '}')

# --- 5. unknown keys must be ignored, not stored -----------------------
Send-Frame "unknown key"         '{"role":"ui","not_in_schema":"zzz"}'
Send-Frame "wrong type"          '{"role":"ui","frame_p95_ms":"a string"}'
Send-Frame "null role"           '{"role":null,"state":"idle"}'

# --- 6. connection exhaustion -----------------------------------------
# max_clients defaults to 4. Opening more must be refused cleanly, and
# the agent must recover once they close.
Write-Host "`nopening 40 concurrent connections (max_clients is 4)..." -ForegroundColor Yellow
$conns = @()
$refused = 0
for ($i = 0; $i -lt 40; $i++) {
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream(
                 ".", $Pipe, [System.IO.Pipes.PipeDirection]::InOut)
        $c.Connect(400)
        $conns += $c
    } catch { $refused++ }
}
"  connected {0}, refused {1}" -f $conns.Count, $refused
foreach ($c in $conns) { try { $c.Dispose() } catch {} }
Start-Sleep -Seconds 2

# a normal frame must still work after the flood
Send-Frame "normal frame after flood" '{"role":"ui","state":"idle","frame_p95_ms":18.2}'

# --- 7. optional soak --------------------------------------------------
if ($Soak -gt 0) {
    Write-Host "`nsoaking for $Soak seconds..." -ForegroundColor Yellow
    $end = (Get-Date).AddSeconds($Soak)
    $n = 0
    while ((Get-Date) -lt $end) {
        Send-Frame "soak" ("[" * 200000) | Out-Null
        Send-Frame "soak" '{"role":"ui","state":"idle"}' | Out-Null
        $n += 2
    }
    "  sent $n frames"
}

Write-Host "`nNow check:" -ForegroundColor Cyan
Write-Host "  1. is edgevitals.exe still running?"
Write-Host "  2. tasklist /FI ""IMAGENAME eq edgevitals.exe"" /FO LIST   - working set near 6 MB?"
Write-Host "  3. did logs\telemetry-*.csv keep growing through all of this?"
Write-Host "  4. does the console show 'client limit reached' rather than errors?`n"
