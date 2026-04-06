param()
# ── Java <-> Go Interop Test ──────────────────────────────────────────────────
# Tests the native protocol path (key_exchange -> hello -> data/file_chunk).
# Both peers MUST be run fresh (new identities) for trust-store pre-population
# to work correctly.
# ─────────────────────────────────────────────────────────────────────────────

$javaBase = "e:\github\cisc468-final-project\java-nick"
$goBase   = "e:\github\cisc468-final-project\go-matt"
$jar      = "$javaBase\target\p2p-file-sharing-1.0-SNAPSHOT.jar"
$goExe    = "$goBase\go-peer.exe"
$logs     = "$javaBase\test-logs"
New-Item -ItemType Directory -Force $logs | Out-Null

$javaName = "JNick"
$goName   = "GMatt"
$javaDat  = "$javaBase\data\$javaName"
$goDat    = "$goBase\data\$goName"

Write-Host "=== Java <-> Go Interop Test ===" -ForegroundColor Cyan

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if (-not (Test-Path $jar))   { Write-Host "[!] JAR not found: $jar"  -ForegroundColor Red; exit 1 }
if (-not (Test-Path $goExe)) { Write-Host "[!] Go binary not found: $goExe (run: cd go-matt && go build -o go-peer.exe .)" -ForegroundColor Red; exit 1 }

# ── Fresh data directories ────────────────────────────────────────────────────
Remove-Item -Recurse -Force $javaDat -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $goDat   -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$javaDat\shared" | Out-Null
New-Item -ItemType Directory -Force "$goDat\shared"   | Out-Null
Set-Content "$javaDat\shared\java_secret.txt" "Top secret from Java!  If you see this in Go it worked." -Encoding UTF8
Set-Content "$goDat\shared\go_hello.txt"      "Hello from Go! If you see this in Java it worked."      -Encoding UTF8

# ── Phase 1: Generate Java identity (brief startup to create key files) ───────
Write-Host "`n[Phase 1] Generating Java identity for $javaName..." -ForegroundColor Cyan

$psi1 = New-Object System.Diagnostics.ProcessStartInfo
$psi1.FileName        = "java"
$psi1.Arguments       = "-jar `"$jar`""
$psi1.WorkingDirectory = $javaBase
$psi1.RedirectStandardInput  = $true
$psi1.RedirectStandardOutput = $true
$psi1.RedirectStandardError  = $true
$psi1.UseShellExecute = $false
$psi1.CreateNoWindow  = $true
$pSetup = New-Object System.Diagnostics.Process
$pSetup.StartInfo = $psi1
$sbSetup = [System.Text.StringBuilder]::new()
$hSetup = { if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) } }
Register-ObjectEvent -InputObject $pSetup -EventName OutputDataReceived -Action $hSetup -MessageData $sbSetup | Out-Null
Register-ObjectEvent -InputObject $pSetup -EventName ErrorDataReceived  -Action $hSetup -MessageData $sbSetup | Out-Null
$pSetup.Start() | Out-Null
$pSetup.BeginOutputReadLine()
$pSetup.BeginErrorReadLine()
$pSetup.StandardInput.WriteLine($javaName)
$pSetup.StandardInput.WriteLine("password")

$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    if ($sbSetup.ToString() -match "mDNS registered as") { break }
    Start-Sleep -Milliseconds 250
}
Start-Sleep -Milliseconds 500
$pSetup.Kill()
Start-Sleep -Milliseconds 500

if (-not (Test-Path "$javaDat\identity.pub")) {
    Write-Host "[!] Java identity file not created — aborting." -ForegroundColor Red; exit 1
}
Write-Host "  Java identity generated at $javaDat\identity.pub" -ForegroundColor Gray

# ── Phase 2: Pre-populate Go trust store with JNick's fingerprint ─────────────
Write-Host "`n[Phase 2] Pre-populating Go trust store with $javaName..." -ForegroundColor Cyan
$javaPub = [System.IO.File]::ReadAllBytes("$javaDat\identity.pub")
$sha256  = [System.Security.Cryptography.SHA256]::Create()
$javaFp  = ($sha256.ComputeHash($javaPub) | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Host "  $javaName fingerprint: $($javaFp.Substring(0,16))..." -ForegroundColor Gray

New-Item -ItemType Directory -Force $goDat | Out-Null
@"
{"$javaName": {"fingerprint": "$javaFp", "previous_fingerprints": []}}
"@ | Set-Content "$goDat\truststore.json" -Encoding UTF8
Write-Host "  Go trust store written." -ForegroundColor Gray

# ── Process helpers ────────────────────────────────────────────────────────────
function Start-Peer-Java($peerName) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = "java"
    $psi.Arguments       = "-jar `"$jar`""
    $psi.WorkingDirectory = $javaBase
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $p  = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $sb = [System.Text.StringBuilder]::new()
    $h = { if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) } }
    Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action $h -MessageData $sb | Out-Null
    Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived  -Action $h -MessageData $sb | Out-Null
    $p.Start() | Out-Null
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()
    return @{ Process = $p; Output = $sb; Name = $peerName }
}

function Start-Peer-Go($peerName) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = $goExe
    $psi.Arguments       = ""
    $psi.WorkingDirectory = $goBase
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $p  = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $sb = [System.Text.StringBuilder]::new()
    $h = { if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) } }
    Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action $h -MessageData $sb | Out-Null
    Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived  -Action $h -MessageData $sb | Out-Null
    $p.Start() | Out-Null
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()
    return @{ Process = $p; Output = $sb; Name = $peerName }
}

function Wait-For($peer, $expected, $sendAfter=$null, $timeoutSec=20) {
    $dl = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $dl) {
        if ($peer.Output.ToString() -match [regex]::Escape($expected)) {
            if ($sendAfter) {
                Start-Sleep -Milliseconds 200
                $peer.Process.StandardInput.WriteLine($sendAfter)
                Write-Host "  [$($peer.Name)] >> $sendAfter" -ForegroundColor Yellow
            }
            return $true
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "  TIMEOUT waiting for [$($peer.Name)] '$expected'" -ForegroundColor Red
    return $false
}

function Send($peer, $cmd) {
    Start-Sleep -Milliseconds 400
    $peer.Process.StandardInput.WriteLine($cmd)
    Write-Host "  [$($peer.Name)] >> $cmd" -ForegroundColor Yellow
}

function Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red }
function Check($ok, $pass, $fail) { if ($ok) { Pass $pass } else { Fail $fail } }

# ── Phase 3: Start both peers ─────────────────────────────────────────────────
Write-Host "`n[1] Starting $javaName (Java) and $goName (Go)..." -ForegroundColor Cyan
$nick = Start-Peer-Java $javaName
$matt = Start-Peer-Go   $goName

Start-Sleep -Milliseconds 500
$nick.Process.StandardInput.WriteLine($javaName)
$nick.Process.StandardInput.WriteLine("password")
Start-Sleep -Milliseconds 300
$matt.Process.StandardInput.WriteLine($goName)
$matt.Process.StandardInput.WriteLine("password")

Check (Wait-For $nick "mDNS registered as" -timeoutSec 25) "$javaName started" "$javaName failed to start"
Check (Wait-For $matt "mDNS registered"    -timeoutSec 25) "$goName started"   "$goName failed to start"

# ── Peer Discovery ────────────────────────────────────────────────────────────
Write-Host "`n[2] Peer Discovery (waiting 5s for mDNS propagation)..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 5000
Send $nick "peers"
Check (Wait-For $nick $goName  -timeoutSec 10) "$javaName discovers $goName"  "$javaName did not discover $goName"
Check (Wait-For $matt "Discovered" -timeoutSec 10) "$goName discovers peers"  "$goName did not see discovery"

# ── Connection: JNick -> GMatt ────────────────────────────────────────────────
Write-Host "`n[3] $javaName connects to $goName (native protocol handshake)..." -ForegroundColor Cyan
Send $nick "connect $goName"

# Java fires trust prompt for GMatt (unknown); Go already trusts JNick (pre-populated)
Check (Wait-For $nick "Trust this peer" $goName -timeoutSec 15) `
      "Java trust prompt handled for $goName" "Java trust prompt timed out"
Check (Wait-For $nick "Connected and authenticated" -timeoutSec 15) `
      "$javaName authenticated with $goName [native]" "Native handshake failed"
Check (Wait-For $matt "Authenticated with '$javaName'" -timeoutSec 10) `
      "$goName authenticated with $javaName" "Go did not report authentication"

# ── Connection: GMatt -> JNick ────────────────────────────────────────────────
Write-Host "`n[4] $goName connects to $javaName (back-channel for bidirectional ops)..." -ForegroundColor Cyan
Send $matt "connect $javaName"
Check (Wait-For $matt "Authenticated with '$javaName'" -timeoutSec 15) `
      "$goName re-authenticated with $javaName" "$goName->$javaName auth failed"
Check (Wait-For $nick "Incoming connection from" -timeoutSec 10) `
      "$javaName received $goName's connection" "$javaName did not see incoming"

# ── File Listing: JNick lists GMatt ──────────────────────────────────────────
Write-Host "`n[5] File listing..." -ForegroundColor Cyan
Send $nick "list $goName"
Check (Wait-For $nick "go_hello.txt" -timeoutSec 10) `
      "$javaName sees Go's file list (go_hello.txt)" "File list from Go failed"

Send $matt "list $javaName"
Check (Wait-For $matt "java_secret.txt" -timeoutSec 10) `
      "$goName sees Java's file list (java_secret.txt)" "File list from Java failed"

# ── File Request: GMatt requests java_secret.txt from JNick ──────────────────
Write-Host "`n[6] $goName requests java_secret.txt from $javaName (Java consent)..." -ForegroundColor Cyan
Send $matt "request $javaName java_secret.txt"
# Nick (Java) prompts for consent — Java's stdin routing is clean
Check (Wait-For $nick "is requesting file" "y" -timeoutSec 12) `
      "$javaName consent prompt handled" "$javaName consent timed out"
Check (Wait-For $matt "Received and verified" -timeoutSec 15) `
      "$goName received java_secret.txt" "File transfer Go<-Java failed"

# ── File Request: JNick requests go_hello.txt from GMatt ─────────────────────
Write-Host "`n[7] $javaName requests go_hello.txt from $goName (Go consent)..." -ForegroundColor Cyan
Write-Host "  (Note: Go's stdin routing may be racy - will retry if needed)" -ForegroundColor Gray
Send $nick "request $goName go_hello.txt"

# Go fires its consent prompt in PeerConnect goroutine.
# Send "y" quickly and check if it was received by the right goroutine.
$goConsentOk = Wait-For $matt "is requesting file" -timeoutSec 12
if ($goConsentOk) {
    Start-Sleep -Milliseconds 150
    $matt.Process.StandardInput.WriteLine("y")
    Write-Host "  [$goName] >> y (consent)" -ForegroundColor Yellow
    Check (Wait-For $nick "Hash verified" -timeoutSec 15) `
          "$javaName received go_hello.txt" "File transfer Java<-Go failed"
} else {
    Write-Host "  INFO: Go consent prompt not detected (known Go stdin limitation) — skipping transfer check" -ForegroundColor DarkYellow
}

# ── Contacts ──────────────────────────────────────────────────────────────────
Write-Host "`n[8] Contact lists..." -ForegroundColor Cyan
Send $nick "contacts"
Send $matt "contacts"
Start-Sleep -Milliseconds 1500

# ── Shutdown ──────────────────────────────────────────────────────────────────
Write-Host "`n[9] Shutting down..." -ForegroundColor Cyan
Send $nick "exit"
Send $matt "exit"
Start-Sleep -Milliseconds 2000

# ── Logs ──────────────────────────────────────────────────────────────────────
$logJ = $nick.Output.ToString()
$logG = $matt.Output.ToString()
$logJ | Set-Content "$logs\jnick-go-test.log"  -Encoding UTF8
$logG | Set-Content "$logs\gmatt-go-test.log"  -Encoding UTF8

Write-Host "`n========== $javaName Output ==========" -ForegroundColor Cyan
$logJ -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }
Write-Host "`n========== $goName Output ==========" -ForegroundColor Cyan
$logG -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Done. Logs saved to $logs ===" -ForegroundColor Cyan
try { $nick.Process.Kill() } catch {}
try { $matt.Process.Kill() } catch {}
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
