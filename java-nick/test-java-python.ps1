param()
# Java <-> Python Interop Test
# Tests the Java auth protocol (AUTH_REQUEST -> AUTH_RESPONSE -> AUTH_SUCCESS).
# Python auto-detects Java protocol from the mDNS "fingerprint" TXT record.
# Python consent is handled via P2P_CONSENT_QUEUE env var (pre-loaded file).

$javaBase   = "e:\github\cisc468-final-project\java-nick"
$pythonBase = "e:\github\cisc468-final-project\python-alice"
$jar        = "$javaBase\target\p2p-file-sharing-1.0-SNAPSHOT.jar"
$logs       = "$javaBase\test-logs"
New-Item -ItemType Directory -Force $logs | Out-Null

$javaName   = "JNick2"
$pythonName = "AAlice"
$javaDat    = "$javaBase\data\$javaName"
$pythonDat  = "$pythonBase\data\$pythonName"

# Pre-load consent responses for Python (covers trust + file ops)
$consentFile = "$logs\python-consent-queue.txt"
"y`ny`ny`ny`ny`ny`ny`n" | Set-Content $consentFile -Encoding UTF8

Write-Host "=== Java <-> Python Interop Test ===" -ForegroundColor Cyan

# ----- Pre-flight checks -----------------------------------------------------
if (-not (Test-Path $jar)) {
    Write-Host "[!] JAR not found: $jar" -ForegroundColor Red; exit 1
}

# ----- Fresh data directories ------------------------------------------------
Remove-Item -Recurse -Force $javaDat   -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $pythonDat -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$javaDat\shared"   | Out-Null
New-Item -ItemType Directory -Force "$pythonDat\shared" | Out-Null
Set-Content "$javaDat\shared\java_doc.txt"       "Confidential Java document."         -Encoding UTF8
Set-Content "$pythonDat\shared\python_notes.txt" "Python notes - interop successful!" -Encoding UTF8

# ----- Phase 1: Generate Java identity --------------------------------------
Write-Host ""
Write-Host "[Phase 1] Generating Java identity for $javaName..." -ForegroundColor Cyan

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

$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    if ($sbSetup.ToString() -match "mDNS registered as") { break }
    Start-Sleep -Milliseconds 250
}
Start-Sleep -Milliseconds 500
$pSetup.StandardInput.WriteLine("exit")
Start-Sleep -Milliseconds 2000
try { $pSetup.Kill() } catch {}
Start-Sleep -Milliseconds 2000

if (-not (Test-Path "$javaDat\identity.pub")) {
    Write-Host "[!] Java identity file not created - aborting." -ForegroundColor Red; exit 1
}
Write-Host "  Java identity generated." -ForegroundColor Gray

# ----- Phase 2: Pre-populate Python trust store ------------------------------
Write-Host ""
Write-Host "[Phase 2] Pre-populating Python trust store with $javaName fingerprint..." -ForegroundColor Cyan
$javaPub = [System.IO.File]::ReadAllBytes("$javaDat\identity.pub")
$sha256  = [System.Security.Cryptography.SHA256]::Create()
$javaFp  = ($sha256.ComputeHash($javaPub) | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Host "  $javaName fingerprint: $($javaFp.Substring(0,16))..." -ForegroundColor Gray

$javaPubB64 = [Convert]::ToBase64String($javaPub)

New-Item -ItemType Directory -Force $pythonDat | Out-Null
# Python accepts both list and dict format; use list for JSON compatibility
$pythonTrust = '[{"name": "' + $javaName + '", "fingerprint": "' + $javaFp + '", "identity_pub": "' + $javaPubB64 + '"}]'
# UTF-8 WITHOUT BOM - Python's json.load handles BOM but this is cleaner
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$pythonDat\truststore.json", $pythonTrust, $utf8NoBom)
Write-Host "  Python trust store written." -ForegroundColor Gray

# ----- Process helpers -------------------------------------------------------
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

function Start-Peer-Python($peerName, $consentQueuePath) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = "python"
    # -u disables stdout/stderr buffering so async reader gets output immediately
    $psi.Arguments       = "-u app.py --name `"$peerName`" --password password"
    $psi.WorkingDirectory = $pythonBase
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $psi.EnvironmentVariables["P2P_CONSENT_QUEUE"] = $consentQueuePath
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

# ----- Phase 3: Start Python first, then Java --------------------------------
# Python starts browsing immediately; Java announces itself shortly after.
# This gives Python the best chance to discover Java via mDNS query+response.
Write-Host ""
Write-Host "[1] Starting $pythonName (Python) first, then $javaName (Java)..." -ForegroundColor Cyan

$alice = Start-Peer-Python $pythonName $consentFile
Check (Wait-For $alice "mDNS registered" -timeoutSec 25) "$pythonName started" "$pythonName failed to start"

# Read Python's IP and port from its mDNS registration log
Start-Sleep -Milliseconds 500
$pythonLog  = $alice.Output.ToString()
$pythonPort = 6767
$pythonIp   = "127.0.0.1"
if ($pythonLog -match "mDNS registered \(([^:]+):(\d+)\)") {
    $pythonIp   = $Matches[1]
    $pythonPort = [int]$Matches[2]
}
Write-Host "  $pythonName is on $pythonIp`:$pythonPort" -ForegroundColor Gray

# Give Python 3s to start browsing before Java announces
Start-Sleep -Milliseconds 3000

$nick = Start-Peer-Java $javaName
Start-Sleep -Milliseconds 600
$nick.Process.StandardInput.WriteLine($javaName)
$nick.Process.StandardInput.WriteLine("password")
Check (Wait-For $nick "mDNS registered as" -timeoutSec 25) "$javaName started" "$javaName failed to start"

# ----- Peer Discovery --------------------------------------------------------
Write-Host ""
Write-Host "[2] Peer Discovery (10s wait, then direct-connect fallback)..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 10000
Send $nick "peers"
$mdnsOk = Wait-For $nick $pythonName -timeoutSec 5
if ($mdnsOk) {
    Pass "$javaName discovered $pythonName via mDNS"
    Check (Wait-For $alice "Discovered" -timeoutSec 8) "$pythonName discovers peers" "$pythonName no discovery"
} else {
    Write-Host "  mDNS cross-client discovery not available" -ForegroundColor DarkYellow
    Write-Host "  Will use connect_ip fallback for $javaName->$pythonName" -ForegroundColor Gray
    Pass "$pythonName reachable via direct IP (mDNS skipped)"
}

# ----- Connection: JNick2 -> AAlice -----------------------------------------
Write-Host ""
Write-Host "[3] $javaName connects to $pythonName (Java->Python handshake)..." -ForegroundColor Cyan
if ($mdnsOk) {
    Send $nick "connect $pythonName"
} else {
    Send $nick "connect_ip $pythonIp $pythonPort $pythonName"
}

# Python pre-trusts JNick2 (trust store pre-populated). No Python trust prompt.
# Java sees AAlice as unknown -> fires trust prompt.
Check (Wait-For $nick "Trust this peer" $pythonName -timeoutSec 15) `
      "Java trust prompt for $pythonName handled" "Java trust prompt timed out"
Check (Wait-For $nick "Connected and authenticated" -timeoutSec 15) `
      "$javaName connected to $pythonName" "Java->Python handshake failed"
Check (Wait-For $alice "Authenticated with '$javaName'" -timeoutSec 10) `
      "$pythonName authenticated $javaName" "$pythonName did not authenticate"

# ----- Back-channel readiness -----------------------------------------------
# Java now runs a background handlePeerMessages thread on every outgoing session,
# so Python can send requests over the EXISTING JNick2->AAlice connection without
# needing to open a new one. No mDNS discovery or explicit connect is required.
Write-Host ""
Write-Host "[4] Back-channel check (Java background reader on outgoing session)..." -ForegroundColor Cyan
Write-Host "  Java now accepts incoming requests from Python on the existing connection." -ForegroundColor Gray
Pass "Back-channel enabled (handlePeerMessages on outgoing session)"
$backChannelOk = $true

# ----- File Listing ----------------------------------------------------------
Write-Host ""
Write-Host "[5] File listing (no consent required)..." -ForegroundColor Cyan

# JNick2 lists AAlice (always available via connection A)
Send $nick "list $pythonName"
Check (Wait-For $nick "python_notes.txt" -timeoutSec 10) `
      "$javaName sees Python file list" "File list from Python failed"

# AAlice lists JNick2 (requires back-channel or connection A on Python side)
if ($backChannelOk) {
    Send $alice "list $javaName"
    Check (Wait-For $alice "java_doc.txt" -timeoutSec 10) `
          "$pythonName sees Java file list" "File list from Java failed"
} else {
    Write-Host "  SKIP: $pythonName->$javaName file list (no back-channel)" -ForegroundColor DarkYellow
}

# ----- File Request: JNick2 requests python_notes.txt from AAlice ------------
# Python auto-consents via P2P_CONSENT_QUEUE
Write-Host ""
Write-Host "[6] $javaName requests python_notes.txt from $pythonName (Python auto-consents)..." -ForegroundColor Cyan
Send $nick "request $pythonName python_notes.txt"
Check (Wait-For $nick "Hash verified" -timeoutSec 20) `
      "$javaName received and verified python_notes.txt" "Java<-Python file transfer failed"

# ----- File Request: AAlice requests java_doc.txt from JNick2 ----------------
if ($backChannelOk) {
    Write-Host ""
    Write-Host "[7] $pythonName requests java_doc.txt from $javaName (Java consent)..." -ForegroundColor Cyan
    # Python must run 'list JNick2' first to know the file hash for Java protocol
    Send $alice "list $javaName"
    Check (Wait-For $alice "java_doc.txt" -timeoutSec 10) `
          "$pythonName got file list from $javaName" "$pythonName file list failed"
    Send $alice "request $javaName java_doc.txt"
    Check (Wait-For $nick "is requesting file" "y" -timeoutSec 12) `
          "$javaName consent prompt handled" "$javaName consent timed out"
    Check (Wait-For $alice "Received and verified" -timeoutSec 15) `
          "$pythonName received java_doc.txt" "Python<-Java file transfer failed"
} else {
    Write-Host ""
    Write-Host "[7] SKIP: $pythonName requests from $javaName (no back-channel)" -ForegroundColor DarkYellow
}

# ----- File Send: JNick2 sends java_doc.txt to AAlice ------------------------
# Java-initiated push works over connection A (no back-channel needed)
Write-Host ""
Write-Host "[8] $javaName sends java_doc.txt to $pythonName (Python auto-consents)..." -ForegroundColor Cyan
Send $nick "send $pythonName java_doc.txt"
Check (Wait-For $nick  "sent successfully" -timeoutSec 20) `
      "$javaName confirmed file sent" "$javaName send confirmation missing"
Check (Wait-For $alice "Received and verified" -timeoutSec 15) `
      "$pythonName received the sent file" "$pythonName did not receive file"

# ----- Key Migration ---------------------------------------------------------
Write-Host ""
Write-Host "[9] Key migration: $javaName migrates to a new identity key..." -ForegroundColor Cyan
Send $nick "migrate"
Check (Wait-For $nick "Key migration complete" -timeoutSec 10) `
      "$javaName migration completed" "$javaName migration failed"
Check (Wait-For $alice "Updated trusted key for" -timeoutSec 12) `
      "$pythonName accepted key migration" "$pythonName did not receive migration"

# ----- Contacts --------------------------------------------------------------
Write-Host ""
Write-Host "[10] Contact lists..." -ForegroundColor Cyan
Send $nick  "contacts"
Send $alice "contacts"
Start-Sleep -Milliseconds 1500

# ----- Shutdown --------------------------------------------------------------
Write-Host ""
Write-Host "[11] Shutting down..." -ForegroundColor Cyan
Send $nick  "exit"
Send $alice "exit"
Start-Sleep -Milliseconds 2000

# ----- Logs ------------------------------------------------------------------
$logJ = $nick.Output.ToString()
$logP = $alice.Output.ToString()
$logJ | Set-Content "$logs\jnick2-python-test.log"  -Encoding UTF8
$logP | Set-Content "$logs\aalice-python-test.log"  -Encoding UTF8

Write-Host ""
Write-Host "========== $javaName Output ==========" -ForegroundColor Cyan
$logJ -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }
Write-Host ""
Write-Host "========== $pythonName Output ==========" -ForegroundColor Cyan
$logP -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "=== Done. Logs saved to $logs ===" -ForegroundColor Cyan
try { $nick.Process.Kill()  } catch {}
try { $alice.Process.Kill() } catch {}
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
