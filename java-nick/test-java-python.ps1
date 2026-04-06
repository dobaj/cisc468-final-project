param()
# ── Java <-> Python Interop Test ──────────────────────────────────────────────
# Tests the Java auth protocol (AUTH_REQUEST -> AUTH_RESPONSE -> AUTH_SUCCESS).
# Python auto-detects the Java protocol from the mDNS "fingerprint" TXT record.
# Python consent is handled via P2P_CONSENT_QUEUE env var (pre-loaded file).
# ─────────────────────────────────────────────────────────────────────────────

$javaBase   = "e:\github\cisc468-final-project\java-nick"
$pythonBase = "e:\github\cisc468-final-project\python-alice"
$jar        = "$javaBase\target\p2p-file-sharing-1.0-SNAPSHOT.jar"
$logs       = "$javaBase\test-logs"
New-Item -ItemType Directory -Force $logs | Out-Null

$javaName   = "JNick2"
$pythonName = "AAlice"
$javaDat    = "$javaBase\data\$javaName"
$pythonDat  = "$pythonBase\data\$pythonName"

# Pre-load consent responses for Python (y for all prompts)
$consentFile = "$javaBase\test-logs\python-consent-queue.txt"
"y`ny`ny`ny`ny`ny" | Set-Content $consentFile -Encoding UTF8

Write-Host "=== Java <-> Python Interop Test ===" -ForegroundColor Cyan

# ── Pre-flight ────────────────────────────────────────────────────────────────
if (-not (Test-Path $jar)) {
    Write-Host "[!] JAR not found: $jar" -ForegroundColor Red; exit 1
}
python --version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Python not found in PATH" -ForegroundColor Red; exit 1
}

# ── Fresh data directories ────────────────────────────────────────────────────
Remove-Item -Recurse -Force $javaDat    -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $pythonDat  -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$javaDat\shared"    | Out-Null
New-Item -ItemType Directory -Force "$pythonDat\shared"  | Out-Null
Set-Content "$javaDat\shared\java_doc.txt"       "Confidential Java document."         -Encoding UTF8
Set-Content "$pythonDat\shared\python_notes.txt" "Python notes — interop successful!" -Encoding UTF8

# ── Phase 1: Generate Java identity ──────────────────────────────────────────
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

$deadline = (Get-Date).AddSeconds(25)
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
Write-Host "  Java identity generated." -ForegroundColor Gray

# ── Phase 2: Pre-populate Python trust store with JNick2's fingerprint ────────
Write-Host "`n[Phase 2] Pre-populating Python trust store with $javaName..." -ForegroundColor Cyan
$javaPub = [System.IO.File]::ReadAllBytes("$javaDat\identity.pub")
$sha256  = [System.Security.Cryptography.SHA256]::Create()
$javaFp  = ($sha256.ComputeHash($javaPub) | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Host "  $javaName fingerprint: $($javaFp.Substring(0,16))..." -ForegroundColor Gray

$javaPubB64 = [Convert]::ToBase64String($javaPub)

New-Item -ItemType Directory -Force $pythonDat | Out-Null
# Python reads both dict and list formats; use list format for consistency
@"
[{"name": "$javaName", "fingerprint": "$javaFp", "identity_pub": "$javaPubB64"}]
"@ | Set-Content "$pythonDat\truststore.json" -Encoding UTF8
Write-Host "  Python trust store written." -ForegroundColor Gray

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

function Start-Peer-Python($peerName, $consentQueuePath) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = "python"
    $psi.Arguments       = "app.py --name `"$peerName`" --password password"
    $psi.WorkingDirectory = $pythonBase
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    # Pass P2P_CONSENT_QUEUE so Python auto-answers consent prompts
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

# ── Phase 3: Start both peers ─────────────────────────────────────────────────
Write-Host "`n[1] Starting $javaName (Java) and $pythonName (Python)..." -ForegroundColor Cyan

$nick = Start-Peer-Java   $javaName
$alice = Start-Peer-Python $pythonName $consentFile

Start-Sleep -Milliseconds 600
$nick.Process.StandardInput.WriteLine($javaName)
$nick.Process.StandardInput.WriteLine("password")

Check (Wait-For $nick  "mDNS registered as" -timeoutSec 25) "$javaName started"   "$javaName failed to start"
Check (Wait-For $alice "mDNS registered"    -timeoutSec 25) "$pythonName started" "$pythonName failed to start"

# ── Peer Discovery ────────────────────────────────────────────────────────────
Write-Host "`n[2] Peer Discovery (waiting 5s for mDNS propagation)..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 5000
Send $nick "peers"
Check (Wait-For $nick  $pythonName  -timeoutSec 10) "$javaName discovers $pythonName"  "$javaName did not discover $pythonName"
Check (Wait-For $alice "Discovered" -timeoutSec 10) "$pythonName discovers $javaName"  "$pythonName did not see discovery"

# ── Connection: JNick2 -> AAlice ──────────────────────────────────────────────
Write-Host "`n[3] $javaName connects to $pythonName (Java auth protocol)..." -ForegroundColor Cyan
Send $nick "connect $pythonName"

# Python sees JNick2 as pre-trusted (no prompt). Java sees AAlice as unknown -> trust prompt.
Check (Wait-For $nick "Trust this peer" $pythonName -timeoutSec 15) `
      "Java trust prompt for $pythonName handled" "Java trust prompt timed out"
Check (Wait-For $nick "Connected and authenticated" -timeoutSec 15) `
      "$javaName connected to $pythonName [java protocol]" "Java->Python handshake failed"
Check (Wait-For $alice "Authenticated with '$javaName'" -timeoutSec 10) `
      "$pythonName saw incoming from $javaName" "$pythonName did not authenticate"

# ── Connection: AAlice -> JNick2 ──────────────────────────────────────────────
Write-Host "`n[4] $pythonName connects to $javaName (back-channel)..." -ForegroundColor Cyan
Send $alice "connect $javaName"
# Both sides already trust each other — no prompts expected
Check (Wait-For $alice "Authenticated with '$javaName'" -timeoutSec 15) `
      "$pythonName authenticated $javaName (outgoing)" "$pythonName->$javaName auth failed"
Check (Wait-For $nick "Incoming connection from" -timeoutSec 10) `
      "$javaName received $pythonName's connection" "$javaName no incoming"

# ── File Listing ──────────────────────────────────────────────────────────────
Write-Host "`n[5] File listing (no consent required)..." -ForegroundColor Cyan
Send $nick "list $pythonName"
Check (Wait-For $nick "python_notes.txt" -timeoutSec 10) `
      "$javaName sees Python file list" "File list from Python failed"

Send $alice "list $javaName"
Check (Wait-For $alice "java_doc.txt" -timeoutSec 10) `
      "$pythonName sees Java file list" "File list from Java failed"

# ── File Request: JNick2 requests python_notes.txt from AAlice ───────────────
Write-Host "`n[6] $javaName requests python_notes.txt from $pythonName (Python auto-consents)..." -ForegroundColor Cyan
Send $nick "request $pythonName python_notes.txt"
# Python uses P2P_CONSENT_QUEUE to auto-answer "y"
Check (Wait-For $nick "Hash verified" -timeoutSec 20) `
      "$javaName received and verified python_notes.txt" "Java<-Python file transfer failed"

# ── File Request: AAlice requests java_doc.txt from JNick2 ───────────────────
Write-Host "`n[7] $pythonName requests java_doc.txt from $javaName (Java consent)..." -ForegroundColor Cyan
Send $alice "request $javaName java_doc.txt"
Check (Wait-For $nick "is requesting file" "y" -timeoutSec 12) `
      "$javaName consent prompt handled" "$javaName consent timed out"
Check (Wait-For $alice "Received and verified" -timeoutSec 15) `
      "$pythonName received java_doc.txt" "Python<-Java file transfer failed"

# ── File Send: JNick2 sends java_doc.txt to AAlice ───────────────────────────
Write-Host "`n[8] $javaName sends java_doc.txt to $pythonName (Python auto-consents)..." -ForegroundColor Cyan
Send $nick "send $pythonName java_doc.txt"
# Python auto-accepts via consent queue
Check (Wait-For $nick "sent successfully" -timeoutSec 20) `
      "$javaName confirmed file sent" "$javaName send confirmation missing"
Check (Wait-For $alice "Received and verified" -timeoutSec 15) `
      "$pythonName received the sent file" "$pythonName did not receive file"

# ── Key Migration: JNick2 migrates key ───────────────────────────────────────
Write-Host "`n[9] Key migration: $javaName migrates to a new identity key..." -ForegroundColor Cyan
Send $nick "migrate"
Check (Wait-For $nick "Key migration complete" -timeoutSec 10) `
      "$javaName migration completed" "$javaName migration failed"
Check (Wait-For $alice "Updated trusted key" -timeoutSec 12) `
      "$pythonName accepted key migration" "$pythonName did not receive migration"

# ── Contacts ──────────────────────────────────────────────────────────────────
Write-Host "`n[10] Contact lists..." -ForegroundColor Cyan
Send $nick  "contacts"
Send $alice "contacts"
Start-Sleep -Milliseconds 1500

# ── Shutdown ──────────────────────────────────────────────────────────────────
Write-Host "`n[11] Shutting down..." -ForegroundColor Cyan
Send $nick  "exit"
Send $alice "exit"
Start-Sleep -Milliseconds 2000

# ── Logs ──────────────────────────────────────────────────────────────────────
$logJ = $nick.Output.ToString()
$logP = $alice.Output.ToString()
$logJ | Set-Content "$logs\jnick2-python-test.log"  -Encoding UTF8
$logP | Set-Content "$logs\aalice-python-test.log"  -Encoding UTF8

Write-Host "`n========== $javaName Output ==========" -ForegroundColor Cyan
$logJ -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }
Write-Host "`n========== $pythonName Output ==========" -ForegroundColor Cyan
$logP -split "`n" | Where-Object {$_.Trim()} | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Done. Logs saved to $logs ===" -ForegroundColor Cyan
try { $nick.Process.Kill()  } catch {}
try { $alice.Process.Kill() } catch {}
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
