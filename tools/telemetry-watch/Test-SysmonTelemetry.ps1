<## Read-only positive health sample. No service start/stop or log clearing. ##>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$path='C:\ProgramData\HomelabHealth\sysmon-health.jsonl'
$result=[ordered]@{kind='sysmon';host=$env:COMPUTERNAME;utc=[DateTime]::UtcNow.ToString('o');status='fail';service_running=$false;channel_enabled=$false;channel_readable=$false;last_process_event_utc=$null;last_record_id=$null;age_seconds=$null;reason=$null}
try {
 $result.service_running=(Get-Service -Name Sysmon64 -ErrorAction Stop).Status -eq 'Running'
 $channel=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
 $result.channel_enabled=$channel.IsEnabled
 $latest=Get-WinEvent -FilterHashtable @{LogName=$channel.LogName;Id=1} -MaxEvents 1 -ErrorAction Stop
 $result.channel_readable=$true;$result.last_record_id=$latest.RecordId
 $result.last_process_event_utc=$latest.TimeCreated.ToUniversalTime().ToString('o')
 $result.age_seconds=[math]::Round(([DateTime]::UtcNow-$latest.TimeCreated.ToUniversalTime()).TotalSeconds,1)
 if($result.service_running -and $result.channel_enabled -and $result.channel_readable -and $result.age_seconds -ge -60 -and $result.age_seconds -le 900){$result.status='ok';$result.reason='Service running; enabled channel readable; process-creation evidence within15minutes'}else{$result.reason='Service/channel/freshness check failed'}
}catch{$result.reason=$_.Exception.GetType().Name}
# Keep at most the active1MiB log and one preceding generation, both under the protected folder.
$share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
if((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 1MB){
 $read=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
 $copy=[IO.FileStream]::new(($path+'.1'),[IO.FileMode]::Create,[IO.FileAccess]::Write,$share)
 try{$read.CopyTo($copy)}finally{$read.Dispose();$copy.Dispose()}
 $truncate=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,$share)
 try{$truncate.SetLength(0)}finally{$truncate.Dispose()}
}
# Windows PowerShell5.1 Add-Content has sharing behavior incompatible with an active reader.
$stream=[IO.FileStream]::new($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,$share)
$writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false))
try{$writer.WriteLine((@{homelab_health=$result} | ConvertTo-Json -Depth 4 -Compress))}finally{$writer.Dispose()}
if($result.status -eq 'ok'){exit 0}else{exit 1}
