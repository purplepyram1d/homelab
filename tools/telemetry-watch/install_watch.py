"""Install only after isolated tests; preserve exact config rollback. Does not restart."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

source=Path(__file__).parent
code=Path('/opt/homelab-telemetry-watch/20261024')
state=Path('/var/lib/homelab-telemetry-watch')
logs=Path('/var/log/homelab-telemetry-watch')
backup=Path('/var/backups/homelab-telemetry-watch-20261024')
rule=Path('/var/ossec/etc/rules/sysmon_arrival_watch.xml')
config=Path('/var/ossec/etc/ossec.conf')
units=[Path('/etc/systemd/system')/n for n in ('homelab-telemetry-watch.service','homelab-telemetry-watch.timer')]
for path in (code,state,logs,backup,rule,*units):
    if path.exists():raise RuntimeError('Existing target; inspect before installation: '+str(path))
for rule_file in Path('/var/ossec/etc/rules').glob('*.xml'):
    for node in ET.fromstring('<root>'+rule_file.read_text()+'</root>').iter('rule'):
        if node.attrib.get('id') in ('100894','100895','100896','100897'):
            raise RuntimeError('Rule ID already owned')
for path in (code,state,logs,backup):path.mkdir(parents=True,mode=0o700)
for name in ('telemetry_watch.py','test_telemetry_watch.py'):
    shutil.copyfile(source/name,code/name);os.chmod(code/name,0o600)
subprocess.run(['python3','-m','unittest','discover','-s',str(code),'-p','test_telemetry_watch.py','-q'],check=True)
shutil.copy2(config,backup/'ossec.conf.before')
old=config.read_bytes();before=hashlib.sha256(old).hexdigest();metadata=config.stat()
new=old+b'\n<ossec_config>\n  <localfile>\n    <location>/var/log/homelab-telemetry-watch/events.jsonl</location>\n    <log_format>json</log_format>\n  </localfile>\n</ossec_config>\n'
ET.fromstring(b'<root>'+new+b'</root>')
shutil.copyfile(source.parents[1]/'detections/wazuh/telemetry-health/sysmon_arrival_watch.xml',rule)
os.chown(rule,metadata.st_uid,metadata.st_gid);os.chmod(rule,0o640)
candidate=config.with_name('ossec.conf.watch-candidate')
candidate.write_bytes(new);os.chown(candidate,metadata.st_uid,metadata.st_gid);os.chmod(candidate,metadata.st_mode & 0o777)
if hashlib.sha256(config.read_bytes()).hexdigest()!=before:raise RuntimeError('Concurrent config edit')
os.replace(candidate,config)
try:
    subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'],check=True)
    subprocess.run(['/var/ossec/bin/wazuh-logcollector','-t'],check=True)
except BaseException:
    shutil.copy2(backup/'ossec.conf.before',config)
    rule.unlink()
    raise
for unit in units:shutil.copyfile(source/unit.name,unit);os.chmod(unit,0o644)
log=logs/'events.jsonl';log.touch(mode=0o640)
subprocess.run(['systemd-analyze','verify',*[str(p) for p in units]],check=True)
result=dict(configuration_valid=True,restart_required=True,timer_started=False,backup=str(backup),
            config_before_sha256=before,config_after_sha256=hashlib.sha256(new).hexdigest(),
            installed_code=str(code),state=str(state),log=str(log))
(backup/'install.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
