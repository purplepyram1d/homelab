#!/bin/bash
# Wazuh Alert Query Utilities
# Helpers for querying /var/ossec/logs/alerts/alerts.json on the Wazuh manager
#
# Usage:
#   source alert-query.sh
#   wazuhgrep 100001          # raw grep for rule ID
#   jqwazuh 100002            # structured JSON output for rule ID

# wazuhgrep: fast grep for a rule ID in the alert log
wazuhgrep() {
  if [ -z "$1" ]; then
    echo "Usage: wazuhgrep <rule_id>"
    return 1
  fi
  sudo grep -F "\"id\":\"$1\"" /var/ossec/logs/alerts/alerts.json
}

# jqwazuh: structured output for a rule ID — time, host, event, user, process
jqwazuh() {
  if [ -z "$1" ]; then
    echo "Usage: jqwazuh <rule_id>"
    return 1
  fi
  sudo jq -c "select(.rule.id==\"$1\") | {
    time: .timestamp,
    id: .rule.id,
    desc: .rule.description,
    host: (.agent.name // \"N/A\"),
    event: (.data.win.system.eventID // \"N/A\"),
    user: (
      .data.win.eventdata.TargetUserName //
      .data.win.eventdata.SubjectUserName //
      .data.win.eventdata.AccountName //
      \"N/A\"
    ),
    process: (
      .data.win.eventdata.Image //
      .data.win.eventdata.SourceImage //
      \"N/A\"
    )
  }" /var/ossec/logs/alerts/alerts.json
}

# live_alerts: tail the alert log and pretty-print incoming alerts for a rule ID
live_alerts() {
  if [ -z "$1" ]; then
    echo "Usage: live_alerts <rule_id>"
    return 1
  fi
  sudo tail -f /var/ossec/logs/alerts/alerts.json | jq -c "select(.rule.id==\"$1\")"
}
