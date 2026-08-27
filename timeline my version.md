# Timeline

# Core Evidence Timeline

| Approx. Time | Activity | Evidence |
|---|---|---|
| 07:58:33 | Endpoint verification | Hostname, user, timestamp |
| 07:59 | Directory creation | `C:\WMIPermanentEventLab` |
| 08:00:04 | Baseline creation | `baseline.txt` |
| 08:01:07 | Payload creation | `wmi-payload.ps1` |
| 08:01:07 | File creation telemetry | Sysmon Event ID 11 |
| Before WMI creation | Existing subscription review | WMI enumeration |
| WMI configuration | Event filter creation | `Lab_WMI_Event_Filter` |
| WMI configuration | Consumer creation | `Lab_WMI_Command_Consumer` |
| WMI configuration | Binding creation | `__FilterToConsumerBinding` |
| 08:06:56 | Pre-execution timestamp | `Get-Date` |
| 08:07:43 | Payload execution | `wmi-event-result.txt` |
| 08:08-08:09 | PowerShell process review | Sysmon Event ID 1 |
| Post-execution | WMI evidence export | Filters, consumers, bindings |
| Post-execution | Wazuh verification | Agent status |
| Post-execution | Separate monitoring observation | Listening-port alert |

---

