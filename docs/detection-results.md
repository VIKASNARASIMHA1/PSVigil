| Test | Group | ATT&CK | Expected rule | Result | Time to detect (s) |
|---|---|---|---|---|---|
| EncodedPowerShell | basic | T1059.001 | VGL-0001 | Detected | 2.8 |
| BruteForce | basic | T1110 | VGL-0002 | Detected | 2.9 |
| NewLocalUser | basic | T1136.001 | VGL-0003 | Detected | 2.4 |
| ScheduledTask | basic | T1053.005 | VGL-0004 | Detected | 2.4 |
| NewService | basic | T1543.003 | VGL-0005 | Detected | 2.4 |
| DefenderTamper | basic | T1562.001 | VGL-0009 | Detected | 2.4 |
| DownloadCradle | basic | T1105 | VGL-0011 | Detected | 2.4 |
| EncodedPowerShell-enc | variants | T1059.001 | VGL-0001 | Detected | 2.5 |
| EncodedPowerShell-ec | variants | T1059.001 | VGL-0001 | Detected | 2.5 |
| EncodedPowerShell-e | variants | T1059.001 | VGL-0001 | Detected | 3 |
| EncodedPowerShell-upper | variants | T1059.001 | VGL-0001 | Detected | 2.5 |
| EncodedPowerShell-short | variants | T1059.001 | VGL-0001 | Detected | 2.5 |
| RuntimeDecode | variants | T1027 | VGL-0012 | Detected | 2.4 |
| DefenderTamper-exclusion | variants | T1562.001 | VGL-0009 | Detected | 2.4 |
| DownloadCradle-iwr | variants | T1105 | VGL-0011 | Detected | 2.4 |
| Chain-Persistence | chains | T1136 | VGL-0102 | Detected | 3 |
| Chain-ExecEvasion | chains | T1059 | VGL-0103 | Detected | 2.7 |
| Chain-BruteForceSuccess | chains | T1110.001 | VGL-0101 | Detected | 3.2 |

Detection rate: 18/18. Average time to detect: 2.6 s (measured from the end of each simulation until the rule fired, 1 s polling).
