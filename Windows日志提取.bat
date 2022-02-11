@ECHO OFF
wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational TerminalServices.evtx
wevtutil epl Security Security.evtx
wevtutil epl System System.evtx