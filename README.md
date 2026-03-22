# SOC Alerting System (PCAP & Log Analysis)

## Overview
Developed a SOC-style alerting system that analyzes PCAP and log files to detect suspicious activity such as brute-force attacks, DDoS patterns, and abnormal traffic behavior.

## Features
- PCAP analysis using PyShark
- Log file analysis for failed login attempts
- Detection of suspicious IPs based on thresholds
- Alert generation for potential security incidents
- Simple GUI for file selection

## Detection Capabilities
- Multiple failed login attempts (brute-force detection)
- High packet volume from single IP (possible DDoS)
- Suspicious network behavior patterns

## Technologies Used
- Python
- PyShark
- Tkinter

## Example Alerts
- ALERT: Suspicious activity from IP (multiple failed logins)
- ALERT: High traffic detected from IP (possible attack)

## Purpose
This project demonstrates how SOC analysts detect and respond to suspicious activity in network traffic and system logs.

## Future Improvements
- Integration with SIEM platforms
- Real-time monitoring
- Advanced anomaly detection
