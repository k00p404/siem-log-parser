# SIEM Log Parser & Alerter

## Objective
To build a proactive monitoring tool for identifying fraudulent patterns and unauthorized access attempts within application logs.

## Skills Applied
* Python (File I/O, Regular Expressions, Data Parsing)
* Defensive Automation
* Security Monitoring & Alerting Logic

## How it Works
The script performs tail-end monitoring on system or application logs. It utilizes a sliding window approach to count occurrences of specific status codes or patterns (e.g., HTTP 401/403) and triggers an alert when pre-defined thresholds are breached.

## Security Focus: Brute Force and Fraud Detection
Specifically designed to mitigate:
* **Brute Force Attacks:** Threshold-based detection of repeated failed authentication.
* **Transaction Spikes:** Monitoring for high-frequency requests that deviate from established baselines.