* We can use various options to tell `Nmap` how fast (`-T <0-5>`), with which frequency (`--min-parallelism <number>`), which timeouts (`--max-rtt-timeout <time>`) the test packets should have, how many packets should be sent simultaneously (`--min-rate <number>`), and with the number of retries (`--max-retries <number>`) for the scanned ports the targets should be scanned.
* `-F`
	* scans top 100 ports and is FAST

| `-oN tnet.minrate300`        | Saves the results in normal formats, starting the specified file name. |
| ---------------------------- | ---------------------------------------------------------------------- |
| `--min-rate 300`             | Sets the minimum number of packets to be sent per second.              |
| `--max-retries 0`            | Sets the number of retries that will be performed during the scan.<br> |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout.<br>              |
| `--max-rtt-timeout 100ms`    | Sets the specified time value as maximum RTT timeout.                  |
| `-T 5`                       | Specifies the insane timing template.                                  |

--- 
#### Timing

Because such settings cannot always be optimized manually, as in a black-box penetration test, `Nmap` offers six different timing templates (`-T <0-5>`). These values (`0-5`) determine the aggressiveness of our scans. This can also have negative effects if the scan is too aggressive, and security systems may block us due to the produced network traffic. The default timing template used when we have defined nothing else is the normal (`-T 3`).

- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`