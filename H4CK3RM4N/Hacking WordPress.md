|                                |                                                                                        |
| ------------------------------ | -------------------------------------------------------------------------------------- |
| **Command**                    | **Description**                                                                        |
| `tree -L 1`                    | Lists contents of current directory                                                    |
| `curl -s -X GET <url>`         | Makes a GET request to a webserver and receives HTML source code of requested web page |
| `curl -I -X GET <url>`         | Prints the response header of the GET request from the requested web page              |
| `curl -X POST -d <data> <url>` | Sends a POST request with data to specific webserver                                   |
| `wpscan --url <url> -e ap`     | Scans specific WordPress application to enumerate plugins                              |
| `wpscan --url <url> -e u`      | Scans specific WordPress application to enumerate users                                |
| `msfconsole`                   | Starts Metasploit Framework                                                            |
| `html2text`                    | Converts redirected HTML output or files to easily readable output                     |
| `grep <pattern>`               | Filters specific pattern in files or redirected output                                 |
| `jq`                           | Transforms JSON input and streams of JSON entities                                     |
| `man <tool>`                   | Man provides you with the manpage of the specific tool                                 |

Plugins

```
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

Themes

```
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

Specific Plugin Enumeration

```
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta
```