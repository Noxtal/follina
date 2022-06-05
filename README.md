# follina (POC)
All about CVE-2022-30190, aka follina, that is a RCE vulnerability that affects Microsoft Support Diagnostic Tools (MSDT) on Office apps such as Word. This is a very simple POC, feel free to check the sources below for more threat intelligence.

# Usage
```commandline
usage: follina.py [-h] [--command COMMAND] [--ip IP] [--port PORT] [--output OUTPUT] [--reverse REVERSE]

POC for CVE-2022-30190, aka follina

options:
  -h, --help            show this help message and exit
  --command COMMAND, -c COMMAND
                        The command to run on the victim (defaults to calc.exe)
  --ip IP, -i IP        IP to serve the payload on (defaults to 127.0.0.1)
  --port PORT, -p PORT  Port to serve the payload on (defaults to 4444)
  --output OUTPUT, -o OUTPUT
                        Filename for output, should end with extension .doc, .docx or maybe .rtf (defaults to maldoc.docx)
  --reverse REVERSE, -r REVERSE
                        Instantiate a reverse shell connection from the target at port furnished. 64-bits systems only.
```

# Workaround
Disabling MSDT from the registry should fix this issue
```
reg delete HKEY_CLASSES_ROOT\ms-msdt /f
```

# Sources
https://0xsp.com/offensive/follina-cve-2022-30190-rtf/

https://github.com/JMousqueton/PoC-CVE-2022-30190

https://github.com/JohnHammond/msdt-follina

https://youtu.be/dGCOhORNKRk

https://youtu.be/3ytqP1QvhUc
