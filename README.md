# follina (POC)
All about CVE-2022-30190, aka follina, that is a RCE vulnerability that affects Microsoft Support Diagnostic Tools (MSDT) on Office apps such as Word. This is a very simple POC, feel free to check the sources below for more threat intelligence.

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
