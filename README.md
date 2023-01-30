# DeCatraz

An test deobfuscator for Alcartz obfuscator's control flow flattening based on unicorn

# Usage
```
python main.py -f [FILE] 
    --addr [file offset of target function in hex format] 
    -s [arget function size]
```

# NOTE
this script can only remove control-flow obfuscation and the mov obfuscation!
The other obfuscations is rather easy to remove