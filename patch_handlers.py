import re

with open("internal/web/handlers.go", "r") as f:
    content = f.read()

pattern = r'for ipKey, bytes := range hostBytes \{\n\t\tif s\.geoLookup == nil \{\n\t\t\tcontinue\n\t\t\}\n\t\tinfo, ok := geoCache\[ip\]'
replacement = r'for ipKey, bytes := range hostBytes {\n\t\tif s.geoLookup == nil {\n\t\t\tcontinue\n\t\t}\n\t\tip := model.SafeIPString(ipKey[:])\n\t\tinfo, ok := geoCache[ip]'

content = re.sub(pattern, replacement, content, count=1)

with open("internal/web/handlers.go", "w") as f:
    f.write(content)
