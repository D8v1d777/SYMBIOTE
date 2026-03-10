with open('OmniVulnScanner.py', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total: {len(lines)} lines")
for i in range(1758, min(1776, len(lines))):
    s = repr(lines[i])[:90]
    print(f"  {i+1}: {s}")
