modules = [
    ("qtawesome", "qtawesome"),
    ("requests", "requests"),
    ("urllib3", "urllib3"),
    ("yaml", "PyYAML"),
    ("bs4", "beautifulsoup4"),
    ("PySide6", "PySide6"),
    ("customtkinter", "customtkinter"),
    ("colorama", "colorama"),
    ("click", "click"),
    ("tqdm", "tqdm"),
    ("jinja2", "jinja2"),
    ("bandit", "bandit"),
    ("safety", "safety"),
    ("nmap", "python-nmap"),
    ("scapy", "scapy"),
    ("cryptography", "cryptography"),
    ("paramiko", "paramiko"),
    ("androguard", "androguard"),
    ("apkfile", "apkfile"),
    ("selenium", "selenium"),
]

for mod_name, pkg_name in modules:
    try:
        __import__(mod_name)
        print(f"{pkg_name}: OK")
    except ImportError as e:
        print(f"{pkg_name}: FAILED ({e})")
    except Exception as e:
        print(f"{pkg_name}: ERROR ({e})")
