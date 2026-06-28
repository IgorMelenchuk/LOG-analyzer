import re

SQLi_PATTERN = re.compile(r"[\'\"`;]')]|[\'\"`]--|[^=]+==|[{}]+", re.I)
XSS_PATTERN = re.compile(r"<script.*?>.*?</script>|<img[^>]*src|[\(\)\-\"\'][\=\-\#\$\;]", re.I)
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.\/|\.\\")
DDOS_PATTERN = re.compile(r"GET \/.*? HTTP\/1\.1\ [0-9]{3}\ -")

# Добавление новых шаблонов для безопасности
HONEYPOT_PATTERN = re.compile(r"http[s]?://(\b\d{1,3}\.){3}\d{1,3}", re.I)