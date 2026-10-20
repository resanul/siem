import urllib.request
import json

sample_ips = [
    '23.212.164.123', '142.251.154.119', '20.165.94.63',
    '135.234.160.246', '13.207.115.146', '40.126.35.129',
    '2.19.212.199', '150.171.27.11', '142.251.223.14',
    '151.101.129.91', '34.93.153.102', '148.113.16.33'
]

print("Resolving GeoIP for sample IPs:")
for ip in sample_ips:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,as"
        req = urllib.request.urlopen(url, timeout=2)
        res = json.loads(req.read().decode())
        if res.get("status") == "success":
            print(f"  {ip:16} -> {res.get('city')}, {res.get('country')} (Lat: {res.get('lat')}, Lon: {res.get('lon')}) | {res.get('isp')}")
    except Exception as e:
        print(f"  {ip:16} -> Error: {e}")
