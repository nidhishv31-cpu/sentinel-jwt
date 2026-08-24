import urllib.request
import json
from datetime import datetime
from backend.database import get_connection

def is_private_ip(ip: str) -> bool:
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("127."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except:
                pass
    return False

def geolocate_ip(ip_address: str) -> dict:
    if is_private_ip(ip_address):
        return {
            "status": "success",
            "query": ip_address,
            "country": "Local Network",
            "countryCode": "LOC",
            "city": "Local",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Private",
            "org": "Private",
            "as": "Private"
        }
    
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        return {"status": "fail", "query": ip_address, "message": str(e)}

def batch_geolocate(ip_list: list, db_path: str) -> list:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    results = []
    ips_to_fetch = []
    
    for ip in set(ip_list):
        cursor.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            results.append({
                "status": "success",
                "query": row["ip"],
                "country": row["country"],
                "countryCode": row["country_code"],
                "city": row["city"],
                "lat": row["lat"],
                "lon": row["lon"],
                "isp": row["isp"]
            })
        else:
            ips_to_fetch.append(ip)
            
    cached_at = datetime.utcnow().isoformat()
    for ip in ips_to_fetch:
        geo = geolocate_ip(ip)
        if geo.get("status") == "success":
            cursor.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, country, country_code, city, lat, lon, isp, cached_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ip, geo.get("country"), geo.get("countryCode"), geo.get("city"), geo.get("lat"), geo.get("lon"), geo.get("isp"), cached_at)
            )
        results.append(geo)
        
    conn.commit()
    conn.close()
    return results

def get_attack_map_data(db_path: str) -> list:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT source_ip, COUNT(*) as event_count FROM security_events GROUP BY source_ip")
    rows = cursor.fetchall()
    
    ip_counts = {row["source_ip"]: row["event_count"] for row in rows}
    conn.close()
    
    geo_results = batch_geolocate(list(ip_counts.keys()), db_path)
    
    map_data = []
    for geo in geo_results:
        if geo.get("status") == "success":
            ip = geo["query"]
            map_data.append({
                "ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "event_count": ip_counts.get(ip, 0)
            })
            
    return map_data
