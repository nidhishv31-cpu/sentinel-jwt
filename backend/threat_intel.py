import urllib.request
from datetime import datetime
from backend.database import get_connection

BLOCKLIST_FEEDS = [
    # Firehol Level 1 - confirmed attacks
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    # Emerging Threats compromised IPs  
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
]

def fetch_and_store_feeds(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Clear old entries
    cursor.execute("DELETE FROM threat_intel_entries")
    
    count = 0
    updated_at = datetime.utcnow().isoformat()
    
    for feed in BLOCKLIST_FEEDS:
        try:
            req = urllib.request.Request(feed, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    ip_address = line
                    category = "compromised" if "emergingthreats" in feed else "confirmed_attack"
                    
                    cursor.execute(
                        "INSERT INTO threat_intel_entries (ip_address, feed_source, category, updated_at) VALUES (?, ?, ?, ?)",
                        (ip_address, feed, category, updated_at)
                    )
                    count += 1
        except Exception as e:
            print(f"Error fetching {feed}: {e}")
            
    conn.commit()
    conn.close()
    return count

def lookup_ip(ip_address, db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel_entries WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "is_known_threat": True,
            "feed_source": row["feed_source"],
            "category": row["category"]
        }
    return None

def get_threat_intel_stats(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM threat_intel_entries")
    total = cursor.fetchone()["total"]
    
    cursor.execute("SELECT feed_source, COUNT(*) as count FROM threat_intel_entries GROUP BY feed_source")
    feeds = {row["feed_source"]: row["count"] for row in cursor.fetchall()}
    
    cursor.execute("SELECT MAX(updated_at) as last_updated FROM threat_intel_entries")
    last_updated = cursor.fetchone()["last_updated"]
    
    conn.close()
    return {
        "total_entries": total,
        "entries_per_feed": feeds,
        "last_updated": last_updated
    }
