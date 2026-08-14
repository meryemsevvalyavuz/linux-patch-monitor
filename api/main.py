"""
Linux Patch Monitor - Backend API
Agent'lardan gelen sunucu ve paket bilgisini karsilar, veritabanina yazar.
Panel icin ozet ve CVE detay endpoint'leri de burada.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

from config import DB_CONFIG

app = FastAPI(title="Patch Monitor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


# --- Pydantic modelleri ---

class ServerRegister(BaseModel):
    hostname: str
    ip_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None


class PackageItem(BaseModel):
    package_name: str
    installed_version: str
    available_version: str | None = None


class PackagesPayload(BaseModel):
    packages: list[PackageItem]


# --- Endpoint 1: Sunucu kaydi/guncellemesi ---

@app.post("/servers/register")
def register_server(server: ServerRegister):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO servers (hostname, ip_address, os_name, os_version, last_checked)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (hostname)
        DO UPDATE SET
            ip_address = EXCLUDED.ip_address,
            os_name = EXCLUDED.os_name,
            os_version = EXCLUDED.os_version,
            last_checked = EXCLUDED.last_checked
        RETURNING id
    """, (server.hostname, server.ip_address, server.os_name, server.os_version, datetime.now()))

    server_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "ok", "server_id": server_id}


# --- Endpoint 2: Paket listesini kaydet (UPSERT mantigiyla) ---

@app.post("/servers/{hostname}/packages")
def receive_packages(hostname: str, payload: PackagesPayload):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    if row is None:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Sunucu kayitli degil, once register cagirin")

    server_id = row[0]

    cur.execute("SELECT id, package_name FROM packages WHERE server_id = %s", (server_id,))
    existing = {name: pid for pid, name in cur.fetchall()}

    incoming_names = set()

    for pkg in payload.packages:
        incoming_names.add(pkg.package_name)

        if pkg.package_name in existing:
            cur.execute("""
                UPDATE packages
                SET installed_version = %s, available_version = %s, updated_at = NOW()
                WHERE id = %s
            """, (pkg.installed_version, pkg.available_version, existing[pkg.package_name]))
        else:
            cur.execute("""
                INSERT INTO packages (server_id, package_name, installed_version, available_version)
                VALUES (%s, %s, %s, %s)
            """, (server_id, pkg.package_name, pkg.installed_version, pkg.available_version))

    removed_names = set(existing.keys()) - incoming_names
    for name in removed_names:
        cur.execute("DELETE FROM packages WHERE id = %s", (existing[name],))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "ok",
        "packages_saved": len(payload.packages),
        "removed": len(removed_names),
    }


# --- Endpoint: Filo geneli ozet (Dashboard icin) ---

@app.get("/fleet/summary")
def get_fleet_summary():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) as total FROM servers")
    total_servers = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(DISTINCT server_id) as total
        FROM packages
        WHERE available_version IS NOT NULL
    """)
    servers_with_missing_updates = cur.fetchone()["total"]

    up_to_date_servers = total_servers - servers_with_missing_updates

    cur.execute("""
        SELECT COUNT(DISTINCT p.server_id) as total
        FROM cve_matches cm
        JOIN packages p ON cm.package_id = p.id
        WHERE cm.severity = 'Kritik'
    """)
    critical_servers = cur.fetchone()["total"]

    cur.close()
    conn.close()

    return {
        "total_servers": total_servers,
        "up_to_date_servers": up_to_date_servers,
        "servers_with_missing_updates": servers_with_missing_updates,
        "critical_servers": critical_servers,
    }


# --- Endpoint 3: Sunucu listesi ---

@app.get("/servers")
def list_servers():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM servers ORDER BY hostname")
    servers = cur.fetchall()

    cur.close()
    conn.close()

    return servers


# --- Endpoint 4: Sunucu ozet bilgisi (panel icin) ---

@app.get("/servers/{hostname}/summary")
def get_server_summary(hostname: str):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    if row is None:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Sunucu bulunamadi")

    server_id = row["id"]

    cur.execute("SELECT COUNT(*) as total FROM packages WHERE server_id = %s", (server_id,))
    total_packages = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(*) as total FROM packages
        WHERE server_id = %s AND available_version IS NOT NULL
    """, (server_id,))
    upgradable_packages = cur.fetchone()["total"]

    cur.execute("""
        SELECT cm.severity, COUNT(*) as total
        FROM cve_matches cm
        JOIN packages p ON cm.package_id = p.id
        WHERE p.server_id = %s
        GROUP BY cm.severity
    """, (server_id,))
    severity_counts = {row["severity"]: row["total"] for row in cur.fetchall()}

    cur.close()
    conn.close()

    return {
        "hostname": hostname,
        "total_packages": total_packages,
        "upgradable_packages": upgradable_packages,
        "severity_counts": severity_counts,
    }


# --- Endpoint 5: Sunucunun CVE detay listesi (panel icin) ---

@app.get("/servers/{hostname}/cves")
def get_server_cves(hostname: str):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    if row is None:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Sunucu bulunamadi")

    server_id = row["id"]

    cur.execute("""
        SELECT p.package_name, p.installed_version, cm.cve_id, cm.cvss_score,
               cm.severity, cm.description
        FROM cve_matches cm
        JOIN packages p ON cm.package_id = p.id
        WHERE p.server_id = %s
        ORDER BY cm.cvss_score DESC NULLS LAST
    """, (server_id,))

    results = cur.fetchall()

    cur.close()
    conn.close()

    return results


# --- Endpoint 6: Sunucunun kurulu paket listesi (panel icin) ---

@app.get("/servers/{hostname}/packages")
def get_server_packages(hostname: str):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    if row is None:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Sunucu bulunamadi")

    server_id = row["id"]

    cur.execute("""
        SELECT package_name, installed_version, available_version
        FROM packages
        WHERE server_id = %s
        ORDER BY package_name
    """, (server_id,))

    results = cur.fetchall()

    cur.close()
    conn.close()

    return results
