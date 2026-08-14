CREATE TABLE servers (
id SERIAL PRIMARY KEY,
hostname VARCHAR(255) NOT NULL UNIQUE,
ip_address VARCHAR (45),
os_name VARCHAR(100),
os_version VARCHAR(100),
last_checked TIMESTAMP,
created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE packages (
id SERIAL PRIMARY KEY,
server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
package_name VARCHAR(255) NOT NULL,
installed_version VARCHAR(255) NOT NULL,
available_version VARCHAR(255),
updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE cve_matches (
id SERIAL PRIMARY KEY,
package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
cve_id VARCHAR(50) NOT NULL,
description TEXT,
cvss_score NUMERIC(3,1),
severity VARCHAR(20),
notified BOOLEAN DEFAULT FALSE,
matched_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE nvd_cve_cache (
cve_id VARCHAR(50) PRIMARY KEY,
description TEXT,
cvss_score NUMERIC(3,1),
severity VARCHAR(20),
affected_product VARCHAR(255),
synced_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_pacages_server_id ON packages(server_id);
CREATE INDEX idx_cve_matches_packages_id ON cve_matches(package_id);
CREATE INDEX idx_nvd_cache_product ON nvd_cve_cache(affected_product);

CREATE TABLE nvd_sync_state (
product_name VARCHAR(255) PRIMARY KEY,
last_synced_at TIMESTAMP 
);

