import { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css'

const API_URL = 'http://localhost:8000'

function getRiskLevel(serverSummary) {
  if (!serverSummary) return 'green'
  const critical = serverSummary.severity_counts?.Kritik || 0
  if (critical > 0) return 'red'
  if (serverSummary.upgradable_packages > 0) return 'yellow'
  return 'green'
}

function App() {
  const [fleetSummary, setFleetSummary] = useState(null)
  const [servers, setServers] = useState([])
  const [serverSummaries, setServerSummaries] = useState({})
  const [selectedHost, setSelectedHost] = useState(null)
  const [summary, setSummary] = useState(null)
  const [packages, setPackages] = useState([])
  const [cves, setCves] = useState([])
  const [activeTab, setActiveTab] = useState('packages')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Sayfa ilk acildiginda: filo ozeti + sunucu listesi + her sunucunun ozeti
  useEffect(() => {
    Promise.all([
      axios.get(`${API_URL}/fleet/summary`),
      axios.get(`${API_URL}/servers`),
    ])
      .then(async ([fleetRes, serversRes]) => {
        setFleetSummary(fleetRes.data)
        setServers(serversRes.data)

        // her sunucu icin ozet cekelim (renk kodu icin lazim)
        const summaries = {}
        await Promise.all(
          serversRes.data.map(async (s) => {
            try {
              const res = await axios.get(`${API_URL}/servers/${s.hostname}/summary`)
              summaries[s.hostname] = res.data
            } catch (e) {
              summaries[s.hostname] = null
            }
          })
        )
        setServerSummaries(summaries)

        if (serversRes.data.length > 0) {
          setSelectedHost(serversRes.data[0].hostname)
        }
        setLoading(false)
      })
      .catch((err) => {
        console.error('Veri alinamadi:', err)
        setError("API'ye baglanilamadi. Backend calisiyor mu kontrol edin.")
        setLoading(false)
      })
  }, [])

  // Secili sunucu degistiginde detay verilerini cek
  useEffect(() => {
    if (!selectedHost) return

    axios.get(`${API_URL}/servers/${selectedHost}/summary`)
      .then(res => setSummary(res.data))
      .catch(err => console.error('Ozet alinamadi:', err))

    axios.get(`${API_URL}/servers/${selectedHost}/packages`)
      .then(res => setPackages(res.data))
      .catch(err => console.error('Paket listesi alinamadi:', err))

    axios.get(`${API_URL}/servers/${selectedHost}/cves`)
      .then(res => setCves(res.data))
      .catch(err => console.error('CVE listesi alinamadi:', err))
  }, [selectedHost])

  if (loading) {
    return <div className="status-message">Yukleniyor...</div>
  }

  if (error) {
    return <div className="status-message error">{error}</div>
  }

  const missingUpdates = packages.filter(p => p.available_version)

  return (
    <div className="container">
      <header>
        <h1>Linux Patch Monitor</h1>
        <p className="subtitle">Yama ve Guvenlik Acigi Takip Paneli</p>
      </header>

      {/* --- Fleet Dashboard --- */}
      {fleetSummary && (
        <div className="summary-cards">
          <div className="card">
            <span className="card-value">{fleetSummary.total_servers}</span>
            <span className="card-label">Toplam Sunucu</span>
          </div>
          <div className="card low">
            <span className="card-value">{fleetSummary.up_to_date_servers}</span>
            <span className="card-label">Guncel Sunucu</span>
          </div>
          <div className="card medium">
            <span className="card-value">{fleetSummary.servers_with_missing_updates}</span>
            <span className="card-label">Eksik Guncellemesi Olan</span>
          </div>
          <div className="card critical">
            <span className="card-value">{fleetSummary.critical_servers}</span>
            <span className="card-label">Kritik CVE'li Sunucu</span>
          </div>
        </div>
      )}

      {/* --- Renk Kodlu Sunucu Listesi --- */}
      <div className="server-table-section">
        <h2>Sunucular</h2>
        <table>
          <thead>
            <tr>
              <th>Durum</th>
              <th>Hostname</th>
              <th>Isletim Sistemi</th>
              <th>Son Kontrol</th>
            </tr>
          </thead>
          <tbody>
            {servers.map(s => {
              const risk = getRiskLevel(serverSummaries[s.hostname])
              return (
                <tr
                  key={s.id}
                  className={`server-row ${selectedHost === s.hostname ? 'selected' : ''}`}
                  onClick={() => setSelectedHost(s.hostname)}
                >
                  <td><span className={`risk-dot risk-${risk}`}></span></td>
                  <td>{s.hostname}</td>
                  <td>{s.os_name} {s.os_version}</td>
                  <td>{s.last_checked ? new Date(s.last_checked).toLocaleString() : '-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* --- Sunucu Detay --- */}
      {selectedHost && (
        <div className="cve-section">
          <h2>{selectedHost} - Detay</h2>

          {summary && (
            <div className="summary-cards">
              <div className="card">
                <span className="card-value">{summary.total_packages}</span>
                <span className="card-label">Toplam Paket</span>
              </div>
              <div className="card">
                <span className="card-value">{summary.upgradable_packages}</span>
                <span className="card-label">Guncelleme Bekleyen</span>
              </div>
              <div className="card critical">
                <span className="card-value">{summary.severity_counts.Kritik || 0}</span>
                <span className="card-label">Kritik CVE</span>
              </div>
              <div className="card high">
                <span className="card-value">{summary.severity_counts.Yuksek || 0}</span>
                <span className="card-label">Yuksek CVE</span>
              </div>
              <div className="card medium">
                <span className="card-value">{summary.severity_counts.Orta || 0}</span>
                <span className="card-label">Orta CVE</span>
              </div>
              <div className="card low">
                <span className="card-value">{summary.severity_counts.Dusuk || 0}</span>
                <span className="card-label">Dusuk CVE</span>
              </div>
            </div>
          )}

          <div className="detail-tabs">
            <button
              className={activeTab === 'packages' ? 'active' : ''}
              onClick={() => setActiveTab('packages')}
            >
              Kurulu Paketler ({packages.length})
            </button>
            <button
              className={activeTab === 'missing' ? 'active' : ''}
              onClick={() => setActiveTab('missing')}
            >
              Eksik Guncellemeler ({missingUpdates.length})
            </button>
            <button
              className={activeTab === 'cves' ? 'active' : ''}
              onClick={() => setActiveTab('cves')}
            >
              CVE Kayitlari ({cves.length})
            </button>
          </div>

          {activeTab === 'packages' && (
            packages.length === 0 ? (
              <div className="empty-note">Kurulu paket bilgisi bulunamadi.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Paket</th>
                    <th>Kurulu Surum</th>
                    <th>Mevcut Surum</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((p, i) => (
                    <tr key={i}>
                      <td>{p.package_name}</td>
                      <td>{p.installed_version}</td>
                      <td>{p.available_version || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {activeTab === 'missing' && (
            missingUpdates.length === 0 ? (
              <div className="empty-note">Bu sunucuda eksik guncelleme yok.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Paket</th>
                    <th>Kurulu Surum</th>
                    <th>Mevcut Surum</th>
                  </tr>
                </thead>
                <tbody>
                  {missingUpdates.map((p, i) => (
                    <tr key={i}>
                      <td>{p.package_name}</td>
                      <td>{p.installed_version}</td>
                      <td>{p.available_version}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {activeTab === 'cves' && (
            cves.length === 0 ? (
              <div className="empty-note">Bu sunucuda tespit edilmis CVE yok.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Paket</th>
                    <th>Surum</th>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>Onem</th>
                  </tr>
                </thead>
                <tbody>
                  {cves.map((cve, i) => (
                    <tr key={i} className={`severity-${cve.severity}`}>
                      <td>{cve.package_name}</td>
                      <td>{cve.installed_version}</td>
                      <td>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {cve.cve_id}
                        </a>
                      </td>
                      <td>{cve.cvss_score ?? '-'}</td>
                      <td>{cve.severity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
        </div>
      )}
    </div>
  )
}

export default App
