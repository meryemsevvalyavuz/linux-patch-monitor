import { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css'

const API_URL = 'http://localhost:8000'

function App() {
  const [servers, setServers] = useState([])
  const [selectedHost, setSelectedHost] = useState(null)
  const [summary, setSummary] = useState(null)
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Sayfa ilk acildiginda sunucu listesini cek
  useEffect(() => {
    axios.get(`${API_URL}/servers`)
      .then(res => {
        setServers(res.data)
        // ilk sunucuyu otomatik secili yapalim, tek sunucumuz oldugu icin pratik
        if (res.data.length > 0) {
          setSelectedHost(res.data[0].hostname)
        }
        setLoading(false)
      })
      .catch(err => {
        console.error('Sunucu listesi alinamadi:', err)
        setError('API\'ye baglanilamadi. Backend calisiyor mu kontrol edin.')
        setLoading(false)
      })
  }, [])

  // Secili sunucu degistiginde ozet ve CVE verisini cek
  useEffect(() => {
    if (!selectedHost) return

    axios.get(`${API_URL}/servers/${selectedHost}/summary`)
      .then(res => setSummary(res.data))
      .catch(err => console.error('Ozet alinamadi:', err))

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

  return (
    <div className="container">
      <header>
        <h1>Linux Patch Monitor</h1>
        <p className="subtitle">Yama ve Guvenlik Acigi Takip Paneli</p>
      </header>

      <div className="server-selector">
        <label>Sunucu: </label>
        <select value={selectedHost || ''} onChange={e => setSelectedHost(e.target.value)}>
          {servers.map(s => (
            <option key={s.id} value={s.hostname}>{s.hostname}</option>
          ))}
        </select>
      </div>

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

      <div className="cve-section">
        <h2>Guvenlik Acigi Detaylari ({cves.length})</h2>
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
      </div>
    </div>
  )
}

export default App
