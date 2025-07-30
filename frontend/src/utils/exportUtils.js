import { saveAs } from 'file-saver';

// Export utilities for OSINT results
export const exportUtils = {
  // Export data as JSON file
  exportAsJSON: (data, filename = 'osint-results') => {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const timestamp = new Date().toISOString().split('T')[0];
    saveAs(blob, `${filename}-${timestamp}.json`);
  },

  // Export data as HTML report
  exportAsHTML: (data, filename = 'osint-report') => {
    const html = generateHTMLReport(data);
    const blob = new Blob([html], { type: 'text/html' });
    const timestamp = new Date().toISOString().split('T')[0];
    saveAs(blob, `${filename}-${timestamp}.html`);
  },

  // Export data as CSV (for tabular data)
  exportAsCSV: (data, filename = 'osint-data') => {
    const csv = generateCSV(data);
    const blob = new Blob([csv], { type: 'text/csv' });
    const timestamp = new Date().toISOString().split('T')[0];
    saveAs(blob, `${filename}-${timestamp}.csv`);
  },

  // Export data as plain text summary
  exportAsText: (data, filename = 'osint-summary') => {
    const text = generateTextSummary(data);
    const blob = new Blob([text], { type: 'text/plain' });
    const timestamp = new Date().toISOString().split('T')[0];
    saveAs(blob, `${filename}-${timestamp}.txt`);
  }
};

// Main export function for components
export const exportData = (data, format, filename) => {
  switch (format) {
    case 'json':
      exportUtils.exportAsJSON(data, filename);
      break;
    case 'html':
      exportUtils.exportAsHTML(data, filename);
      break;
    case 'csv':
      exportUtils.exportAsCSV(data, filename);
      break;
    case 'txt':
      exportUtils.exportAsText(data, filename);
      break;
    default:
      console.error('Unsupported export format:', format);
  }
};

// Generate HTML report from OSINT data
function generateHTMLReport(data) {
  const timestamp = new Date().toISOString();
  const riskColor = getRiskColor(data.overallRisk);
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Hawk Report - ${data.query}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            opacity: 0.9;
            margin-top: 10px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #4a5568;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
            ${riskColor.css}
        }
        .meta-info {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .key-value {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }
        .key {
            font-weight: 600;
            color: #4a5568;
        }
        .value {
            color: #2d3748;
        }
        .recommendations {
            background: #ebf8ff;
            border: 1px solid #bee3f8;
            border-radius: 8px;
            padding: 20px;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 8px;
        }
        .footer {
            text-align: center;
            color: #718096;
            font-size: 0.9em;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
        }
        pre {
            background: #1a202c;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        .highlight {
            background: #fef5e7;
            padding: 2px 4px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🦅 OSINT Hawk Report</h1>
        <div class="subtitle">Intelligence Analysis Report</div>
    </div>

    <div class="card">
        <h2>📋 Investigation Summary</h2>
        <div class="meta-info">
            <div class="key-value">
                <span class="key">Target:</span>
                <span class="value highlight">${escapeHtml(data.query)}</span>
            </div>
            <div class="key-value">
                <span class="key">Investigation Type:</span>
                <span class="value">${data.type.toUpperCase()}</span>
            </div>
            <div class="key-value">
                <span class="key">Risk Level:</span>
                <span class="value"><span class="risk-badge">${data.overallRisk}</span></span>
            </div>
            <div class="key-value">
                <span class="key">Investigation Date:</span>
                <span class="value">${new Date(data.timestamp).toLocaleString()}</span>
            </div>
            <div class="key-value">
                <span class="key">Report Generated:</span>
                <span class="value">${new Date(timestamp).toLocaleString()}</span>
            </div>
        </div>
    </div>

    ${generateTypeSpecificHTML(data)}

    ${data.recommendations && data.recommendations.length > 0 ? `
    <div class="card">
        <h2>💡 Recommendations</h2>
        <div class="recommendations">
            <ul>
                ${data.recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
            </ul>
        </div>
    </div>
    ` : ''}

    <div class="card">
        <h2>📊 Raw Data</h2>
        <pre>${JSON.stringify(data, null, 2)}</pre>
    </div>

    <div class="footer">
        <p>Generated by OSINT Hawk - Open Source Intelligence Tool</p>
        <p><strong>Disclaimer:</strong> This report is for educational and legitimate security research purposes only.</p>
    </div>
</body>
</html>`;
}

// Generate type-specific HTML content
function generateTypeSpecificHTML(data) {
  switch (data.type) {
    case 'username':
      return generateUsernameHTML(data);
    case 'email':
      return generateEmailHTML(data);
    case 'domain':
      return generateDomainHTML(data);
    case 'ip':
      return generateIPHTML(data);
    case 'file':
      return generateFileHTML(data);
    default:
      return '';
  }
}

function generateUsernameHTML(data) {
  return `
    <div class="card">
        <h2>👤 Username Analysis</h2>
        <div class="meta-info">
            <div class="key-value">
                <span class="key">Platforms Checked:</span>
                <span class="value">${data.totalPlatforms}</span>
            </div>
            <div class="key-value">
                <span class="key">Found On:</span>
                <span class="value">${data.foundOn} platforms</span>
            </div>
        </div>
        
        <div class="grid">
            ${data.platforms.map(platform => `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px;">
                    <h3>${platform.platform}</h3>
                    <div class="key-value">
                        <span class="key">Status:</span>
                        <span class="value">${platform.exists ? '✅ Found' : '❌ Not Found'}</span>
                    </div>
                    ${platform.profileUrl ? `
                    <div class="key-value">
                        <span class="key">Profile URL:</span>
                        <span class="value"><a href="${platform.profileUrl}" target="_blank">${platform.profileUrl}</a></span>
                    </div>
                    ` : ''}
                    ${platform.followers !== undefined ? `
                    <div class="key-value">
                        <span class="key">Followers:</span>
                        <span class="value">${platform.followers}</span>
                    </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>
    </div>
  `;
}

function generateEmailHTML(data) {
  return `
    <div class="card">
        <h2>📧 Email Analysis</h2>
        
        ${data.breachCheck ? `
        <div style="margin-bottom: 20px;">
            <h3>🔍 Breach Analysis</h3>
            <div class="key-value">
                <span class="key">Breaches Found:</span>
                <span class="value">${data.breachCheck.breachCount || 0}</span>
            </div>
            ${data.breachCheck.breaches && data.breachCheck.breaches.length > 0 ? `
                <div style="margin-top: 15px;">
                    ${data.breachCheck.breaches.map(breach => `
                        <div style="border: 1px solid #fed7d7; background: #fef5f5; padding: 10px; border-radius: 6px; margin: 10px 0;">
                            <strong>${breach.name}</strong> - ${breach.breachDate}
                            <br><small>${breach.description}</small>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        </div>
        ` : ''}
        
        ${data.domainAnalysis ? `
        <div>
            <h3>🌐 Domain Analysis</h3>
            <div class="key-value">
                <span class="key">Domain:</span>
                <span class="value">${data.domainAnalysis.domain}</span>
            </div>
            <div class="key-value">
                <span class="key">Type:</span>
                <span class="value">${data.domainAnalysis.analysis?.type || 'Unknown'}</span>
            </div>
            <div class="key-value">
                <span class="key">Disposable:</span>
                <span class="value">${data.domainAnalysis.isDisposable ? '⚠️ Yes' : '✅ No'}</span>
            </div>
        </div>
        ` : ''}
    </div>
  `;
}

function generateDomainHTML(data) {
  return `
    <div class="card">
        <h2>🌐 Domain Analysis</h2>
        
        ${data.whoisData?.data ? `
        <div style="margin-bottom: 20px;">
            <h3>📋 WHOIS Information</h3>
            <div class="key-value">
                <span class="key">Registrar:</span>
                <span class="value">${data.whoisData.data.registrar || 'N/A'}</span>
            </div>
            <div class="key-value">
                <span class="key">Creation Date:</span>
                <span class="value">${data.whoisData.data.creationDate || 'N/A'}</span>
            </div>
            <div class="key-value">
                <span class="key">Expiration Date:</span>
                <span class="value">${data.whoisData.data.expirationDate || 'N/A'}</span>
            </div>
        </div>
        ` : ''}
        
        ${data.subdomains?.subdomains ? `
        <div>
            <h3>🔍 Subdomains (${data.subdomains.count})</h3>
            <div style="max-height: 200px; overflow-y: auto; background: #f7fafc; padding: 10px; border-radius: 6px;">
                ${data.subdomains.subdomains.slice(0, 20).map(sub => `<div>${sub}</div>`).join('')}
                ${data.subdomains.count > 20 ? '<div><em>...and more</em></div>' : ''}
            </div>
        </div>
        ` : ''}
    </div>
  `;
}

function generateIPHTML(data) {
  return `
    <div class="card">
        <h2>🌍 IP Address Analysis</h2>
        
        ${data.geolocation ? `
        <div style="margin-bottom: 20px;">
            <h3>📍 Geolocation</h3>
            <div class="key-value">
                <span class="key">Country:</span>
                <span class="value">${data.geolocation.location?.countryName || 'Unknown'}</span>
            </div>
            <div class="key-value">
                <span class="key">City:</span>
                <span class="value">${data.geolocation.location?.city || 'Unknown'}</span>
            </div>
            <div class="key-value">
                <span class="key">ISP:</span>
                <span class="value">${data.geolocation.network?.isp || 'Unknown'}</span>
            </div>
        </div>
        ` : ''}
        
        ${data.threatIntelligence ? `
        <div>
            <h3>⚠️ Threat Intelligence</h3>
            <div class="key-value">
                <span class="key">Abuse Confidence:</span>
                <span class="value">${data.threatIntelligence.abuseConfidence || 0}%</span>
            </div>
            <div class="key-value">
                <span class="key">Total Reports:</span>
                <span class="value">${data.threatIntelligence.totalReports || 0}</span>
            </div>
        </div>
        ` : ''}
    </div>
  `;
}

function generateFileHTML(data) {
  return `
    <div class="card">
        <h2>📁 File Analysis</h2>
        
        <div style="margin-bottom: 20px;">
            <h3>📋 File Information</h3>
            <div class="key-value">
                <span class="key">File Name:</span>
                <span class="value">${data.metadata?.originalName || 'Unknown'}</span>
            </div>
            <div class="key-value">
                <span class="key">File Size:</span>
                <span class="value">${formatFileSize(data.metadata?.size)}</span>
            </div>
            <div class="key-value">
                <span class="key">File Type:</span>
                <span class="value">${data.metadata?.extension || 'Unknown'}</span>
            </div>
        </div>
        
        ${data.hashes ? `
        <div style="margin-bottom: 20px;">
            <h3>🔒 File Hashes</h3>
            <div class="key-value">
                <span class="key">MD5:</span>
                <span class="value" style="font-family: monospace;">${data.hashes.md5}</span>
            </div>
            <div class="key-value">
                <span class="key">SHA1:</span>
                <span class="value" style="font-family: monospace;">${data.hashes.sha1}</span>
            </div>
            <div class="key-value">
                <span class="key">SHA256:</span>
                <span class="value" style="font-family: monospace;">${data.hashes.sha256}</span>
            </div>
        </div>
        ` : ''}
        
        ${data.virusTotalResult?.stats ? `
        <div>
            <h3>🛡️ VirusTotal Scan</h3>
            <div class="key-value">
                <span class="key">Detections:</span>
                <span class="value">${data.virusTotalResult.stats.malicious}/${data.virusTotalResult.stats.total}</span>
            </div>
            <div class="key-value">
                <span class="key">Scan Date:</span>
                <span class="value">${new Date(data.virusTotalResult.scanDate).toLocaleString()}</span>
            </div>
        </div>
        ` : ''}
    </div>
  `;
}

// Generate CSV from data
function generateCSV(data) {
  // This is a simplified CSV generation - you might want to customize based on data type
  const headers = ['Field', 'Value'];
  const rows = [headers];
  
  function addRow(key, value) {
    rows.push([key, value]);
  }
  
  addRow('Query', data.query);
  addRow('Type', data.type);
  addRow('Risk Level', data.overallRisk);
  addRow('Timestamp', data.timestamp);
  
  // Add type-specific data
  if (data.type === 'username') {
    addRow('Total Platforms', data.totalPlatforms);
    addRow('Found On', data.foundOn);
  }
  
  return rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
}

// Generate text summary
function generateTextSummary(data) {
  const lines = [];
  lines.push('OSINT HAWK INVESTIGATION REPORT');
  lines.push('================================');
  lines.push('');
  lines.push(`Target: ${data.query}`);
  lines.push(`Type: ${data.type.toUpperCase()}`);
  lines.push(`Risk Level: ${data.overallRisk.toUpperCase()}`);
  lines.push(`Investigation Date: ${new Date(data.timestamp).toLocaleString()}`);
  lines.push('');
  
  if (data.recommendations && data.recommendations.length > 0) {
    lines.push('RECOMMENDATIONS:');
    data.recommendations.forEach((rec, index) => {
      lines.push(`${index + 1}. ${rec}`);
    });
    lines.push('');
  }
  
  lines.push('DISCLAIMER:');
  lines.push('This report is for educational and legitimate security research purposes only.');
  lines.push('');
  lines.push('Generated by OSINT Hawk');
  
  return lines.join('\n');
}

// Utility functions
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function getRiskColor(riskLevel) {
  const colors = {
    none: { css: 'background: #f7fafc; color: #4a5568;' },
    low: { css: 'background: #f0fff4; color: #22543d;' },
    medium: { css: 'background: #fffbeb; color: #92400e;' },
    high: { css: 'background: #fef2f2; color: #991b1b;' },
    critical: { css: 'background: #fdf4ff; color: #701a75;' },
  };
  return colors[riskLevel] || colors.none;
}

function formatFileSize(bytes) {
  if (!bytes) return 'Unknown';
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}
