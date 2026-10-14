package report

import (
	"html/template"
	"io"
	"strings"
	"sudo-check/pkg/audit"
)

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Sudoers Security Audit Report. Identifies security misconfigurations, dangerous defaults, and GTFObins bypass vulnerabilities.">
    <title>Sudoers Audit Report - {{.Hostname}}</title>
    <style>
        :root {
            --bg-gradient-start: #0b0f19;
            --bg-gradient-end: #020617;
            --panel-bg: rgba(17, 24, 39, 0.6);
            --panel-border: rgba(255, 255, 255, 0.05);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --font-primary: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-code: 'Space Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            --accent-crit: #ff453a;
            --accent-high: #bf5af2;
            --accent-med: #ff9f0a;
            --accent-low: #64d2ff;
            --accent-info: #0a84ff;
            --accent-crit-bg: rgba(255, 69, 58, 0.15);
            --accent-high-bg: rgba(191, 90, 242, 0.15);
            --accent-med-bg: rgba(255, 159, 10, 0.15);
            --accent-low-bg: rgba(100, 210, 255, 0.15);
            --accent-info-bg: rgba(10, 132, 255, 0.15);
            --shadow-glow: rgba(0, 0, 0, 0.5);
        }

        [data-theme="light"] {
            --bg-gradient-start: #f8fafc;
            --bg-gradient-end: #e2e8f0;
            --panel-bg: rgba(255, 255, 255, 0.8);
            --panel-border: rgba(0, 0, 0, 0.06);
            --text-main: #0f172a;
            --text-muted: #475569;
            --accent-crit-bg: rgba(255, 69, 58, 0.1);
            --accent-high-bg: rgba(191, 90, 242, 0.1);
            --accent-med-bg: rgba(255, 159, 10, 0.1);
            --accent-low-bg: rgba(100, 210, 255, 0.1);
            --accent-info-bg: rgba(10, 132, 255, 0.1);
            --shadow-glow: rgba(148, 163, 184, 0.2);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            transition: background-color 0.3s, border-color 0.3s, color 0.3s;
        }

        body {
            font-family: var(--font-primary);
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem 1rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Header Style */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            padding: 1.5rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            box-shadow: 0 8px 32px var(--shadow-glow);
        }

        .header-title h1 {
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
        }

        .theme-toggle-btn {
            background: transparent;
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            cursor: pointer;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .theme-toggle-btn:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        /* Metrics Dashboard */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .metric-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 4px 24px var(--shadow-glow);
            position: relative;
            overflow: hidden;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
        }

        .card-crit::before { background: var(--accent-crit); }
        .card-high::before { background: var(--accent-high); }
        .card-med::before { background: var(--accent-med); }
        .card-low::before { background: var(--accent-low); }
        .card-info::before { background: var(--accent-info); }

        .metric-num {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }

        .metric-label {
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }

        /* Filter Controls */
        .controls-panel {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .search-bar {
            display: flex;
            gap: 0.5rem;
        }

        .search-input {
            flex-grow: 1;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            font-family: var(--font-primary);
            font-size: 0.95rem;
        }

        .search-input:focus {
            outline: 2px solid #6366f1;
            outline-offset: -1px;
        }

        .filter-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .filter-btn {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 500;
            cursor: pointer;
        }

        .filter-btn.active {
            background: #6366f1;
            color: #ffffff;
            border-color: #6366f1;
        }

        .filter-btn:hover:not(.active) {
            background: rgba(255, 255, 255, 0.08);
        }

        /* Metadata Section */
        .system-meta {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 2rem;
            font-size: 0.9rem;
            display: flex;
            flex-wrap: wrap;
            gap: 2rem;
        }

        .meta-item strong {
            color: var(--text-muted);
            margin-right: 0.5rem;
        }

        /* Findings List */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .finding-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
        }

        .finding-title-sec {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
        }

        .finding-id {
            font-family: var(--font-code);
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 700;
            letter-spacing: 0.05em;
        }

        .finding-title {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .sev-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.3rem 0.8rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .badge-crit { background: var(--accent-crit-bg); color: var(--accent-crit); border: 1px solid rgba(255, 69, 58, 0.3); }
        .badge-high { background: var(--accent-high-bg); color: var(--accent-high); border: 1px solid rgba(191, 90, 242, 0.3); }
        .badge-med { background: var(--accent-med-bg); color: var(--accent-med); border: 1px solid rgba(255, 159, 10, 0.3); }
        .badge-low { background: var(--accent-low-bg); color: var(--accent-low); border: 1px solid rgba(100, 210, 255, 0.3); }
        .badge-info { background: var(--accent-info-bg); color: var(--accent-info); border: 1px solid rgba(10, 132, 255, 0.3); }

        .finding-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            background: rgba(0, 0, 0, 0.15);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
        }

        .finding-detail-item strong {
            color: var(--text-muted);
            margin-right: 0.5rem;
        }

        .finding-desc {
            font-size: 0.95rem;
            color: var(--text-main);
        }

        .finding-remediation {
            border-left: 3px solid #10b981;
            padding-left: 1rem;
            margin-top: 0.5rem;
        }

        .remediation-title {
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #10b981;
            margin-bottom: 0.3rem;
        }

        .remediation-content {
            font-size: 0.9rem;
            color: var(--text-main);
        }

        pre {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--panel-border);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-family: var(--font-code);
            font-size: 0.85rem;
            overflow-x: auto;
            margin-top: 0.5rem;
            color: #34d399;
        }

        .no-findings {
            text-align: center;
            padding: 3rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            color: var(--text-muted);
        }

        @media (max-width: 768px) {
            header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }
            .theme-toggle-btn {
                align-self: flex-end;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>Sudoers Security Audit Report</h1>
                <p>Generated by sudo-check utility</p>
            </div>
            <button class="theme-toggle-btn" id="themeToggleBtn" onclick="toggleTheme()">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707.707M12 5a7 7 0 100 14 7 7 0 000-14z"/></svg>
                Toggle Theme
            </button>
        </header>

        <section class="system-meta">
            <div class="meta-item"><strong>Target Host:</strong> {{if .Hostname}}{{.Hostname}}{{else}}localhost{{end}}</div>
            <div class="meta-item"><strong>Sudo Version:</strong> {{if .SudoVersion}}{{.SudoVersion}}{{else}}Unknown{{end}}</div>
            <div class="meta-item"><strong>Total Findings:</strong> <span id="totalFindingsCount">0</span></div>
        </section>

        <!-- Dashboard Metrics -->
        <section class="metrics-grid">
            <div class="metric-card card-crit">
                <div class="metric-label">Critical</div>
                <div class="metric-num" id="crit-count">0</div>
            </div>
            <div class="metric-card card-high">
                <div class="metric-label">High</div>
                <div class="metric-num" id="high-count">0</div>
            </div>
            <div class="metric-card card-med">
                <div class="metric-label">Medium</div>
                <div class="metric-num" id="med-count">0</div>
            </div>
            <div class="metric-card card-low">
                <div class="metric-label">Low</div>
                <div class="metric-num" id="low-count">0</div>
            </div>
            <div class="metric-card card-info">
                <div class="metric-label">Info</div>
                <div class="metric-num" id="info-count">0</div>
            </div>
        </section>

        <!-- Interactive Filters -->
        <section class="controls-panel">
            <div class="search-bar">
                <input type="text" class="search-input" id="searchInput" placeholder="Search by ID, title, description, command, user..." oninput="filterFindings()">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" id="btn-all" onclick="filterSeverity('ALL')">All Severities</button>
                <button class="filter-btn" id="btn-crit" onclick="filterSeverity('CRITICAL')">Critical</button>
                <button class="filter-btn" id="btn-high" onclick="filterSeverity('HIGH')">High</button>
                <button class="filter-btn" id="btn-med" onclick="filterSeverity('MEDIUM')">Medium</button>
                <button class="filter-btn" id="btn-low" onclick="filterSeverity('LOW')">Low</button>
                <button class="filter-btn" id="btn-info" onclick="filterSeverity('INFO')">Info</button>
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" id="btn-cat-all" onclick="filterCategory('ALL')">All Categories</button>
                <button class="filter-btn" id="btn-cat-policy" onclick="filterCategory('POLICY')">Policy Configuration</button>
                <button class="filter-btn" id="btn-cat-system" onclick="filterCategory('SYSTEM')">System Host Checks</button>
            </div>
        </section>

        <!-- Findings Lists -->
        <main class="findings-list" id="findingsContainer">
            <!-- Render System Findings -->
            {{range .SystemFindings}}
            <article class="finding-card" data-severity="{{.Severity}}" data-category="SYSTEM">
                <div class="finding-header">
                    <div class="finding-title-sec">
                        <span class="finding-id">{{.ID}}</span>
                        <h2 class="finding-title">{{.Title}}</h2>
                    </div>
                    <span class="sev-badge {{if eq .Severity "CRITICAL"}}badge-crit{{else if eq .Severity "HIGH"}}badge-high{{else if eq .Severity "MEDIUM"}}badge-med{{else if eq .Severity "LOW"}}badge-low{{else}}badge-info{{end}}">{{.Severity}}</span>
                </div>
                <div class="finding-details-grid">
                    <div class="finding-detail-item"><strong>Source:</strong> System Health Check</div>
                    {{if .Context}}<div class="finding-detail-item"><strong>Target Path:</strong> {{.Context}}</div>{{end}}
                </div>
                <p class="finding-desc">{{.Description}}</p>
                <div class="finding-remediation">
                    <div class="remediation-title">Remediation</div>
                    <div class="remediation-content">
                        {{if hasPrefix .Remediation "Run "}}
                        <pre><code>{{.Remediation}}</code></pre>
                        {{else if hasPrefix .Remediation "Upgrade "}}
                        <p>{{.Remediation}}</p>
                        {{else}}
                        <p>{{.Remediation}}</p>
                        {{end}}
                    </div>
                </div>
            </article>
            {{end}}

            <!-- Render Policy Findings -->
            {{range .PolicyFindings}}
            <article class="finding-card" data-severity="{{.Severity}}" data-category="POLICY">
                <div class="finding-header">
                    <div class="finding-title-sec">
                        <span class="finding-id">{{.ID}}</span>
                        <h2 class="finding-title">{{.Title}}</h2>
                    </div>
                    <span class="sev-badge {{if eq .Severity "CRITICAL"}}badge-crit{{else if eq .Severity "HIGH"}}badge-high{{else if eq .Severity "MEDIUM"}}badge-med{{else if eq .Severity "LOW"}}badge-low{{else}}badge-info{{end}}">{{.Severity}}</span>
                </div>
                <div class="finding-details-grid">
                    <div class="finding-detail-item"><strong>Source:</strong> Sudoers Policy</div>
                    {{if .User}}<div class="finding-detail-item"><strong>User/Group:</strong> {{.User}}</div>{{end}}
                    {{if .Runas}}<div class="finding-detail-item"><strong>Runas:</strong> {{.Runas}}</div>{{end}}
                    {{if .Host}}<div class="finding-detail-item"><strong>Host:</strong> {{.Host}}</div>{{end}}
                    {{if .Command}}<div class="finding-detail-item"><strong>Command:</strong> <code>{{.Command}}</code></div>{{end}}
                    {{if .Context}}<div class="finding-detail-item"><strong>Location:</strong> {{.Context}}</div>{{end}}
                </div>
                <p class="finding-desc">{{.Description}}</p>
                <div class="finding-remediation">
                    <div class="remediation-title">Remediation</div>
                    <div class="remediation-content">
                        {{if contains .Remediation "Example exploit command:"}}
                        <p>{{preGTFOExploitText .Remediation}}</p>
                        <pre><code>{{gtfoExploitCommand .Remediation}}</code></pre>
                        {{else if contains .Remediation "Defaults "}}
                        <pre><code>{{.Remediation}}</code></pre>
                        {{else}}
                        <p>{{.Remediation}}</p>
                        {{end}}
                    </div>
                </div>
            </article>
            {{end}}

            <div class="no-findings" id="noFindingsMsg" style="display: none;">
                <h2>No findings match the selected filters.</h2>
            </div>
        </main>
    </div>

    <script>
        let currentSeverity = 'ALL';
        let currentCategory = 'ALL';

        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
        }

        // Run calculations on load
        window.onload = function() {
            calculateStats();
        };

        function calculateStats() {
            const cards = document.querySelectorAll('.finding-card');
            let total = 0;
            let crit = 0;
            let high = 0;
            let med = 0;
            let low = 0;
            let info = 0;

            cards.forEach(card => {
                total++;
                const sev = card.getAttribute('data-severity');
                if (sev === 'CRITICAL') crit++;
                else if (sev === 'HIGH') high++;
                else if (sev === 'MEDIUM') med++;
                else if (sev === 'LOW') low++;
                else if (sev === 'INFO') info++;
            });

            document.getElementById('totalFindingsCount').innerText = total;
            document.getElementById('crit-count').innerText = crit;
            document.getElementById('high-count').innerText = high;
            document.getElementById('med-count').innerText = med;
            document.getElementById('low-count').innerText = low;
            document.getElementById('info-count').innerText = info;
        }

        function filterSeverity(sev) {
            currentSeverity = sev;
            updateSeverityButtons();
            filterFindings();
        }

        function filterCategory(cat) {
            currentCategory = cat;
            updateCategoryButtons();
            filterFindings();
        }

        function updateSeverityButtons() {
            const buttons = {
                'ALL': 'btn-all',
                'CRITICAL': 'btn-crit',
                'HIGH': 'btn-high',
                'MEDIUM': 'btn-med',
                'LOW': 'btn-low',
                'INFO': 'btn-info'
            };
            for (let s in buttons) {
                document.getElementById(buttons[s]).classList.remove('active');
            }
            document.getElementById(buttons[currentSeverity]).classList.add('active');
        }

        function updateCategoryButtons() {
            const buttons = {
                'ALL': 'btn-cat-all',
                'POLICY': 'btn-cat-policy',
                'SYSTEM': 'btn-cat-system'
            };
            for (let c in buttons) {
                document.getElementById(buttons[c]).classList.remove('active');
            }
            document.getElementById(buttons[currentCategory]).classList.add('active');
        }

        function filterFindings() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;

            cards.forEach(card => {
                const sev = card.getAttribute('data-severity');
                const cat = card.getAttribute('data-category');
                const text = card.innerText.toLowerCase();

                const matchesQuery = text.includes(query);
                const matchesSeverity = (currentSeverity === 'ALL' || sev === currentSeverity);
                const matchesCategory = (currentCategory === 'ALL' || cat === currentCategory);

                if (matchesQuery && matchesSeverity && matchesCategory) {
                    card.style.display = 'flex';
                    visibleCount++;
                } else {
                    card.style.display = 'none';
                }
            });

            const noMsg = document.getElementById('noFindingsMsg');
            if (visibleCount === 0) {
                noMsg.style.display = 'block';
            } else {
                noMsg.style.display = 'none';
            }
        }
    </script>
</body>
</html>
`

// WriteHTMLReport formats the audit results as a premium responsive HTML report.
func WriteHTMLReport(result *audit.AuditResult, w io.Writer) error {
	tmpl := template.New("htmlReport").Funcs(template.FuncMap{
		"hasPrefix": strings.HasPrefix,
		"contains":  strings.Contains,
		"preGTFOExploitText": func(s string) string {
			sep := "Example exploit command:\n"
			if idx := strings.Index(s, sep); idx != -1 {
				return s[:idx]
			}
			return s
		},
		"gtfoExploitCommand": func(s string) string {
			sep := "Example exploit command:\n"
			if idx := strings.Index(s, sep); idx != -1 {
				return s[idx+len(sep):]
			}
			return ""
		},
	})

	t, err := tmpl.Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	return t.Execute(w, result)
}
