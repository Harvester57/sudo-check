let currentSeverity = 'ALL';
let currentCategory = 'ALL';
let currentFile = 'ALL';
let currentPrincipal = 'ALL';
let currentRule = 'ALL';
let currentCompliance = 'ALL';
let currentReqFilter = null;
let currentGroupBy = 'NONE';
let currentDensity = 'detailed';
let currentViewTab = 'report';
let currentFrameworkFilter = 'ALL';
let triggeredReqsOnly = false;
let allCards = [];

const severityOrder = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4
};

function compareLex(a, b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

function normalizeComplianceJS(tag) {
    return (tag || '').trim().toUpperCase().replace(/^ANSSI-BP-028-R/, 'ANSSI-BP-028 R');
}

function switchViewTab(tabName, focusTabBtn) {
    const validTabs = ['report', 'frameworks', 'template'];
    if (!validTabs.includes(tabName)) tabName = 'report';
    currentViewTab = tabName;

    validTabs.forEach(t => {
        const btn = document.getElementById('tab-' + t);
        const panel = document.getElementById('panel-' + t);
        const isSelected = (t === tabName);
        if (btn) {
            btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
            btn.setAttribute('tabindex', isSelected ? '0' : '-1');
            if (isSelected && focusTabBtn) {
                btn.focus();
            }
        }
        if (panel) {
            if (isSelected) {
                panel.removeAttribute('hidden');
            } else {
                panel.setAttribute('hidden', '');
            }
        }
    });
}

function handleTablistKeydown(event) {
    const tabs = ['report', 'frameworks', 'template'];
    const idx = tabs.indexOf(currentViewTab);
    if (idx === -1) return;

    let nextIdx = -1;
    if (event.key === 'ArrowRight') {
        nextIdx = (idx + 1) % tabs.length;
    } else if (event.key === 'ArrowLeft') {
        nextIdx = (idx - 1 + tabs.length) % tabs.length;
    } else if (event.key === 'Home') {
        nextIdx = 0;
    } else if (event.key === 'End') {
        nextIdx = tabs.length - 1;
    }

    if (nextIdx !== -1) {
        event.preventDefault();
        switchViewTab(tabs[nextIdx], true);
    }
}

function setFrameworkFilter(fwId) {
    currentFrameworkFilter = fwId || 'ALL';
    const allBtn = document.getElementById('btn-fw-all');
    if (allBtn) {
        const isAll = (currentFrameworkFilter === 'ALL');
        allBtn.classList.toggle('active', isAll);
        allBtn.setAttribute('aria-pressed', isAll ? 'true' : 'false');
    }
    document.querySelectorAll('[id^="btn-fw-"]').forEach(btn => {
        if (btn.id === 'btn-fw-all' || btn.id === 'btn-fw-triggered') return;
        const active = (btn.id === 'btn-fw-' + currentFrameworkFilter);
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    filterFrameworkCatalog();
}

function toggleTriggeredReqsOnly() {
    triggeredReqsOnly = !triggeredReqsOnly;
    const btn = document.getElementById('btn-fw-triggered');
    if (btn) {
        btn.classList.toggle('active', triggeredReqsOnly);
        btn.setAttribute('aria-pressed', triggeredReqsOnly ? 'true' : 'false');
    }
    filterFrameworkCatalog();
}

function clearFrameworkSearch() {
    const input = document.getElementById('frameworkSearchInput');
    if (input) {
        input.value = '';
        filterFrameworkCatalog();
    }
}

function filterFrameworkCatalog() {
    const input = document.getElementById('frameworkSearchInput');
    const query = input ? input.value.trim().toLowerCase() : '';
    const clearBtn = document.getElementById('clearFrameworkSearchBtn');
    if (clearBtn) clearBtn.style.display = query.length > 0 ? 'inline-block' : 'none';

    let totalVisibleReqs = 0;
    document.querySelectorAll('.framework-group-card').forEach(groupEl => {
        const groupFwId = groupEl.getAttribute('data-fw-group');
        const groupMatchesFw = (currentFrameworkFilter === 'ALL' || groupFwId === currentFrameworkFilter);
        let visibleReqs = 0;

        groupEl.querySelectorAll('.framework-req-card').forEach(reqEl => {
            const isTriggered = reqEl.getAttribute('data-req-triggered') === 'true';
            if (!reqEl._searchText) {
                reqEl._searchText = (reqEl.textContent || '').toLowerCase();
            }
            const matchesQuery = (query === '' || reqEl._searchText.includes(query));
            const matchesTriggered = (!triggeredReqsOnly || isTriggered);

            if (groupMatchesFw && matchesQuery && matchesTriggered) {
                reqEl.style.display = 'flex';
                visibleReqs++;
                totalVisibleReqs++;
            } else {
                reqEl.style.display = 'none';
            }
        });

        groupEl.style.display = (groupMatchesFw && visibleReqs > 0) ? 'block' : 'none';
    });

    const noFwMsg = document.getElementById('noFrameworkReqsMsg');
    if (noFwMsg) {
        noFwMsg.hidden = totalVisibleReqs !== 0;
    }
}

function jumpToAuditReportByRule(ruleId) {
    switchViewTab('report', false);
    resetAllFilters();
    currentRule = ruleId;
    document.querySelectorAll('[data-facet-rule]').forEach(el => {
        el.classList.toggle('active-facet', el.getAttribute('data-facet-rule') === currentRule);
    });
    filterFindings();
    const container = document.getElementById('findingsContainer');
    if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function jumpToAuditReportByRequirement(btn) {
    if (!btn) return;
    const code = btn.getAttribute('data-req-code') || '';
    const rulesCSV = btn.getAttribute('data-req-rules') || '';
    const compsCSV = btn.getAttribute('data-req-comps') || '';
    switchViewTab('report', false);
    resetAllFilters();
    currentReqFilter = {
        code: code,
        rules: rulesCSV ? rulesCSV.split(',').map(s => s.trim()).filter(Boolean) : [],
        comps: compsCSV ? compsCSV.split(',').map(s => normalizeComplianceJS(s)).filter(Boolean) : []
    };
    filterFindings();
    const container = document.getElementById('findingsContainer');
    if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function jumpToFrameworkRequirement(fwCode) {
    switchViewTab('frameworks', false);
    setFrameworkFilter('ALL');
    if (triggeredReqsOnly) toggleTriggeredReqsOnly();
    const input = document.getElementById('frameworkSearchInput');
    if (input) {
        input.value = fwCode || '';
        filterFrameworkCatalog();
    }
}

function jumpToTemplateSection(sectionId) {
    switchViewTab('template', false);
    scrollToElementId(sectionId);
}

function scrollToElementId(id) {
    const el = document.getElementById(id);
    if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function copySectionPre(btn) {
    const section = btn.closest('.template-section-card');
    const code = section ? section.querySelector('pre code') : null;
    if (code) copyTextWithFeedback(btn, code.textContent);
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const isDark = currentTheme === 'dark' || (!currentTheme && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const newTheme = isDark ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    try {
        localStorage.setItem('sudo-check-theme', newTheme);
    } catch (e) {}
}

if (window.matchMedia) {
    const colorSchemeMQ = window.matchMedia('(prefers-color-scheme: dark)');
    const onSchemeChange = function(e) {
        try {
            const saved = localStorage.getItem('sudo-check-theme');
            if (saved === 'light' || saved === 'dark') return;
        } catch (err) {}
        document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
    };
    if (typeof colorSchemeMQ.addEventListener === 'function') {
        colorSchemeMQ.addEventListener('change', onSchemeChange);
    }
}

window.onload = function() {
    const container = document.getElementById('findingsContainer');
    if (container) {
        currentGroupBy = container.getAttribute('data-default-group-by') || 'NONE';
    }
    allCards = Array.from(document.querySelectorAll('.finding-card'));
    setupEventDelegation();
    setupKeyboardShortcuts();
    setupBeforeMatchDelegation();
    if (currentGroupBy !== 'NONE') {
        rebuildGrouping();
        filterFindings();
    }
};

function setupEventDelegation() {
    const triageEl = document.getElementById('triageOverview');
    if (triageEl) {
        triageEl.addEventListener('click', function(e) {
            const fileBtn = e.target.closest('[data-facet-file]');
            if (fileBtn) {
                toggleFileFilter(fileBtn.getAttribute('data-facet-file'));
                return;
            }
            const prinBtn = e.target.closest('[data-facet-principal]');
            if (prinBtn) {
                togglePrincipalFilter(prinBtn.getAttribute('data-facet-principal'));
                return;
            }
            const ruleBtn = e.target.closest('[data-facet-rule]');
            if (ruleBtn) {
                toggleRuleFilter(ruleBtn.getAttribute('data-facet-rule'));
                return;
            }
            const compBtn = e.target.closest('[data-facet-comp]');
            if (compBtn) {
                toggleComplianceFilter(compBtn.getAttribute('data-facet-comp'));
            }
        });
    }

    const container = document.getElementById('findingsContainer');
    if (container) {
        container.addEventListener('click', function(e) {
            const compBtn = e.target.closest('[data-comp]');
            if (compBtn) {
                toggleComplianceFilter(compBtn.getAttribute('data-comp'));
                return;
            }
            const actionBtn = e.target.closest('[data-action]');
            if (actionBtn) {
                const action = actionBtn.getAttribute('data-action');
                const card = actionBtn.closest('.finding-card');
                if (action === 'filter-file' && card) {
                    e.stopPropagation();
                    toggleFileFilter(card.getAttribute('data-file'));
                } else if (action === 'filter-principal' && card) {
                    togglePrincipalFilter(card.getAttribute('data-principal'));
                } else if (action === 'toggle-compact' && card) {
                    e.stopPropagation();
                    toggleCompactCard(card);
                } else if (action === 'copy-code') {
                    copyCodeBlock(actionBtn);
                } else if (action === 'copy-sibling') {
                    copySiblingCode(actionBtn);
                }
                return;
            }
            const headerEl = e.target.closest('.finding-header');
            if (headerEl && currentDensity === 'compact') {
                const card = headerEl.closest('.finding-card');
                if (card) toggleCompactCard(card);
            }
        });
    }

    const fwPanel = document.getElementById('panel-frameworks');
    if (fwPanel) {
        fwPanel.addEventListener('click', function(e) {
            const ruleBtn = e.target.closest('[data-jump-rule]');
            if (ruleBtn) {
                jumpToAuditReportByRule(ruleBtn.getAttribute('data-jump-rule'));
                return;
            }
            const reqBtn = e.target.closest('[data-req-code]');
            if (reqBtn) {
                jumpToAuditReportByRequirement(reqBtn);
                return;
            }
            const tplBtn = e.target.closest('[data-jump-tpl]');
            if (tplBtn) {
                jumpToTemplateSection(tplBtn.getAttribute('data-jump-tpl'));
                return;
            }
            const actionBtn = e.target.closest('[data-action="copy-code"]');
            if (actionBtn) {
                copyCodeBlock(actionBtn);
            }
        });
    }

    const tplPanel = document.getElementById('panel-template');
    if (tplPanel) {
        tplPanel.addEventListener('click', function(e) {
            const scrollBtn = e.target.closest('[data-scroll-to]');
            if (scrollBtn) {
                scrollToElementId(scrollBtn.getAttribute('data-scroll-to'));
                return;
            }
            const fwBtn = e.target.closest('[data-jump-fw]');
            if (fwBtn) {
                jumpToFrameworkRequirement(fwBtn.getAttribute('data-jump-fw'));
                return;
            }
            const ruleBtn = e.target.closest('[data-jump-rule]');
            if (ruleBtn) {
                jumpToAuditReportByRule(ruleBtn.getAttribute('data-jump-rule'));
                return;
            }
            const actionBtn = e.target.closest('[data-action]');
            if (actionBtn) {
                const action = actionBtn.getAttribute('data-action');
                if (action === 'copy-section-pre') {
                    copySectionPre(actionBtn);
                } else if (action === 'copy-code') {
                    copyCodeBlock(actionBtn);
                }
            }
        });
    }
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        const activeSearchId = currentViewTab === 'frameworks' ? 'frameworkSearchInput' : 'searchInput';
        const searchInput = document.getElementById(activeSearchId);
        if (!searchInput) return;
        if (e.key === '/' && document.activeElement !== searchInput && !['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        } else if (e.key === 'Escape' && document.activeElement === searchInput) {
            if (searchInput.value !== '') {
                if (currentViewTab === 'frameworks') clearFrameworkSearch();
                else clearSearch();
            } else {
                searchInput.blur();
            }
        }
    });
}

function setupBeforeMatchDelegation() {
    const container = document.getElementById('findingsContainer');
    if (!container) return;

    container.addEventListener('beforematch', function(e) {
        const card = e.target.closest('.finding-card');
        if (card) {
            card.classList.add('is-expanded');
            const btn = card.querySelector('.compact-toggle-btn');
            if (btn) btn.setAttribute('aria-expanded', 'true');
        }
    });
}

function toggleSeverityCard(sev) {
    filterSeverity(currentSeverity === sev ? 'ALL' : sev);
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

function setFileFilter(file) {
    currentFile = file || 'ALL';
    const sel = document.getElementById('fileFilterSelect');
    if (sel && sel.value !== currentFile) sel.value = currentFile;
    document.querySelectorAll('[data-facet-file]').forEach(el => {
        el.classList.toggle('active-facet', el.getAttribute('data-facet-file') === currentFile);
    });
    filterFindings();
}

function toggleFileFilter(file) {
    setFileFilter(currentFile === file ? 'ALL' : file);
}

function setPrincipalFilter(principal) {
    currentPrincipal = principal || 'ALL';
    const sel = document.getElementById('principalFilterSelect');
    if (sel && sel.value !== currentPrincipal) sel.value = currentPrincipal;
    document.querySelectorAll('[data-facet-principal]').forEach(el => {
        el.classList.toggle('active-facet', el.getAttribute('data-facet-principal') === currentPrincipal);
    });
    filterFindings();
}

function togglePrincipalFilter(principal) {
    setPrincipalFilter(currentPrincipal === principal ? 'ALL' : principal);
}

function toggleRuleFilter(ruleId) {
    currentRule = currentRule === ruleId ? 'ALL' : ruleId;
    document.querySelectorAll('[data-facet-rule]').forEach(el => {
        el.classList.toggle('active-facet', el.getAttribute('data-facet-rule') === currentRule);
    });
    filterFindings();
}

function toggleComplianceFilter(comp) {
    const norm = normalizeComplianceJS(comp);
    currentCompliance = currentCompliance === norm ? 'ALL' : norm;
    document.querySelectorAll('[data-facet-comp]').forEach(el => {
        el.classList.toggle('active-facet', normalizeComplianceJS(el.getAttribute('data-facet-comp')) === currentCompliance);
    });
    filterFindings();
}

function clearSearch() {
    const input = document.getElementById('searchInput');
    if (input) {
        input.value = '';
        filterFindings();
    }
}

function resetAllFilters() {
    currentSeverity = 'ALL';
    currentCategory = 'ALL';
    currentFile = 'ALL';
    currentPrincipal = 'ALL';
    currentRule = 'ALL';
    currentCompliance = 'ALL';
    currentReqFilter = null;
    const input = document.getElementById('searchInput');
    if (input) input.value = '';
    const fileSel = document.getElementById('fileFilterSelect');
    if (fileSel) fileSel.value = 'ALL';
    const prinSel = document.getElementById('principalFilterSelect');
    if (prinSel) prinSel.value = 'ALL';
    document.querySelectorAll('.active-facet').forEach(el => el.classList.remove('active-facet'));
    updateSeverityButtons();
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
    const metricCards = {
        'CRITICAL': 'metric-crit',
        'HIGH': 'metric-high',
        'MEDIUM': 'metric-med',
        'LOW': 'metric-low',
        'INFO': 'metric-info'
    };
    for (let s in buttons) {
        const btn = document.getElementById(buttons[s]);
        if (btn) {
            const active = (s === currentSeverity);
            btn.classList.toggle('active', active);
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        }
    }
    for (let s in metricCards) {
        const mc = document.getElementById(metricCards[s]);
        if (mc) {
            const active = (s === currentSeverity);
            mc.classList.toggle('active-metric', active);
            mc.setAttribute('aria-pressed', active ? 'true' : 'false');
        }
    }
}

function updateCategoryButtons() {
    const buttons = {
        'ALL': 'btn-cat-all',
        'POLICY': 'btn-cat-policy',
        'GTFOBINS': 'btn-dom-gtfo',
        'COMMANDS': 'btn-dom-cmd',
        'DEFAULTS': 'btn-dom-def',
        'SYSTEM': 'btn-cat-system'
    };
    for (let c in buttons) {
        const btn = document.getElementById(buttons[c]);
        if (btn) {
            const active = (c === currentCategory);
            btn.classList.toggle('active', active);
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        }
    }
    const isPolicySub = (currentCategory === 'GTFOBINS' || currentCategory === 'COMMANDS' || currentCategory === 'DEFAULTS');
    const isAnyPolicy = (currentCategory === 'POLICY' || isPolicySub);
    const policyGroup = document.getElementById('policyFilterGroup');
    const policyParentBtn = document.getElementById('btn-cat-policy');
    if (policyGroup) policyGroup.classList.toggle('has-active-policy', isAnyPolicy);
    if (policyParentBtn) policyParentBtn.classList.toggle('parent-context', isPolicySub);
}

function setViewDensity(mode) {
    currentDensity = mode === 'compact' ? 'compact' : 'detailed';
    const container = document.getElementById('findingsContainer');
    const btnDet = document.getElementById('btn-view-detailed');
    const btnComp = document.getElementById('btn-view-compact');
    const isDet = (currentDensity === 'detailed');
    if (btnDet) {
        btnDet.classList.toggle('active', isDet);
        btnDet.setAttribute('aria-pressed', isDet ? 'true' : 'false');
    }
    if (btnComp) {
        btnComp.classList.toggle('active', !isDet);
        btnComp.setAttribute('aria-pressed', !isDet ? 'true' : 'false');
    }

    if (container) {
        container.classList.toggle('view-compact', currentDensity === 'compact');
    }

    const supportsBeforeMatch = ('onbeforematch' in HTMLElement.prototype);
    const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
    cards.forEach(card => {
        const body = card.querySelector('.finding-expandable-body');
        const btn = card.querySelector('.compact-toggle-btn');
        if (!body) return;
        if (currentDensity === 'compact') {
            card.classList.remove('is-expanded');
            if (supportsBeforeMatch) {
                body.setAttribute('hidden', 'until-found');
            } else {
                body.removeAttribute('hidden');
                card.classList.add('is-expanded');
            }
            if (btn) btn.setAttribute('aria-expanded', supportsBeforeMatch ? 'false' : 'true');
        } else {
            card.classList.remove('is-expanded');
            body.removeAttribute('hidden');
            if (btn) btn.setAttribute('aria-expanded', 'true');
        }
    });
}

function toggleCompactCard(card) {
    if (!card) return;
    const body = card.querySelector('.finding-expandable-body');
    const btn = card.querySelector('.compact-toggle-btn');
    const expanding = !card.classList.contains('is-expanded');
    card.classList.toggle('is-expanded', expanding);
    if (body) {
        if (expanding) {
            body.removeAttribute('hidden');
        } else if ('onbeforematch' in HTMLElement.prototype) {
            body.setAttribute('hidden', 'until-found');
        }
    }
    if (btn) btn.setAttribute('aria-expanded', expanding ? 'true' : 'false');
}

function expandAllDisclosures(expand) {
    if (currentViewTab === 'frameworks') {
        document.querySelectorAll('.framework-group-card').forEach(grp => {
            grp.open = expand;
        });
        return;
    }
    document.querySelectorAll('.finding-group').forEach(grp => {
        grp.open = expand;
    });
    if (currentDensity === 'compact') {
        const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
        cards.forEach(card => {
            const body = card.querySelector('.finding-expandable-body');
            const btn = card.querySelector('.compact-toggle-btn');
            card.classList.toggle('is-expanded', expand);
            if (body) {
                if (expand) {
                    body.removeAttribute('hidden');
                } else if ('onbeforematch' in HTMLElement.prototype) {
                    body.setAttribute('hidden', 'until-found');
                }
            }
            if (btn) btn.setAttribute('aria-expanded', expand ? 'true' : 'false');
        });
    }
}

function setGroupBy(mode) {
    currentGroupBy = mode || 'NONE';
    const sel = document.getElementById('groupBySelect');
    if (sel && sel.value !== currentGroupBy) sel.value = currentGroupBy;
    rebuildGrouping();
    filterFindings();
}

function rebuildGrouping() {
    const container = document.getElementById('findingsContainer');
    const noMsg = document.getElementById('noFindingsMsg');
    if (!container) return;
    if (allCards.length === 0) {
        allCards = Array.from(container.querySelectorAll('.finding-card'));
    }

    const sortedCards = allCards.slice().sort((a, b) => {
        return parseInt(a.getAttribute('data-order') || '0', 10) - parseInt(b.getAttribute('data-order') || '0', 10);
    });

    container.querySelectorAll('.finding-group').forEach(grp => grp.remove());

    const fragment = document.createDocumentFragment();
    if (currentGroupBy === 'NONE') {
        sortedCards.forEach(card => fragment.appendChild(card));
        container.insertBefore(fragment, noMsg);
        return;
    }

    const groupsMap = new Map();
    sortedCards.forEach(card => {
        let key = '';
        let title = '';
        let subtitle = '';
        let sharedRem = '';
        let sharedRemCode = '';
        let sharedRemLabel = '';

        if (currentGroupBy === 'FILE') {
            key = card.getAttribute('data-file') || 'Global Policy';
            title = key;
            subtitle = 'Source File';
        } else if (currentGroupBy === 'RULE') {
            key = card.getAttribute('data-id') || 'RULE';
            title = key;
            subtitle = card.getAttribute('data-rule-title') || '';
            if (!subtitle) {
                const titleEl = card.querySelector('.finding-title');
                subtitle = titleEl ? titleEl.textContent : '';
            }
            const remP = card.querySelector('.remediation-content p');
            sharedRem = remP ? remP.textContent : '';
            const remCodeEl = card.querySelector('.remediation-code-block code');
            sharedRemCode = remCodeEl ? remCodeEl.textContent : '';
            const remLabelEl = card.querySelector('.remediation-code-label');
            sharedRemLabel = remLabelEl ? remLabelEl.textContent : 'Example Fix';
        } else if (currentGroupBy === 'USER') {
            key = card.getAttribute('data-principal') || '(Global / Unscoped)';
            title = key;
            subtitle = 'Principal Scope';
        } else if (currentGroupBy === 'SEVERITY') {
            key = card.getAttribute('data-severity') || 'INFO';
            title = key;
            subtitle = 'Severity Level';
        }

        if (!groupsMap.has(key)) {
            groupsMap.set(key, {
                key: key,
                title: title,
                subtitle: subtitle,
                sharedRem: sharedRem,
                hasUniformRem: true,
                hasAnyRem: sharedRem !== '',
                sharedRemCode: sharedRemCode,
                sharedRemLabel: sharedRemLabel,
                hasUniformRemCode: true,
                hasAnyRemCode: sharedRemCode !== '',
                cards: [],
                crit: 0,
                high: 0,
                med: 0,
                low: 0,
                info: 0,
                minOrder: 99
            });
        } else if (currentGroupBy === 'RULE') {
            const existing = groupsMap.get(key);
            if (sharedRem !== '') {
                existing.hasAnyRem = true;
            }
            if (sharedRem !== existing.sharedRem) {
                existing.hasUniformRem = false;
            }
            if (sharedRemCode !== '') {
                existing.hasAnyRemCode = true;
            }
            if (sharedRemCode !== existing.sharedRemCode) {
                existing.hasUniformRemCode = false;
            }
        }
        const g = groupsMap.get(key);
        g.cards.push(card);
        const sev = card.getAttribute('data-severity') || 'INFO';
        const ord = severityOrder[sev] !== undefined ? severityOrder[sev] : 5;
        if (ord < g.minOrder) g.minOrder = ord;
        if (sev === 'CRITICAL') g.crit++;
        else if (sev === 'HIGH') g.high++;
        else if (sev === 'MEDIUM') g.med++;
        else if (sev === 'LOW') g.low++;
        else g.info++;
    });

    const groupsList = Array.from(groupsMap.values());
    groupsList.sort((a, b) => {
        if (a.minOrder !== b.minOrder) return a.minOrder - b.minOrder;
        if (a.crit !== b.crit) return b.crit - a.crit;
        if (a.high !== b.high) return b.high - a.high;
        if (a.med !== b.med) return b.med - a.med;
        if (a.low !== b.low) return b.low - a.low;
        if (a.cards.length !== b.cards.length) return b.cards.length - a.cards.length;
        return compareLex(a.key, b.key);
    });

    groupsList.forEach(g => {
        const details = document.createElement('details');
        details.className = 'finding-group';
        details.setAttribute('data-group-kind', currentGroupBy);
        details.setAttribute('data-group-key', g.key);
        details.open = true;

        const summary = document.createElement('summary');
        summary.className = 'finding-group-header';

        const left = document.createElement('span');
        left.className = 'group-header-left';

        const chevron = document.createElement('span');
        chevron.className = 'group-chevron';
        chevron.textContent = '\u25B6';
        left.appendChild(chevron);

        const titleSpan = document.createElement('span');
        titleSpan.className = 'group-title';
        titleSpan.textContent = g.title;
        left.appendChild(titleSpan);

        if (g.subtitle) {
            const subSpan = document.createElement('span');
            subSpan.className = 'group-subtitle';
            subSpan.textContent = '\u2014 ' + g.subtitle;
            left.appendChild(subSpan);
        }

        const right = document.createElement('span');
        right.className = 'triage-row-badges';

        if (g.crit > 0) right.appendChild(makeMiniBadge(g.crit + ' CRIT', 'badge-crit', 'CRIT'));
        if (g.high > 0) right.appendChild(makeMiniBadge(g.high + ' HIGH', 'badge-high', 'HIGH'));
        if (g.med > 0) right.appendChild(makeMiniBadge(g.med + ' MED', 'badge-med', 'MED'));
        if (g.low > 0) right.appendChild(makeMiniBadge(g.low + ' LOW', 'badge-low', 'LOW'));
        if (g.info > 0) right.appendChild(makeMiniBadge(g.info + ' INFO', 'badge-info', 'INFO'));

        const totalSpan = document.createElement('span');
        totalSpan.className = 'mini-total group-visible-count';
        totalSpan.textContent = '(' + g.cards.length + ')';
        right.appendChild(totalSpan);

        summary.appendChild(left);
        summary.appendChild(right);
        details.appendChild(summary);

        if (currentGroupBy === 'RULE' && (g.hasAnyRem || g.hasAnyRemCode)) {
            const remBox = document.createElement('div');
            remBox.className = 'group-shared-remediation';

            const remTitle = document.createElement('strong');
            remTitle.className = 'group-shared-remediation-title';
            remTitle.textContent = 'Shared Rule Remediation (' + g.cards.length + (g.cards.length === 1 ? ' occurrence)' : ' occurrences)');
            remBox.appendChild(remTitle);

            if (g.hasUniformRem && g.sharedRem) {
                const p = document.createElement('p');
                p.textContent = g.sharedRem;
                remBox.appendChild(p);
            } else if (g.hasAnyRem) {
                const noteRem = document.createElement('p');
                noteRem.className = 'group-shared-remediation-note';
                noteRem.textContent = 'Remediation guidance varies per occurrence; review individual findings below.';
                remBox.appendChild(noteRem);
            }

            if (g.hasUniformRemCode && g.sharedRemCode) {
                const codeWrap = document.createElement('div');
                codeWrap.className = 'remediation-code-block';

                const codeHeader = document.createElement('div');
                codeHeader.className = 'remediation-code-header';

                const codeLabel = document.createElement('span');
                codeLabel.className = 'remediation-code-label';
                codeLabel.textContent = g.sharedRemLabel || 'Example Fix';
                codeHeader.appendChild(codeLabel);

                const copyBtn = document.createElement('button');
                copyBtn.type = 'button';
                copyBtn.className = 'copy-btn';
                copyBtn.setAttribute('data-action', 'copy-code');
                copyBtn.textContent = 'Copy';
                codeHeader.appendChild(copyBtn);

                codeWrap.appendChild(codeHeader);

                const pre = document.createElement('pre');
                pre.tabIndex = 0;
                const code = document.createElement('code');
                code.textContent = g.sharedRemCode;
                pre.appendChild(code);
                codeWrap.appendChild(pre);

                remBox.appendChild(codeWrap);
            } else if (g.hasAnyRemCode) {
                const note = document.createElement('p');
                note.className = 'group-shared-remediation-note';
                note.textContent = 'Remediation snippets vary per occurrence; expand individual findings below.';
                remBox.appendChild(note);
            }

            details.appendChild(remBox);
        }

        const body = document.createElement('div');
        body.className = 'finding-group-body';
        g.cards.forEach(card => body.appendChild(card));
        details.appendChild(body);

        fragment.appendChild(details);
    });
    container.insertBefore(fragment, noMsg);
}

function makeMiniBadge(text, cls, sevKey) {
    const span = document.createElement('span');
    span.className = 'mini-sev ' + cls;
    if (sevKey) span.setAttribute('data-group-sev', sevKey);
    span.textContent = text;
    return span;
}

function getCardSearchText(card) {
    if (!card._searchText) {
        card._searchText = [
            card.textContent || '',
            card.getAttribute('data-category') || '',
            card.getAttribute('data-domain') || '',
            card.getAttribute('data-file') || '',
            card.getAttribute('data-principal') || ''
        ].join(' ').toLowerCase();
    }
    return card._searchText;
}

function filterFindings() {
    const searchEl = document.getElementById('searchInput');
    const query = searchEl ? searchEl.value.trim().toLowerCase() : '';
    const clearBtn = document.getElementById('clearSearchBtn');
    const kbdHint = document.getElementById('searchKbdHint');
    if (clearBtn) clearBtn.style.display = query.length > 0 ? 'inline-block' : 'none';
    if (kbdHint) kbdHint.style.display = query.length > 0 ? 'none' : 'inline-block';

    const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
    let visibleCount = 0;
    const domCounts = { POLICY: 0, GTFOBINS: 0, COMMANDS: 0, DEFAULTS: 0, SYSTEM: 0 };
    const sevCountsForButtons = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

    cards.forEach(card => {
        const sev = card.getAttribute('data-severity');
        const cat = card.getAttribute('data-category');
        const dom = card.getAttribute('data-domain');
        const file = card.getAttribute('data-file');
        const principal = card.getAttribute('data-principal');
        const ruleId = card.getAttribute('data-id');
        const compCSV = card.getAttribute('data-compliance') || '';

        const normCardComps = compCSV ? compCSV.split(',').map(s => normalizeComplianceJS(s)) : [];
        const matchesQuery = query === '' || getCardSearchText(card).includes(query);
        const matchesSeverity = (currentSeverity === 'ALL' || sev === currentSeverity);
        const matchesCategory = (currentCategory === 'ALL' || cat === currentCategory || dom === currentCategory);
        const matchesFile = (currentFile === 'ALL' || file === currentFile);
        const matchesPrincipal = (currentPrincipal === 'ALL' || principal === currentPrincipal);
        const matchesRule = (currentRule === 'ALL' || ruleId === currentRule);
        const matchesComp = (currentCompliance === 'ALL' || normCardComps.includes(normalizeComplianceJS(currentCompliance)));
        const matchesReq = (!currentReqFilter || currentReqFilter.rules.includes(ruleId) || currentReqFilter.comps.some(c => normCardComps.includes(c)));
        const matchesBase = matchesQuery && matchesFile && matchesPrincipal && matchesRule && matchesComp && matchesReq;

        if (matchesBase && matchesSeverity) {
            if (cat === 'POLICY' || dom === 'POLICY') domCounts.POLICY++;
            if (dom === 'GTFOBINS') domCounts.GTFOBINS++;
            if (dom === 'COMMANDS') domCounts.COMMANDS++;
            if (dom === 'DEFAULTS') domCounts.DEFAULTS++;
            if (cat === 'SYSTEM' || dom === 'SYSTEM') domCounts.SYSTEM++;
        }

        if (matchesBase && matchesCategory) {
            if (sevCountsForButtons[sev] !== undefined) {
                sevCountsForButtons[sev]++;
            }
        }

        if (matchesBase && matchesSeverity && matchesCategory) {
            card.style.display = 'flex';
            visibleCount++;
        } else {
            card.style.display = 'none';
        }
    });

    const domBtnLabels = [
        ['btn-cat-policy', 'Policy', domCounts.POLICY],
        ['btn-dom-gtfo', 'GTFObins', domCounts.GTFOBINS],
        ['btn-dom-cmd', 'Commands', domCounts.COMMANDS],
        ['btn-dom-def', 'Defaults', domCounts.DEFAULTS],
        ['btn-cat-system', 'System', domCounts.SYSTEM]
    ];
    domBtnLabels.forEach(([id, label, cnt]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = label + ' (' + cnt + ')';
    });

    const sevBtnLabels = [
        ['btn-crit', 'crit-count', 'Critical', sevCountsForButtons.CRITICAL],
        ['btn-high', 'high-count', 'High', sevCountsForButtons.HIGH],
        ['btn-med', 'med-count', 'Medium', sevCountsForButtons.MEDIUM],
        ['btn-low', 'low-count', 'Low', sevCountsForButtons.LOW],
        ['btn-info', 'info-count', 'Info', sevCountsForButtons.INFO]
    ];
    sevBtnLabels.forEach(([btnId, metricId, label, cnt]) => {
        const btn = document.getElementById(btnId);
        if (btn) btn.textContent = label + ' (' + cnt + ')';
        const metric = document.getElementById(metricId);
        if (metric) metric.textContent = String(cnt);
    });

    document.querySelectorAll('.finding-group').forEach(grp => {
        const grpCards = grp.querySelectorAll('.finding-card');
        let grpVisible = 0, gCrit = 0, gHigh = 0, gMed = 0, gLow = 0, gInfo = 0;
        grpCards.forEach(c => {
            if (c.style.display !== 'none') {
                grpVisible++;
                const s = c.getAttribute('data-severity');
                if (s === 'CRITICAL') gCrit++;
                else if (s === 'HIGH') gHigh++;
                else if (s === 'MEDIUM') gMed++;
                else if (s === 'LOW') gLow++;
                else gInfo++;
            }
        });
        grp.style.display = grpVisible > 0 ? 'block' : 'none';
        const countEl = grp.querySelector('.group-visible-count');
        if (countEl) countEl.textContent = '(' + grpVisible + ')';
        const sevCounts = { 'CRIT': gCrit, 'HIGH': gHigh, 'MED': gMed, 'LOW': gLow, 'INFO': gInfo };
        grp.querySelectorAll('[data-group-sev]').forEach(badge => {
            const k = badge.getAttribute('data-group-sev');
            const cnt = sevCounts[k] || 0;
            badge.style.display = cnt > 0 ? 'inline-block' : 'none';
            badge.textContent = cnt + ' ' + k;
        });
        const remTitle = grp.querySelector('.group-shared-remediation-title');
        if (remTitle) {
            remTitle.textContent = 'Shared Rule Remediation (' + grpVisible + (grpVisible === 1 ? ' occurrence)' : ' occurrences)');
        }
    });

    const visEl = document.getElementById('visibleFindingsCount');
    if (visEl) visEl.textContent = visibleCount;

    updateActiveFilterChips(query);

    const noMsg = document.getElementById('noFindingsMsg');
    if (noMsg) {
        noMsg.hidden = visibleCount !== 0;
    }
}

function updateActiveFilterChips(query) {
    const list = document.getElementById('activeFiltersList');
    const resetBtn = document.getElementById('resetFiltersBtn');
    if (!list) return;
    list.innerHTML = '';
    let anyActive = false;

    function addChip(label, onRemove) {
        anyActive = true;
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'active-filter-chip';
        chip.textContent = label + ' \u00D7';
        chip.onclick = onRemove;
        list.appendChild(chip);
    }

    if (currentSeverity !== 'ALL') addChip('Severity: ' + currentSeverity, () => filterSeverity('ALL'));
    if (currentCategory !== 'ALL') {
        const catLabels = {
            'POLICY': 'Policy (All)',
            'GTFOBINS': 'Policy \u203A GTFObins',
            'COMMANDS': 'Policy \u203A Commands',
            'DEFAULTS': 'Policy \u203A Defaults',
            'SYSTEM': 'System'
        };
        addChip('Domain: ' + (catLabels[currentCategory] || currentCategory), () => filterCategory('ALL'));
    }
    if (currentFile !== 'ALL') addChip('Source: ' + currentFile, () => setFileFilter('ALL'));
    if (currentPrincipal !== 'ALL') addChip('Principal: ' + currentPrincipal, () => setPrincipalFilter('ALL'));
    if (currentRule !== 'ALL') addChip('Rule: ' + currentRule, () => toggleRuleFilter(currentRule));
    if (currentCompliance !== 'ALL') addChip('Compliance: ' + currentCompliance, () => toggleComplianceFilter(currentCompliance));
    if (currentReqFilter) addChip('Requirement: ' + currentReqFilter.code, () => { currentReqFilter = null; filterFindings(); });
    if (query !== '') addChip('Search: "' + query + '"', () => clearSearch());

    if (resetBtn) {
        resetBtn.style.display = anyActive ? 'inline-block' : 'none';
    }
}

function copyTextFallback(text) {
    const prevFocus = document.activeElement;
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.left = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    let ok = false;
    try {
        ok = document.execCommand('copy');
    } catch (e) {
        ok = false;
    }
    document.body.removeChild(ta);
    if (prevFocus && typeof prevFocus.focus === 'function') {
        prevFocus.focus({ preventScroll: true });
    }
    return ok;
}

function copyTextWithFeedback(btn, text) {
    if (!text) return;
    const orig = btn.textContent;
    const showCopied = () => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1400);
    };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(text).then(showCopied).catch(() => {
            if (copyTextFallback(text)) showCopied();
        });
        return;
    }
    if (copyTextFallback(text)) {
        showCopied();
    }
}

function copySiblingCode(btn) {
    const box = btn.closest('.rule-evidence-box') || btn.parentElement;
    const code = box ? box.querySelector('.rule-preview-code') : null;
    if (code) copyTextWithFeedback(btn, code.textContent);
}

function copyCodeBlock(btn) {
    const box = btn.closest('.finding-exploit, .finding-remediation, .group-shared-remediation');
    const code = box ? box.querySelector('code') : null;
    if (code) copyTextWithFeedback(btn, code.textContent);
}
