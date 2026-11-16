/**
 * Shadow-Trace | UI Audit Logger (audit_logger.js)
 * Records all user and forensic activities across the Shadow-Trace system.
 * Cryptographically connects to HMAC-chained analyst_audit.db via pywebview.
 */

(function () {
    'use strict';

    // In-memory queue for actions triggered before pywebview bridge is initialized
    const pendingBridgeQueue = [];

    function deriveSeverity(actionType, details) {
        const text = `${actionType || ''} ${details || ''}`.toUpperCase();
        if (text.includes('FAIL') || text.includes('ERROR') || text.includes('STOP') ||
            text.includes('UNAUTHORIZED') || text.includes('TAMPER') || text.includes('DENIED') ||
            text.includes('WRONG') || text.includes('CRITICAL') || text.includes('ALERT') ||
            text.includes('INVALID')) {
            return 'error';
        }
        if (text.includes('CHANGE') || text.includes('UPDATE') || text.includes('QUARANTINE') ||
            text.includes('DELETE') || text.includes('RESTORE') || text.includes('MODIFY') ||
            text.includes('WARNING') || text.includes('PAUSE') || text.includes('PURGE') ||
            text.includes('RESET')) {
            return 'warning';
        }
        return 'normal';
    }

    function formatLocalDate(d) {
        const pad = (n) => String(n).padStart(2, '0');
        const y = d.getFullYear();
        const m = pad(d.getMonth() + 1);
        const day = pad(d.getDate());
        const h = pad(d.getHours());
        const min = pad(d.getMinutes());
        const s = pad(d.getSeconds());
        return `${y}-${m}-${day} ${h}:${min}:${s}`;
    }

    /**
     * Primary audit logging API exposed to entire window context
     */
    window.logUserAction = function (actionType, target, details, severity) {
        if (!actionType) return;
        const now = new Date();
        const sev = severity || deriveSeverity(actionType, details);
        const detailsStr = typeof details === 'object' ? JSON.stringify(details) : (details || '');
        const targetStr = target || '';

        const entry = {
            id: Date.now(),
            date: formatLocalDate(now),
            timestamp: now.toISOString(),
            user: localStorage.getItem('examiner_name') || 'examiner',
            examiner: localStorage.getItem('examiner_name') || 'examiner',
            action: actionType,
            action_type: actionType,
            target: targetStr,
            details: detailsStr,
            ip: '127.0.0.1',
            severity: sev,
            chain_hmac: 'LOCAL_BUFFERED'
        };

        // 1. Maintain local buffer for immediate real-time rendering & cross-page continuity
        try {
            const raw = localStorage.getItem('shadow_trace_user_audit');
            const list = raw ? JSON.parse(raw) : [];
            list.unshift(entry);
            if (list.length > 500) list.length = 500;
            localStorage.setItem('shadow_trace_user_audit', JSON.stringify(list));
        } catch (e) {
            console.warn('[AUDIT] Failed to save local buffer:', e);
        }

        // 2. Transmit to pywebview HMAC-chained backend if available
        if (window.pywebview && window.pywebview.api && window.pywebview.api.log_ui_action) {
            try {
                window.pywebview.api.log_ui_action(actionType, targetStr, detailsStr, sev);
            } catch (e) {
                console.error('[AUDIT] Bridge log_ui_action error:', e);
            }
        } else {
            pendingBridgeQueue.push({ actionType, target: targetStr, details: detailsStr, severity: sev });
        }

        // 3. Dispatch reactive custom event for any live UI table
        try {
            window.dispatchEvent(new CustomEvent('shadowtrace:audit_logged', { detail: entry }));
        } catch (e) {
            console.warn('[AUDIT] Event dispatch error:', e);
        }

        return entry;
    };

    // Flush any pending queue once pywebview bridge becomes ready
    window.addEventListener('pywebviewready', function () {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.log_ui_action) {
            while (pendingBridgeQueue.length > 0) {
                const item = pendingBridgeQueue.shift();
                try {
                    window.pywebview.api.log_ui_action(item.actionType, item.target, item.details, item.severity);
                } catch (e) {
                    console.error('[AUDIT] Error flushing pending log item:', e);
                }
            }
        }
    });

    // Auto-detect and log current page visit
    function logPageVisit() {
        const path = window.location.pathname.toLowerCase();
        let pageName = 'Application';
        if (path.includes('dashboard')) pageName = 'Dashboard';
        else if (path.includes('manual_scan')) pageName = 'Manual Scan';
        else if (path.includes('case_manager')) pageName = 'Case Manager';
        else if (path.includes('qurantine')) pageName = 'Quarantined Files';
        else if (path.includes('user_profile')) pageName = 'User Profile';
        else if (path.includes('system_info')) pageName = 'System Info';
        else if (path.includes('settings')) pageName = 'Settings';

        const lastPage = sessionStorage.getItem('st_last_logged_page');
        if (lastPage !== pageName) {
            sessionStorage.setItem('st_last_logged_page', pageName);
            window.logUserAction('NAVIGATE_PAGE', pageName, `Navigated to ${pageName} module`, 'normal');
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', logPageVisit);
    } else {
        logPageVisit();
    }

    // Attach global CSV exporter
    window.exportAuditLogsAsCSV = function (logsArray) {
        if (!logsArray || !logsArray.length) {
            alert('No audit logs available to export.');
            return;
        }
        const headers = ['ID', 'Date', 'User', 'Action', 'Details', 'IP Address', 'Severity', 'HMAC Signature'];
        const csvRows = [headers.join(',')];

        logsArray.forEach(item => {
            const row = [
                item.id || '',
                `"${(item.date || item.timestamp || '').replace(/"/g, '""')}"`,
                `"${(item.user || item.examiner || '').replace(/"/g, '""')}"`,
                `"${(item.action || item.action_type || '').replace(/"/g, '""')}"`,
                `"${(item.details || '').replace(/"/g, '""')}"`,
                `"${(item.ip || item.ip_address || '').replace(/"/g, '""')}"`,
                `"${(item.severity || 'normal').replace(/"/g, '""')}"`,
                `"${(item.chain_hmac || '').replace(/"/g, '""')}"`
            ];
            csvRows.push(row.join(','));
        });

        const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvRows.join('\n'));
        const link = document.createElement('a');
        link.setAttribute('href', csvContent);
        link.setAttribute('download', `shadowtrace_audit_ledger_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        window.logUserAction('AUDIT_EXPORTED', 'Audit Ledger', `Exported ${logsArray.length} audit records to CSV`, 'normal');
    };


    // ── Workstation Lock Screen Integration ───────────────────────────────────────
    window.lockWorkstation = function (targetReturnPage) {
        let returnPage = targetReturnPage;
        if (!returnPage) {
            const path = window.location.pathname;
            const filename = path.substring(path.lastIndexOf('/') + 1) || 'dashboard.html';
            if (filename !== 'lock.html') {
                returnPage = filename;
            } else {
                returnPage = sessionStorage.getItem('shadowtrace_return_page') || 'dashboard.html';
            }
        }
        sessionStorage.setItem('shadowtrace_return_page', returnPage);
        localStorage.setItem('shadowtrace_return_page', returnPage);
        sessionStorage.setItem('shadowtrace_is_locked', 'true');
        localStorage.setItem('shadowtrace_is_locked', 'true');

        window.logUserAction(
            'SYSTEM_LOCK',
            'Workstation Terminal',
            `Workstation terminal locked by analyst from ${returnPage}`,
            'normal'
        );

        window.location.href = 'lock.html';
    };

    function bindLockButtons() {
        const lockElements = document.querySelectorAll('button[title="lock app"], [data-action="lock"], .lock-app-btn');
        lockElements.forEach(btn => {
            if (!btn.dataset.lockBound) {
                btn.dataset.lockBound = 'true';
                btn.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    window.lockWorkstation();
                });
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindLockButtons);
    } else {
        bindLockButtons();
    }// ── Notifications Drawer & Real-Time Sync Subsystem ─────────────────────────────
    
    // Clear any tainted state left over from the previous rapid-double-click bug
    (function initNotificationStorage() {
        try {
            if (localStorage.getItem('st_notif_fixed_v4') !== 'true') {
                localStorage.removeItem('st_notifications_last_opened');
                localStorage.removeItem('st_notifications_cleared_at');
                localStorage.removeItem('st_has_opened_drawer');
                localStorage.setItem('st_unread_notifs', 'true');
                localStorage.setItem('st_notif_fixed_v4', 'true');
            }
        } catch (e) {}
    })();

    // Ensure CSS is present for slide-in drawer
    function ensureNotificationStyle() {
        if (!document.getElementById('st-notifications-style')) {
            const style = document.createElement('style');
            style.id = 'st-notifications-style';
            style.textContent = `
                #notification-panel {
                    position: fixed !important;
                    top: 0 !important;
                    right: 0 !important;
                    height: 100vh !important;
                    width: 380px !important;
                    max-width: 90vw !important;
                    background-color: rgba(18, 18, 18, 0.96) !important;
                    backdrop-filter: blur(16px) !important;
                    -webkit-backdrop-filter: blur(16px) !important;
                    border-left: 1px solid rgba(255, 255, 255, 0.1) !important;
                    box-shadow: -8px 0 32px rgba(0, 0, 0, 0.6) !important;
                    transform: translateX(100%) !important;
                    transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
                    z-index: 999999 !important;
                    display: flex !important;
                    flex-direction: column !important;
                    pointer-events: none;
                    visibility: hidden;
                }
                #notification-panel.open {
                    transform: translateX(0) !important;
                    pointer-events: auto !important;
                    visibility: visible !important;
                }
                .glass-panel {
                    background-color: rgba(18, 18, 18, 0.96) !important;
                    backdrop-filter: blur(16px) !important;
                    -webkit-backdrop-filter: blur(16px) !important;
                }
            `;
            document.head.appendChild(style);
        }
    }

    function ensureNotificationPanelDOM() {
        ensureNotificationStyle();
        let panel = document.getElementById('notification-panel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'notification-panel';
            panel.className = 'fixed right-0 top-0 h-full w-[380px] glass-panel border-l border-outline-variant z-[999999] flex flex-col shadow-2xl';
            panel.innerHTML = `
                <div class="p-stack-lg border-b border-outline-variant flex justify-between items-center bg-surface-container/50">
                    <div class="flex items-center gap-2">
                        <span class="material-symbols-outlined text-primary text-[20px]">notifications_active</span>
                        <h3 class="font-bold text-primary text-xl uppercase tracking-tight">Notifications</h3>
                    </div>
                    <button class="material-symbols-outlined text-on-surface-variant hover:text-error transition-colors bg-surface-container-highest p-1 rounded cursor-pointer" onclick="toggleNotifications(event)">close</button>
                </div>
                <div class="flex-1 overflow-y-auto custom-scrollbar p-stack-md space-y-3" id="notifications-list">
                    <div class="flex items-center justify-center py-12 text-on-surface-variant/40">
                        <span class="material-symbols-outlined animate-spin text-2xl mr-2">progress_activity</span>
                        <span class="font-data-mono text-xs">Loading alerts...</span>
                    </div>
                </div>
                <div class="p-stack-md border-t border-outline-variant">
                    <button onclick="clearAllNotifications()" class="w-full py-2 bg-surface-container-highest border border-outline-variant rounded text-on-surface hover:text-primary transition-all font-code-sm text-[12px] uppercase tracking-widest cursor-pointer hover:bg-surface-container">Clear All History</button>
                </div>
            `;
            document.body.appendChild(panel);
        }
        return panel;
    }

    // Toggle drawer with debounce to prevent double-firing
    let _lastNotifToggle = 0;
    window.toggleNotifications = function (e) {
        if (e && e.preventDefault) e.preventDefault();
        if (e && e.stopPropagation) e.stopPropagation();

        const now = Date.now();
        if (now - _lastNotifToggle < 300) {
            return; // Ignore duplicate event firing in rapid succession
        }
        _lastNotifToggle = now;

        const panel = ensureNotificationPanelDOM();
        if (!panel) return;

        const willOpen = !panel.classList.contains('open');
        if (willOpen) {
            panel.classList.add('open');
            // Mark notifications as viewed
            localStorage.setItem('st_has_opened_drawer', 'true');
            localStorage.setItem('st_notifications_last_opened', Date.now().toString());
            localStorage.setItem('st_unread_notifs', 'false');
            window.updateNotificationBellDot(false);
            window.renderNotifications();
        } else {
            panel.classList.remove('open');
        }
    };
    window.auditToggleNotifications = window.toggleNotifications;

    window.closeNotifications = function (e) {
        if (e && e.preventDefault) e.preventDefault();
        if (e && e.stopPropagation) e.stopPropagation();
        const panel = document.getElementById('notification-panel');
        if (panel) {
            panel.classList.remove('open');
        }
    };

    window.clearAllNotifications = function () {
        const now = Date.now();
        localStorage.setItem('st_notifications_cleared_at', now.toString());
        localStorage.setItem('st_notifications_last_opened', now.toString());
        localStorage.setItem('st_unread_notifs', 'false');
        window.updateNotificationBellDot(false);
        window.renderNotifications([]);

        if (window.pywebview && window.pywebview.api && window.pywebview.api.clear_notifications) {
            try {
                window.pywebview.api.clear_notifications();
            } catch (e) {
                console.warn('[NOTIFICATIONS] Bridge clear_notifications error:', e);
            }
        }
    };

    window.renderNotifications = async function (explicitItems) {
        ensureNotificationPanelDOM();
        const listEl = document.getElementById('notifications-list');
        if (!listEl) return;

        let items = explicitItems;
        if (!items) {
            if (window.pywebview && window.pywebview.api && window.pywebview.api.get_notifications) {
                try {
                    const raw = await window.pywebview.api.get_notifications(50);
                    items = typeof raw === 'string' ? JSON.parse(raw) : raw;
                } catch (e) {
                    console.warn('[NOTIFICATIONS] Bridge fetch error:', e);
                }
            }
        }

        if (!items) {
            try {
                const localAudit = JSON.parse(localStorage.getItem('shadow_trace_user_audit') || '[]');
                items = localAudit.slice(0, 30).map(a => ({
                    id: a.id,
                    tag: a.action_type || a.action || 'ACTIVITY',
                    title: a.target || 'System Activity',
                    message: a.details || a.action,
                    severity: a.severity || 'normal',
                    timestamp: a.timestamp || a.date,
                    epoch: (new Date(a.timestamp || a.date || Date.now())).getTime() / 1000,
                    time_ago: 'Recent'
                }));
            } catch (e) {
                items = [];
            }
        }

        const clearedAt = parseFloat(localStorage.getItem('st_notifications_cleared_at') || '0');
        const activeItems = (items || []).filter(item => {
            const itemEpochMs = (item.epoch ? item.epoch * 1000 : (new Date(item.timestamp || 0)).getTime());
            return itemEpochMs > clearedAt;
        });

        if (activeItems.length === 0) {
            listEl.innerHTML = `
                <div class="flex flex-col items-center justify-center py-20 text-center text-on-surface-variant/40 space-y-2">
                    <span class="material-symbols-outlined text-4xl text-on-surface-variant/30">notifications_off</span>
                    <p class="font-data-mono text-xs uppercase tracking-wider text-on-surface-variant/60">No Active Notifications</p>
                    <p class="text-[11px] text-on-surface-variant/40 max-w-[200px]">All threats, alerts and system events have been reviewed.</p>
                </div>
            `;
            return;
        }

        let html = '';
        activeItems.forEach(item => {
            const sev = (item.severity || 'info').toLowerCase();
            let borderClass = 'border-l-secondary';
            let tagColor = 'text-secondary';

            if (sev === 'error' || sev === 'critical') {
                borderClass = 'border-l-error border-l-[#ff5252]';
                tagColor = 'text-error text-[#ff5252]';
            } else if (sev === 'warning') {
                borderClass = 'border-l-warning border-l-[#f39c12]';
                tagColor = 'text-warning text-[#f39c12]';
            } else if (sev === 'success' || sev === 'ok') {
                borderClass = 'border-l-success border-l-[#27ae60]';
                tagColor = 'text-success text-[#27ae60]';
            }

            html += `
                <div class="p-stack-md bg-surface-container border border-outline-variant rounded-lg border-l-4 ${borderClass} transition-all hover:bg-surface-bright/50">
                    <div class="flex justify-between items-start mb-1">
                        <span class="font-label-caps ${tagColor} text-[10px] uppercase font-bold tracking-wider">${item.tag || 'SYSTEM ALERT'}</span>
                        <span class="font-code-sm text-on-surface-variant text-[10px]">${item.time_ago || 'Recently'}</span>
                    </div>
                    <p class="text-[13px] text-on-surface font-medium leading-snug">${item.message || item.title || ''}</p>
                </div>
            `;
        });

        listEl.innerHTML = html;
    };

    window.updateNotificationBellDot = function (hasUnread) {
        const dots = document.querySelectorAll(
            '#notification-bell-dot, .notification-bell-dot, button[title="notifications"] span.bg-error, div.relative div.bg-error, button[title="notifications"] span.rounded-full'
        );
        dots.forEach(dot => {
            if (hasUnread) {
                dot.style.display = 'block';
                dot.classList.remove('hidden');
            } else {
                dot.style.display = 'none';
                dot.classList.add('hidden');
            }
        });
    };

    window.checkNotificationStatus = async function () {
        let items = null;
        if (window.pywebview && window.pywebview.api && window.pywebview.api.get_notifications) {
            try {
                const raw = await window.pywebview.api.get_notifications(40);
                items = typeof raw === 'string' ? JSON.parse(raw) : raw;
            } catch (e) {}
        }

        if (!items) {
            try {
                const localAudit = JSON.parse(localStorage.getItem('shadow_trace_user_audit') || '[]');
                items = localAudit.map(a => ({
                    epoch: (new Date(a.timestamp || a.date || Date.now())).getTime() / 1000
                }));
            } catch (e) {
                items = [];
            }
        }

        const hasOpened = localStorage.getItem('st_has_opened_drawer') === 'true';
        const lastOpened = parseFloat(localStorage.getItem('st_notifications_last_opened') || '0');
        const clearedAt = parseFloat(localStorage.getItem('st_notifications_cleared_at') || '0');

        // Check unread count:
        // If user has cleared: only items created AFTER clearedAt
        // If user has opened: only items created AFTER lastOpened
        // If user has never opened and never cleared: all active items count as unread!
        const activeUnread = (items || []).filter(item => {
            const itemEpochMs = (item.epoch ? item.epoch * 1000 : (new Date(item.timestamp || 0)).getTime());
            if (clearedAt && itemEpochMs <= clearedAt) {
                return false;
            }
            if (hasOpened && lastOpened && itemEpochMs <= lastOpened) {
                return false;
            }
            return true;
        });

        const hasUnread = (activeUnread.length > 0);
        localStorage.setItem('st_unread_notifs', hasUnread ? 'true' : 'false');
        window.updateNotificationBellDot(hasUnread);
    };

    /**
     * Synchronizes sidebar monitoring status (ACTIVE MONITORING with green blinking dot vs MONITORING OFF with red blinking dot)
     * across ALL sections (dashboard, case manager, manual scan, quarantine, user profile, system info, settings).
     */
    window.updateSidebarMonitoring = function (isActive) {
        const containers = document.querySelectorAll('.sidebar-monitoring');
        containers.forEach(container => {
            const dot = container.querySelector('.rounded-full') || container.querySelector('div > div:first-child');
            const text = container.querySelector('span');
            if (!dot || !text) return;

            if (isActive) {
                // Active Monitoring: Green blinking dot & text
                dot.classList.remove('bg-error', 'shadow-[0_0_12px_rgba(231,76,60,0.6)]');
                dot.classList.add('bg-[#27ae60]', 'shadow-[0_0_12px_rgba(39,174,96,0.6)]', 'animate-pulse');
                dot.style.backgroundColor = '#27ae60';
                dot.style.boxShadow = '0 0 12px rgba(39,174,96,0.6)';

                text.classList.remove('text-error');
                text.classList.add('text-[#27ae60]');
                text.style.color = '#27ae60';
                text.textContent = 'ACTIVE MONITORING';
            } else {
                // Monitoring Off: Red blinking dot & text
                dot.classList.remove('bg-[#27ae60]', 'shadow-[0_0_12px_rgba(39,174,96,0.6)]');
                dot.classList.add('bg-error', 'shadow-[0_0_12px_rgba(231,76,60,0.6)]', 'animate-pulse');
                dot.style.backgroundColor = '';
                dot.style.boxShadow = '';

                text.classList.remove('text-[#27ae60]');
                text.classList.add('text-error');
                text.style.color = '';
                text.textContent = 'MONITORING OFF';
            }
        });
    };

    window.syncSidebarMonitoringStatus = function () {
        let active = false;
        try {
            const stored = localStorage.getItem('always_on_monitoring');
            if (stored !== null) {
                active = (stored === 'true');
            } else {
                const settingsRaw = localStorage.getItem('shadowtrace_settings');
                if (settingsRaw) {
                    const s = JSON.parse(settingsRaw);
                    if (s && s.always_on_monitoring !== undefined) {
                        active = Boolean(s.always_on_monitoring);
                    }
                }
            }
        } catch (e) {
            console.warn('[MONITOR_SYNC] LocalStorage parse error:', e);
        }

        window.updateSidebarMonitoring(active);

        // Authoritative sync from backend if pywebview bridge is active
        if (window.pywebview && window.pywebview.api && window.pywebview.api.get_settings) {
            window.pywebview.api.get_settings().then(raw => {
                try {
                    const data = (typeof raw === 'string') ? JSON.parse(raw) : raw;
                    if (data && data.always_on_monitoring !== undefined) {
                        const isAlwaysOn = Boolean(data.always_on_monitoring);
                        localStorage.setItem('always_on_monitoring', isAlwaysOn ? 'true' : 'false');
                        window.updateSidebarMonitoring(isAlwaysOn);
                    }
                } catch (err) {}
            }).catch(() => {});
        }
    };

    function bindNotificationElements() {
        ensureNotificationPanelDOM();

        const bellSelectors = 'button[title="notifications"], [data-action="notifications"]';
        document.querySelectorAll(bellSelectors).forEach(btn => {
            btn.style.cursor = 'pointer';
            btn.onclick = function (e) {
                window.toggleNotifications(e);
            };
        });

        window.checkNotificationStatus();
        window.syncSidebarMonitoringStatus();
    }

    // Cross-page storage & focus sync for monitoring status
    window.addEventListener('storage', function (e) {
        if (e.key === 'always_on_monitoring' || e.key === 'shadowtrace_settings') {
            window.syncSidebarMonitoringStatus();
        }
    });

    window.addEventListener('shadowtrace:monitoring_changed', function (e) {
        if (e && e.detail && typeof e.detail.active === 'boolean') {
            window.updateSidebarMonitoring(e.detail.active);
        } else {
            window.syncSidebarMonitoringStatus();
        }
    });

    window.addEventListener('focus', function () {
        window.syncSidebarMonitoringStatus();
    });

    // Close drawer when clicking outside
    document.addEventListener('click', function (e) {
        const panel = document.getElementById('notification-panel');
        if (!panel || !panel.classList.contains('open')) return;

        const bellBtn = e.target.closest('button[title="notifications"], [data-action="notifications"]');
        if (bellBtn || panel.contains(e.target)) {
            return;
        }
        panel.classList.remove('open');
    });

    // Real-time events
    window.addEventListener('shadowtrace:audit_logged', function (e) {
        const detail = (e && e.detail) || {};
        const action = (detail.action || detail.action_type || '').toUpperCase();
        if (action === 'NAVIGATE_PAGE' || action === 'TAB_SWITCHED' || action === 'NOTIFICATIONS_CLEARED') {
            return;
        }

        const panel = document.getElementById('notification-panel');
        if (panel && panel.classList.contains('open')) {
            window.renderNotifications();
        } else {
            localStorage.setItem('st_unread_notifs', 'true');
            window.updateNotificationBellDot(true);
        }
    });

    window.addEventListener('pywebviewready', function () {
        window.checkNotificationStatus();
        window.syncSidebarMonitoringStatus();
    });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindNotificationElements);
    } else {
        bindNotificationElements();
    }

    setInterval(window.checkNotificationStatus, 10000);

})();
