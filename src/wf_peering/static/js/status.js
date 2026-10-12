(function () {
    "use strict"

    const root = document.getElementById("peering-status")
    if (!root) return
    const API = root.dataset.api
    const ROLE = root.dataset.role
    const TEXT = (() => {
        try { return JSON.parse(document.getElementById("peering-texts")?.textContent || "{}") }
        catch { return {} }
    })()

    function t(key, values) {
        let text = TEXT[key] ?? key
        for (const [name, value] of Object.entries(values || {})) text = text.replace(`%(${name})s`, String(value))
        return text
    }

    function el(tag, attrs, ...children) {
        const node = document.createElement(tag)
        for (const [key, value] of Object.entries(attrs || {})) {
            if (value === null || value === undefined || value === false) continue
            if (key === "class") node.className = value
            else if (key === "text") node.textContent = String(value)
            else node.setAttribute(key, String(value))
        }
        for (const child of children.flat()) {
            if (child === null || child === undefined || child === false) continue
            node.append(child instanceof Node ? child : document.createTextNode(String(child)))
        }
        return node
    }

    function badge(kind) {
        const map = { local: "LOCAL", peer: "PEER", claimed: "CLAIMED", unverifiable: "UNVERIFIABLE", self: "SELF",
                      "host-claimed": "CLAIMED", derived: "PEER" }
        const css = { "host-claimed": "claimed", derived: "peer", self: "claimed" }[kind] || kind
        return el("span", { class: `badge ${css}`, text: t(map[kind] || kind) })
    }

    function short(hash) {
        return typeof hash === "string" && hash.length > 20 ? `${hash.slice(0, 10)}…${hash.slice(-8)}` : (hash ?? "–")
    }

    function when(value) {
        if (!value) return "–"
        const date = new Date(value)
        return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
    }

    async function load(path) {
        try {
            const response = await fetch(`${API}${path}`, { credentials: "omit", cache: "no-store" })
            if (!response.ok) return { error: `HTTP ${response.status}` }
            return await response.json()
        } catch (error) {
            return { error: String(error) }
        }
    }

    function card(title, body, options = {}) {
        const section = el("section", { class: `card${options.wide ? " wide" : ""}` }, el("h2", { text: title }), body)
        if (options.score !== undefined && options.score !== null) window.wfTrust.apply(section, options.score)
        return section
    }

    function table(headers, rows) {
        if (!rows.length) return el("p", { class: "empty", text: t("NONE") })
        return el("table", {},
            el("thead", {}, el("tr", {}, headers.map(header => el("th", { text: header })))),
            el("tbody", {}, rows.map(row => el("tr", {}, row.map(cell =>
                cell instanceof Node ? el("td", {}, cell) : el("td", { class: /^[0-9a-f]{16,}$/.test(String(cell)) ? "mono" : null, text: cell ?? "–" })
            ))))
        )
    }

    function hero(trust) {
        const value = document.getElementById("score-value")
        const label = document.getElementById("score-label")
        const host = trust && !trust.error ? trust.report?.host : null
        if (!host || host.score === null || host.score === undefined) {
            value.textContent = "?"
            label.textContent = t("UNCLEAR")
            window.wfTrust.apply(root, null)
            return
        }
        value.textContent = String(host.score)
        label.textContent = host.status === "assessed" ? `${host.level} · ${host.basis}` : `${t("UNCLEAR")} · ${host.basis}`
        if (host.status === "assessed") window.wfTrust.apply(root, host.score)
        else window.wfTrust.apply(root, null)
    }

    function trustCard(trust) {
        if (!trust || trust.error) return card(t("TRUST"), el("p", { class: "empty", text: trust?.error || t("NONE") }))
        const report = trust.report
        const host = report.host
        const population = report.population || {}
        const children = []
        if (host.perspective === "self") children.push(el("p", { class: "notice" }, badge("self"), " ", t("SELF_NOTE")))
        if (host.status !== "assessed") children.push(el("p", { class: "notice", text: t("INSUFFICIENT") }))
        children.push(el("p", {},
            `${t("COMPLETENESS")}: ${host.completeness}% · ${t("BASIS")}: ${host.basis} · ${t("OBSERVERS")}: ${host.independent_observers}`))
        children.push(el("p", { class: "muted" },
            `${t("COUNTS")}: ${population.known ?? 0} / ${population.reported ?? 0} / ${population.reachable ?? 0} / ${population.verified ?? 0}`))
        if (host.caps?.length) children.push(el("ul", { class: "list" }, host.caps.map(cap =>
            el("li", {}, el("span", { class: "badge bad", text: cap.severity }), ` ${cap.signal} → max ${cap.cap}`))))
        children.push(el("details", {}, el("summary", { text: `${t("SIGNALS")} (${host.signals.length})` }),
            table([t("COL_SIGNAL"), t("COL_VALUE"), t("COL_SEVERITY"), t("COL_SOURCE"), t("COL_STATE"), t("COL_OBSERVED")], host.signals.map(signal => [
                signal.id, signal.value ?? "–", signal.severity, badge(signal.source), signal.state, when(signal.observed_at)
            ]))))
        children.push(el("p", { class: "muted", text: `${when(report.computed_at)} · ${t("NODE_LABEL", { node: trust.node })}` }))
        return card(t("TRUST"), el("div", {}, children), { wide: true, score: host.status === "assessed" ? host.score : null })
    }

    function nodeCard(status) {
        if (status.error) return card(t("NODE"), el("p", { class: "empty", text: status.error }))
        const rows = [
            [t("COL_ROLE"), status.role], [t("COL_NODE"), status.node], [t("COL_URL"), status.url], [t("ROW_HOST"), status.host],
            [t("ACTIVE_SINCE"), when(status.started_at)], [t("ROW_UPTIME"), `${Math.round((status.uptime_seconds || 0) / 3600)} h`],
            [t("COL_LEDGER"), `${status.ledger?.size ?? 0} · ${short(status.ledger?.head)}`]
        ]
        if (status.link) rows.push([t("CONNECTION"), `${status.link.state}${status.link.error ? ` (${status.link.error})` : ""} · ${when(status.link.last_heartbeat)}`])
        if (status.host_key) rows.push([t("ROW_HOST_KEY"), status.host_key])
        if (status.verification) rows.push([t("ROW_SELF_CHECK"), status.verification.valid && status.verification.journal_valid ? "ok" : t("SELF_CHECK_FAILED")])
        return card(t("NODE"), table(["", ""], rows))
    }

    function peersCard(peers) {
        if (peers.error) return card(t("PEERS"), el("p", { class: "empty", text: peers.error }))
        const rows = (peers.peers || []).map(peer => [
            peer.url,
            el("span", {}, (peer.sources || []).map(source => el("span", { class: "badge", text: source }))),
            t(peer.connected ? "STATE_CONNECTED" : (peer.last_check?.ok ? "STATE_REACHABLE" : (peer.last_check ? "STATE_UNREACHABLE" : "STATE_UNCHECKED"))),
            peer.last_check?.identity || "–",
            peer.last_check?.comparison || "–",
            when(peer.last_seen)
        ])
        return card(t("PEERS"), el("div", {},
            el("p", { class: "muted", text: peers.claim }),
            table([t("COL_URL"), t("COL_SOURCE"), t("COL_STATE"), t("COL_IDENTITY"), t("COL_LEDGER"), t("COL_LAST_SEEN")], rows)), { wide: true })
    }

    function integrityCard(integrity) {
        if (integrity.error) return card(t("INTEGRITY"), el("p", { class: "empty", text: integrity.error }))
        const served = [], published = []
        for (const group of integrity.groups || []) {
            for (const item of group.records) {
                const record = item.record
                const row = [
                    record.id, group.provider, record.type || "–", record.served_version || record.version || "–",
                    record.latest_version || "–", short(record.hash), item.chain_length ?? 1,
                    badge(integrity.source === "host-ledger" ? "claimed" : "self"),
                    item.missing_since ? `${t("MISSING_SINCE")} ${when(item.missing_since)}` : when(item.confirmed_at)
                ]
                if (record.served === false) published.push([record.label || record.id, ...row.slice(1)])
                else served.push(row)
            }
        }
        const headers = [t("COL_ID"), t("COL_PROVIDER"), t("COL_TYPE"), t("COL_SERVED"), t("COL_LATEST"), t("COL_HASH"),
                         t("COL_CHAIN"), t("COL_SOURCE"), t("COL_CONFIRMED")]
        const body = el("div", {}, table(headers, served))
        if (published.length) body.append(el("details", {}, el("summary", { text: `${t("PUBLISHED")} (${published.length})` }),
            table(headers, published)))
        return card(t("INTEGRITY"), body, { wide: true })
    }

    function checkpointsCard(checkpoints) {
        if (checkpoints.error) return card(t("CHECKPOINTS"), el("p", { class: "empty", text: checkpoints.error }))
        const rows = (checkpoints.checkpoints || []).map(item => [
            item.day, item.status, item.content?.ledger?.size ?? "–", short(item.content?.ledger?.root),
            short(item.content?.state?.root), when(item.computed_at)
        ])
        return card(t("CHECKPOINTS"), el("div", {}, el("p", { class: "muted", text: t("STALE_NOTE") }),
            table([t("COL_DAY"), t("COL_STATUS"), t("COL_SIZE"), t("COL_LEDGER_ROOT"), t("COL_STATE_ROOT"), t("COL_COMPUTED")], rows)))
    }

    function agreementCard(agreement) {
        if (agreement.error) return card(t("AGREEMENT"), el("p", { class: "empty", text: agreement.error }))
        const rows = (agreement.nodes || []).map(node => [
            node.node, node.role || "–", node.status || "–", node.size, short(node.root), node.verdict, badge(node.via === "direct" ? "peer" : "claimed")
        ])
        return card(t("AGREEMENT"), el("div", {},
            el("p", { class: "muted", text: `${agreement.day || "–"} · ${agreement.size ?? "–"} · ${short(agreement.root)}` }),
            table([t("COL_NODE"), t("COL_ROLE"), t("COL_STATUS"), t("COL_SIZE"), t("COL_ROOT"), t("COL_VERDICT"), t("COL_VIA")], rows)))
    }

    function syncCard(sync, status) {
        if (sync.error) return card(t("SYNC"), el("p", { class: "empty", text: sync.error }))
        const children = [table(["", ""], [
            [t("NEXT_SYNC"), sync.next_full_sync ? when(sync.next_full_sync) : "–"],
            [t("NEXT_CHECKPOINT"), when(sync.next_checkpoint)],
            [t("LAST_SYNC"), status.last_sync ? `${when(status.last_sync.finished_at)} · ${status.last_sync.to_seq}` : "–"]
        ])]
        if ((sync.runs || []).length) children.push(table([t("COL_DAY"), t("COL_KIND"), t("COL_STATUS"), t("COL_TO"), t("COL_ERROR"), t("COL_FINISHED")],
            sync.runs.slice(0, 10).map(run => [run.day, run.kind, run.status, run.to_seq ?? "–", run.error || "–", when(run.finished_at)])))
        return card(t("SYNC"), el("div", {}, children))
    }

    function uptimeCard(uptime) {
        if (uptime.error) return card(t("UPTIME"), el("p", { class: "empty", text: uptime.error }))
        const self = uptime.self || {}
        const rows = [[t("THIS_NODE"), badge("self"), `${self.ratio_24h ?? "–"}% / ${self.ratio_7d ?? "–"}% / ${self.ratio_30d ?? "–"}%`,
            (self.downtimes || []).length]]
        if (uptime.host) rows.push([t("ROW_HOST"), badge("local"), `${uptime.host.ratio ?? "–"}% (${uptime.host.samples})`, uptime.host.outage_count ?? 0])
        for (const [url, data] of Object.entries(uptime.peers || {})) {
            rows.push([url, badge("local"), `${data.ratio ?? "–"}% (${data.samples})`, data.outage_count ?? 0])
        }
        return card(t("UPTIME"), table([t("COL_TARGET"), t("COL_SOURCE"), t("COL_RATIOS"), t("COL_OUTAGES")], rows))
    }

    function conflictsCard(conflicts) {
        if (conflicts.error) return card(t("CONFLICTS"), el("p", { class: "empty", text: conflicts.error }))
        const rows = (conflicts.conflicts || []).slice(0, 50).map(item => [
            el("span", { class: `badge ${item.severity === "critical" || item.severity === "high" ? "bad" : ""}`, text: item.severity }),
            item.kind, item.summary, when(item.detected_at), item.resolved_at ? when(item.resolved_at) : t("STATE_OPEN")
        ])
        return card(t("CONFLICTS"), table(["", t("COL_KIND"), t("COL_SUMMARY"), t("COL_DETECTED"), t("COL_STATE")], rows), { wide: true })
    }

    async function render() {
        const [status, trust, peers, integrity, checkpoints, agreement, sync, uptime, conflicts] = await Promise.all([
            load("/status"), load("/trust"), load("/peers"), load("/integrity"), load("/checkpoints?limit=14"),
            load("/checkpoints/agreement"), ROLE === "peer" ? load("/sync") : Promise.resolve(null), load("/uptime"),
            load("/conflicts")
        ])
        hero(trust)
        const sections = document.getElementById("sections")
        sections.replaceChildren(
            trustCard(trust), nodeCard(status),
            syncCard(sync || { next_checkpoint: (status.schedule || {}).checkpoint, runs: [] }, status), integrityCard(integrity),
            checkpointsCard(checkpoints), agreementCard(agreement), peersCard(peers), uptimeCard(uptime),
            conflictsCard(conflicts)
        )
    }

    render()
    setInterval(render, 60000)
})()
