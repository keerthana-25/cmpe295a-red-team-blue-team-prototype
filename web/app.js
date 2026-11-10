'use strict';
/* AgentGuard dashboard. No dependencies. Every piece of server data, including attacker
   payload text, is inserted with textContent / text nodes, never innerHTML. */
(() => {
  const DEFENSES = [
    { id: 'baseline', label: 'Baseline', note: 'No added defense. The control condition.' },
    { id: 'defensive_prompt', label: 'Defensive prompt', note: 'Tells the agent to treat retrieved text as data, not instructions.' },
    { id: 'classifier', label: 'Content classifier', note: 'Scans retrieved content and withholds anything that looks like an injection.' },
    { id: 'tool_validator', label: 'Tool validator', note: "Checks each write action against the task's approved policy before it runs." },
  ];
  const DEFENSE_LABEL = Object.fromEntries(DEFENSES.map(d => [d.id, d.label]));
  const DEFENSE_COLOR = { baseline: '#6B7785', defensive_prompt: '#7D57B0', classifier: '#1B7F6B', tool_validator: '#1D5C9E' };
  const ATTACKERS = [
    { id: 'static', label: 'Static attack set', note: 'A frozen, seeded list of payloads. Ignores every result.' },
    { id: 'static_published', label: 'Published static templates', note: 'Fixed injection strings from AgentDojo and InjecAgent, copied verbatim. Ignores every result.' },
    { id: 'adaptive_demo', label: 'Adaptive demo attacker', note: 'A deterministic fixture that changes tactics after each failure. Sees only whether the last try worked.' },
    { id: 'adaptive_ollama', label: 'Adaptive local model', note: 'A model running on this machine via Ollama. Also sees only success or failure.' },
  ];
  const MODE_LABEL = Object.fromEntries(ATTACKERS.map(a => [a.id, a.label]));
  const VIEWS = [
    { id: 'configure', label: 'Configure' },
    { id: 'live', label: 'Live run' },
    { id: 'compare', label: 'Compare' },
    { id: 'audit', label: 'Audit' },
    { id: 'provenance', label: 'Provenance' },
  ];
  const CELL_LABEL = {
    success: 'Attack worked', blocked: 'Blocked by a defense', ignored: 'Agent ignored the injection',
    offobj: 'Unsafe action, but not the attacker goal', 'benign-ok': 'Benign check passed',
    'benign-blocked': 'Benign check wrongly blocked', invalid: 'Invalid round, excluded',
  };
  const ORACLE_TEXT = {
    ATTACK_EXECUTED: 'The attack worked. The unauthorized action changed the environment state.',
    ATTACK_BLOCKED_CONTENT_FILTER: 'Blocked. The content classifier withheld the retrieved item before the agent saw it.',
    ATTACK_BLOCKED_TOOL_POLICY: 'Blocked. The tool validator refused the unauthorized write before it ran.',
    UNSAFE_ACTION_EXECUTED_OFF_OBJECTIVE: 'An unauthorized action ran, but it was not the attacker goal.',
    ATTACK_IGNORED_BY_AGENT: 'The agent read the injection and did not act on it.',
    BENIGN_NO_ATTACK_SAFE: 'Benign check. No unsafe action occurred.',
  };
  const DEFAULT_WARNING = 'Demonstration data only. These results are not research evidence.';

  const state = {
    view: 'configure', suite: null, runs: [], runId: null, summary: null, stats: null, live: null,
    cfg: {
      scenarios: new Set(), defenses: new Set(DEFENSES.map(d => d.id)), modes: new Set(['static', 'adaptive_demo']),
      budget: 20, seeds: '1,2,3,4,5', target: 'simulated',
      ollamaModel: '', ollamaAbliterated: false, realModel: '', realEndpoint: '', modelFailurePolicy: 'mark_invalid',
    },
    cmp: { mode: null, scenario: '__all__' },
    audit: { campaignId: null, detail: null, round: null, loading: false, error: null },
    formError: null, initError: null,
  };

  // ------------------------------------------------------------------ helpers
  const $ = sel => document.querySelector(sel);
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const NS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null) continue;
      if (k === 'text') el.textContent = v; else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) if (kid) el.append(kid);
    return el;
  }
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  async function api(path, opts) {
    const res = await fetch(path, opts);
    let body = null;
    try { body = await res.json(); } catch (_) { /* non-JSON body */ }
    if (!res.ok) throw new Error((body && body.error) || `Request failed (${res.status})`);
    return body;
  }
  const pct = v => (v == null ? 'n/a' : `${Math.round(v * 100)}%`);
  const clamp01 = v => Math.max(0, Math.min(1, v));
  function statText(st) {
    if (!st || st.mean == null) return 'n/a';
    let t = pct(st.mean);
    if (st.ci_95_low != null) t += ` (${pct(clamp01(st.ci_95_low))} to ${pct(clamp01(st.ci_95_high))})`;
    return t;
  }
  function statCell(st) {
    if (!st || st.mean == null) return h('td', { class: 'num muted', text: 'n/a' });
    const bits = [];
    if (st.ci_95_low != null) bits.push(`${pct(clamp01(st.ci_95_low))} to ${pct(clamp01(st.ci_95_high))}`);
    bits.push(`n = ${st.n}`);
    return h('td', { class: 'num nowrap' }, h('strong', { text: pct(st.mean) }), h('span', { class: 'sub', text: bits.join(', ') }));
  }
  const scenarioTitle = id => {
    const sc = state.suite && state.suite.scenarios.find(x => x.id === id);
    return sc ? sc.title : id;
  };
  const defenseLabel = id => DEFENSE_LABEL[id] || id;

  function roundClass(r) {
    if (!r.valid) return 'invalid';
    if (r.phase === 'benign') return r.oracle.benign_action_blocked ? 'benign-blocked' : 'benign-ok';
    const c = r.oracle.oracle_code || '';
    if (c === 'ATTACK_EXECUTED') return 'success';
    if (c.startsWith('ATTACK_BLOCKED')) return 'blocked';
    if (c === 'UNSAFE_ACTION_EXECUTED_OFF_OBJECTIVE') return 'offobj';
    return 'ignored';
  }
  function legend(keys) {
    return h('div', { class: 'legend', 'aria-label': 'Round colors' },
      keys.map(k => h('span', { class: 'legend-item' }, h('span', { class: `cell ${k}` }), CELL_LABEL[k])));
  }
  const pageHead = (title, sub) => h('div', { class: 'page-head' }, h('h1', { text: title }), sub ? h('p', { class: 'lede', text: sub }) : null);
  const emptyState = (title, body, actionLabel, action) =>
    h('div', { class: 'empty' }, h('h3', { text: title }), h('p', { text: body }),
      actionLabel ? h('button', { class: 'btn', type: 'button', onclick: action, text: actionLabel }) : null);

  // ------------------------------------------------------------------ chrome
  function updateBanner() {
    const el = $('#banner');
    const p = state.summary && state.summary.provenance;
    if (p && !p.demonstration_warning) { el.hidden = true; return; }
    el.hidden = false;
    let detail = p
      ? `Component mix for this run: ${p.component_mix}.`
      : 'The default components are a simulated target agent and a demonstration classifier.';
    if (state.summary && state.summary.campaigns) {
      const measured = state.summary.campaigns.filter(c => c.evidence_status === 'measured_result').length;
      detail += ` Evidence status: ${measured} of ${state.summary.campaigns.length} campaigns are eligible as research evidence.`;
    }
    el.replaceChildren(h('strong', { text: DEFAULT_WARNING }), ` ${detail}`);
  }
  function renderNav() {
    $('#nav').replaceChildren(...VIEWS.map(v => h('li', null,
      h('button', { class: 'nav-btn', type: 'button', 'aria-current': v.id === state.view ? 'page' : null, onclick: () => setView(v.id), text: v.label }))));
    const sel = $('#runSelect');
    sel.replaceChildren(
      h('option', { value: '', text: state.runs.length ? 'Choose a run' : 'No runs yet' }),
      ...state.runs.map(r => h('option', { value: r.run_id, text: `${r.run_id} (${r.status})`, selected: r.run_id === state.runId ? true : null })));
    sel.value = state.runId || '';
  }
  function setView(v) {
    state.view = v;
    if (location.hash.slice(1) !== v) history.replaceState(null, '', `#${v}`);
    render();
    $('#view').focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
  function render() {
    renderNav();
    const m = $('#view');
    m.replaceChildren();
    ({ configure: viewConfigure, live: viewLive, compare: viewCompare, audit: viewAudit, provenance: viewProvenance }[state.view])(m);
  }
  async function refreshRuns() {
    try { state.runs = await api('/api/experiments'); } catch (_) { state.runs = []; }
  }

  // ------------------------------------------------------------------ configure
  function checkbox(id, label, note, checked, onchange, disabled) {
    return h('label', { class: 'check', for: id },
      h('input', { type: 'checkbox', id, checked: checked ? true : null, disabled: disabled ? true : null, onchange }),
      h('span', null, h('span', { class: 'check-label', text: label }), note ? h('span', { class: 'check-note', text: note }) : null));
  }
  function parseSeeds(text) {
    const parts = text.split(',').map(x => x.trim()).filter(Boolean);
    const nums = parts.map(Number);
    if (!nums.length || nums.some(n => !Number.isInteger(n) || n < 0)) return null;
    return [...new Set(nums)];
  }
  function viewConfigure(m) {
    const c = state.cfg;
    m.append(pageHead('Configure an experiment', 'Choose what to attack, how to attack it, and which defenses to compare. Every defense faces the same attempt budget.'));
    if (state.initError) m.append(h('div', { class: 'notice-error', role: 'alert', text: state.initError }));

    // scenarios
    const scnSec = h('section', { class: 'form-section' }, h('h3', { text: 'Scenarios' }));
    if (state.suite) {
      scnSec.append(h('div', { class: 'inline-actions' },
        h('button', { class: 'btn-link', type: 'button', text: 'Select all', onclick: () => { c.scenarios = new Set(state.suite.scenarios.map(x => x.id)); render(); } }),
        h('button', { class: 'btn-link', type: 'button', text: 'Select none', onclick: () => { c.scenarios = new Set(); render(); } })));
      for (const env of ['email', 'documents', 'calendar']) {
        const list = state.suite.scenarios.filter(x => x.environment === env);
        if (!list.length) continue;
        scnSec.append(h('div', { class: 'subhead', text: env[0].toUpperCase() + env.slice(1) }),
          h('div', { class: 'check-grid' }, list.map(sc => checkbox(
            `scn-${sc.id}`, sc.title,
            `${sc.category.replace(/_/g, ' ')}, ${sc.difficulty}${sc.attackable ? '' : ', benign control only (no attack rounds)'}`,
            c.scenarios.has(sc.id), e => { e.target.checked ? c.scenarios.add(sc.id) : c.scenarios.delete(sc.id); updateEstimate(); }))));
      }
    }
    m.append(scnSec);

    // defenses
    m.append(h('section', { class: 'form-section' }, h('h3', { text: 'Defenses' }),
      h('div', { class: 'check-grid' }, DEFENSES.map(d => checkbox(`def-${d.id}`, d.label, d.note, c.defenses.has(d.id),
        e => { e.target.checked ? c.defenses.add(d.id) : c.defenses.delete(d.id); updateEstimate(); })))));

    // attackers
    const FAILURE_POLICIES = [
      ['mark_invalid', 'Mark invalid (default)', "Exclude the failed attempt from every metric. Never continues the same campaign with a substitute attacker."],
      ['abort_campaign', 'Abort the campaign', 'Stop this campaign at the point of failure. Rounds already completed are kept; the rest are recorded as never attempted.'],
      ['restart_as_separate_demo_campaign', 'Restart as a separate demo campaign', 'Abort this campaign the same way, and also start a brand new, separately labeled campaign using the deterministic demo attacker instead. Never combined with the aborted campaign.'],
    ];
    const ollama = h('div', { class: 'field', hidden: c.modes.has('adaptive_ollama') ? null : true, id: 'ollamaFields' },
      h('label', { for: 'ollamaModel', text: 'Ollama model name' }),
      h('input', { class: 'input', id: 'ollamaModel', value: c.ollamaModel, placeholder: 'for example, a locally pulled model', oninput: e => { c.ollamaModel = e.target.value; } }),
      checkbox('ollamaAbl', 'This model is abliterated', 'Recorded in the run manifest so abliterated and standard models can be compared.', c.ollamaAbliterated, e => { c.ollamaAbliterated = e.target.checked; }),
      h('p', { class: 'help', text: 'Requires Ollama listening on 127.0.0.1. Only allowlisted local hosts can be reached.' }),
      h('div', { class: 'field' }, h('label', { for: 'modelFailurePolicy', text: 'If the model becomes unavailable mid-campaign' }),
        h('select', { class: 'select', id: 'modelFailurePolicy', style: 'max-width:420px', onchange: e => { c.modelFailurePolicy = e.target.value; } },
          ...FAILURE_POLICIES.map(([id, label]) => h('option', { value: id, text: label, selected: c.modelFailurePolicy === id ? true : null }))),
        h('p', { class: 'help', text: (FAILURE_POLICIES.find(([id]) => id === c.modelFailurePolicy) || [])[2] || '' })));
    m.append(h('section', { class: 'form-section' }, h('h3', { text: 'Attackers' }),
      h('div', { class: 'check-grid' }, ATTACKERS.map(a => checkbox(`mode-${a.id}`, a.label, a.note, c.modes.has(a.id), e => {
        e.target.checked ? c.modes.add(a.id) : c.modes.delete(a.id);
        $('#ollamaFields').hidden = !c.modes.has('adaptive_ollama');
        updateEstimate();
      }))), ollama));

    // target
    const realFields = h('div', { id: 'realFields', hidden: c.target === 'real_model' ? null : true },
      h('div', { class: 'field' }, h('label', { for: 'realModel', text: 'Target model name' }),
        h('input', { class: 'input', id: 'realModel', value: c.realModel, oninput: e => { c.realModel = e.target.value; } })),
      h('p', { class: 'help', text: 'Uses the same Ollama-style endpoint on 127.0.0.1. Results are labeled as real model output.' }));
    m.append(h('section', { class: 'form-section' }, h('h3', { text: 'Target agent' }),
      h('div', { class: 'seg', role: 'group', 'aria-label': 'Target agent' }, [['simulated', 'Simulated'], ['real_model', 'Real model']].map(([id, label]) =>
        h('button', { class: 'seg-btn', type: 'button', 'aria-pressed': String(c.target === id), text: label, onclick: () => { c.target = id; render(); } }))),
      h('p', { class: 'help', text: c.target === 'simulated'
        ? 'A deterministic stand-in calibrated to the six built-in payload styles. Runs in milliseconds and is always labeled as a simulation.'
        : 'A real tool-calling model. Slower, and results are only as reproducible as the model settings recorded in the manifest.' }),
      realFields));

    // budget and seeds
    m.append(h('section', { class: 'form-section' }, h('h3', { text: 'Budget and repetitions' }),
      h('div', { class: 'controls' },
        h('div', { class: 'field' }, h('label', { for: 'budget', text: 'Attack attempts per campaign' }),
          h('input', { class: 'input input-narrow', id: 'budget', type: 'number', min: '1', max: '500', value: String(c.budget), oninput: e => { c.budget = Number(e.target.value); updateEstimate(); } })),
        h('div', { class: 'field' }, h('label', { for: 'seeds', text: 'Seeds, comma separated' }),
          h('input', { class: 'input', id: 'seeds', value: c.seeds, oninput: e => { c.seeds = e.target.value; updateEstimate(); } }))),
      h('p', { class: 'help', text: 'Each seed is one independent repetition. Confidence intervals need at least three seeds; with fewer, only means are shown.' })));

    m.append(h('div', { id: 'formError' }), h('p', { id: 'estimate', class: 'muted' }),
      h('button', { class: 'btn btn-primary', type: 'button', id: 'runBtn', text: 'Run experiment', onclick: startRun }));
    updateEstimate();
    if (state.formError) showFormError(state.formError);
  }
  function showFormError(msg) {
    state.formError = msg;
    const el = $('#formError');
    if (el) el.replaceChildren(msg ? h('div', { class: 'notice-error', role: 'alert', text: msg }) : '');
  }
  function updateEstimate() {
    const el = $('#estimate');
    if (!el || !state.suite) return;
    const c = state.cfg, seeds = parseSeeds(c.seeds) || [];
    const chosen = state.suite.scenarios.filter(x => c.scenarios.has(x.id));
    const campaigns = chosen.length * c.defenses.size * c.modes.size * seeds.length;
    const attackRounds = chosen.filter(x => x.attackable).length * c.defenses.size * c.modes.size * seeds.length * (c.budget || 0);
    el.textContent = `This will run ${campaigns} campaigns and about ${attackRounds.toLocaleString()} attack rounds.`;
  }
  async function startRun() {
    const c = state.cfg;
    const seeds = parseSeeds(c.seeds);
    let problem = null;
    if (!state.suite) problem = 'The scenario suite has not loaded. Check that the server is running and reload.';
    else if (!c.scenarios.size) problem = 'Select at least one scenario.';
    else if (!c.defenses.size) problem = 'Select at least one defense.';
    else if (!c.modes.size) problem = 'Select at least one attacker.';
    else if (!seeds) problem = 'Seeds must be whole numbers separated by commas, for example 1,2,3.';
    else if (seeds.length !== c.seeds.split(',').filter(x => x.trim()).length) problem = 'Each seed can be used only once. Duplicate seeds would count the same run twice.';
    else if (!(c.budget >= 1 && c.budget <= 500)) problem = 'Attack attempts must be between 1 and 500.';
    else if (c.modes.has('adaptive_ollama') && !c.ollamaModel.trim()) problem = 'Enter an Ollama model name for the adaptive local model attacker.';
    else if (c.target === 'real_model' && !c.realModel.trim()) problem = 'Enter a target model name, or switch the target agent to Simulated.';
    if (problem) { showFormError(problem); return; }
    showFormError(null);

    const body = {
      defenses: DEFENSES.map(d => d.id).filter(id => c.defenses.has(id)),
      attack_modes: ATTACKERS.map(a => a.id).filter(id => c.modes.has(id)),
      attack_budget: c.budget, seeds, target_mode: c.target,
      scenario_ids: state.suite.scenarios.map(x => x.id).filter(id => c.scenarios.has(id)),
    };
    if (c.modes.has('adaptive_ollama')) { body.model_config = { name: c.ollamaModel.trim(), abliterated: c.ollamaAbliterated }; body.model_failure_policy = c.modelFailurePolicy; }
    if (c.target === 'real_model') body.real_target_config = { name: c.realModel.trim() };
    $('#runBtn').disabled = true;
    try {
      const r = await api('/api/experiments', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      await refreshRuns();
      selectRun(r.run_id, 'live');
    } catch (e) {
      showFormError(e.message);
      const btn = $('#runBtn'); if (btn) btn.disabled = false;
    }
  }

  // ------------------------------------------------------------------ run lifecycle and live view
  const newLive = runId => ({ runId, since: 0, campaigns: new Map(), order: [], total: null, doneCount: 0, status: 'running', done: false, error: null, polling: false });
  function selectRun(id, view) {
    state.runId = id || null;
    state.summary = null; state.stats = null;
    state.cmp = { mode: null, scenario: '__all__' };
    state.audit = { campaignId: null, detail: null, round: null, loading: false, error: null };
    state.live = id ? newLive(id) : null;
    updateBanner();
    if (view) setView(view); else render();
    if (id) pollLive();
  }
  function ingest(live, events) {
    for (const e of events) {
      if (e.type === 'campaign_start') {
        live.campaigns.set(e.campaign_id, { ...e, rounds: [], done: false });
        live.order.push(e.campaign_id);
      } else if (e.type === 'round') {
        let c = live.campaigns.get(e.campaign_id);
        if (!c) { c = { campaign_id: e.campaign_id, rounds: [], done: false, defense_id: e.defense_id }; live.campaigns.set(e.campaign_id, c); live.order.push(e.campaign_id); }
        c.rounds.push({ phase: e.phase, valid: e.valid, success: !!e.success, cls: roundClass({ valid: e.valid, phase: e.phase, oracle: { oracle_code: e.oracle_code, benign_action_blocked: e.blocked } }), n: e.round_number });
      } else if (e.type === 'campaign_complete') {
        const c = live.campaigns.get(e.campaign_id);
        if (c) c.done = true;
        live.doneCount += 1;
      }
    }
  }
  async function pollLive() {
    const live = state.live;
    if (!live || live.polling) return;
    live.polling = true;
    try {
      while (state.live === live && !live.done) {
        if (live.total == null) {
          const st = await api(`/api/experiments/${live.runId}/status`);
          live.total = st.campaigns_total; live.status = st.status; live.error = st.error;
        }
        const d = await api(`/api/experiments/${live.runId}/events?since=${live.since}&types=round,campaign_start,campaign_complete`);
        live.since = d.next_since; ingest(live, d.events);
        if (d.status !== 'running') {
          const tail = await api(`/api/experiments/${live.runId}/events?since=${live.since}&types=round,campaign_start,campaign_complete`);
          live.since = tail.next_since; ingest(live, tail.events);
          const st = await api(`/api/experiments/${live.runId}/status`);
          live.status = st.status; live.error = st.error; live.total = st.campaigns_total; live.done = true;
          if (live.status === 'complete' || live.status === 'cancelled') {
            state.summary = await api(`/api/experiments/${live.runId}/summary`);
            state.stats = await api(`/api/experiments/${live.runId}/stats`);
            updateBanner();
          }
          await refreshRuns();
        }
        if (state.view === 'live') updateLive();
        if (!live.done) await sleep(500);
      }
    } catch (e) {
      live.error = e.message; live.done = true; live.status = 'error';
    } finally {
      live.polling = false;
      if (state.live === live) {
        if (state.view === 'live') { renderNav(); updateLive(); } else render();
      }
    }
  }
  function viewLive(m) {
    m.append(pageHead('Live run', 'Each square is one round. Attack rounds come first, then the benign control rounds after a small gap.'));
    if (!state.live) {
      m.append(emptyState('No run selected', 'Start a run from Configure, or choose an earlier run from the list on the left.', 'Go to Configure', () => setView('configure')));
      return;
    }
    m.append(h('div', { id: 'liveBody' }));
    updateLive();
  }
  function updateLive() {
    const body = $('#liveBody'), live = state.live;
    if (!body || !live) return;
    const total = live.total, done = live.doneCount;
    const frac = total ? Math.min(1, done / total) : 0;
    let status;
    if (live.status === 'error') status = `The run failed: ${live.error || 'unknown error'}`;
    else if (live.status === 'cancelled') status = `Run stopped. ${done} campaigns finished before the stop.`;
    else if (live.status === 'complete') status = `Run complete. ${done} campaigns finished.`;
    else status = `Running. ${done} of ${total == null ? '?' : total} campaigns finished.`;

    const actions = h('div', { class: 'controls' });
    if (live.status === 'running') actions.append(h('button', { class: 'btn btn-danger', type: 'button', text: 'Stop run', onclick: async () => { try { await api(`/api/experiments/${live.runId}/cancel`, { method: 'POST' }); } catch (_) { /* run already ended */ } } }));
    if (state.summary) actions.append(h('button', { class: 'btn btn-primary', type: 'button', text: 'View comparison', onclick: () => setView('compare') }));

    const ids = [...live.order].reverse().slice(0, 60);
    const rows = ids.map(id => {
      const c = live.campaigns.get(id);
      const attack = c.rounds.filter(r => r.phase === 'attack' && r.valid);
      const worked = attack.filter(r => r.success).length;
      let firstBenign = true;
      const cells = c.rounds.map(r => {
        const cell = h('span', { class: `cell ${r.cls}`, title: `Round ${r.n}: ${CELL_LABEL[r.cls]}` });
        if (r.phase === 'benign' && firstBenign) { firstBenign = false; return [h('span', { class: 'cell gap' }), cell]; }
        return cell;
      });
      return h('tr', null,
        h('td', { text: scenarioTitle(c.scenario_id) }),
        h('td', { text: MODE_LABEL[c.attack_mode] || c.attack_mode || '' }),
        h('td', null, h('span', { class: 'defense-name' }, h('span', { class: 'dot', style: `background:${DEFENSE_COLOR[c.defense_id] || '#999'}` }), defenseLabel(c.defense_id))),
        h('td', { class: 'num', text: c.seed != null ? String(c.seed) : '' }),
        h('td', null, h('div', { class: 'strip' }, cells)),
        h('td', { class: 'num', text: c.done ? (c.attack_budget === 0 ? 'benign only' : `${worked} of ${attack.length}`) : 'running' }));
    });
    body.replaceChildren(
      h('p', { class: 'status-line', role: 'status', text: status }),
      h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.round(frac * 100)) },
        h('div', { class: 'progress-bar', style: `width:${frac * 100}%` })),
      actions,
      legend(['success', 'blocked', 'ignored', 'offobj', 'benign-ok', 'benign-blocked', 'invalid']),
      rows.length
        ? h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, ['Scenario', 'Attacker', 'Defense', 'Seed', 'Rounds', 'Attacks that worked'].map((t, i) => h('th', { class: i === 3 || i === 5 ? 'num' : null, text: t })))),
          h('tbody', null, rows)))
        : h('p', { class: 'muted', text: 'Waiting for the first campaign to start.' }),
      live.order.length > 60 ? h('p', { class: 'small muted', text: `Showing the 60 most recent of ${live.order.length} campaigns.` }) : null);
  }

  // ------------------------------------------------------------------ charts
  function tradeoffChart(points) {
    const W = 700, H = 440, L = 72, R = 36, T = 26, B = 66;
    const xs = v => L + v * (W - L - R), ys = v => T + (1 - v) * (H - T - B);
    const svg = s('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img',
      'aria-label': 'Scatter plot. Horizontal axis: share of legitimate tasks completed. Vertical axis: share of attacks stopped. Up and to the right is better.' });
    svg.append(s('rect', { x: xs(0.75), y: ys(1), width: xs(1) - xs(0.75), height: ys(0.75) - ys(1), fill: '#E6F1EE' }),
      s('text', { x: xs(1), y: T - 9, 'text-anchor': 'end', text: 'Shaded corner: secure and usable' }));
    for (const t of [0, 0.25, 0.5, 0.75, 1]) {
      svg.append(s('line', { x1: L, x2: W - R, y1: ys(t), y2: ys(t), stroke: '#D2D9E0' }),
        s('line', { x1: xs(t), x2: xs(t), y1: T, y2: H - B, stroke: '#D2D9E0' }),
        s('text', { x: L - 10, y: ys(t) + 4, 'text-anchor': 'end', text: pct(t) }),
        s('text', { x: xs(t), y: H - B + 18, 'text-anchor': 'middle', text: pct(t) }));
    }
    svg.append(s('text', { class: 'axis-title', x: (L + W - R) / 2, y: H - 14, 'text-anchor': 'middle', text: 'Legitimate tasks completed' }),
      s('text', { class: 'axis-title', transform: `translate(18 ${(T + H - B) / 2}) rotate(-90)`, 'text-anchor': 'middle', text: 'Attacks stopped' }));
    for (const p of points.filter(q => q.faint)) {
      svg.append(s('circle', { cx: xs(p.x), cy: ys(p.y), r: 3.5, fill: DEFENSE_COLOR[p.defense_id], opacity: 0.32 }, s('title', { text: `${p.label}: ${scenarioTitle(p.scenario_id)}` })));
    }
    const placed = [];
    for (const p of points.filter(q => !q.faint)) {
      const col = DEFENSE_COLOR[p.defense_id];
      if (p.xlo != null) svg.append(s('line', { x1: xs(clamp01(p.xlo)), x2: xs(clamp01(p.xhi)), y1: ys(p.y), y2: ys(p.y), stroke: col, opacity: 0.55, 'stroke-width': 2 }));
      if (p.ylo != null) svg.append(s('line', { x1: xs(p.x), x2: xs(p.x), y1: ys(clamp01(p.ylo)), y2: ys(clamp01(p.yhi)), stroke: col, opacity: 0.55, 'stroke-width': 2 }));
      svg.append(s('circle', { cx: xs(p.x), cy: ys(p.y), r: 8, fill: col, stroke: '#fff', 'stroke-width': 2 },
        s('title', { text: `${p.label}: ${pct(p.y)} of attacks stopped, ${pct(p.x)} of legitimate tasks completed` })));
      let ly = ys(p.y) + 4;
      const lx = xs(p.x) + 14;
      for (const q of placed) if (Math.abs(q.ly - ly) < 15 && Math.abs(q.lx - lx) < 140) ly = q.ly + 16;
      placed.push({ lx, ly });
      const anchorEnd = lx > W - 150;
      svg.append(s('text', { class: 'point-label', x: anchorEnd ? xs(p.x) - 14 : lx, y: ly, 'text-anchor': anchorEnd ? 'end' : 'start', text: p.label }));
    }
    return svg;
  }
  function adaptationChart(series, maxN) {
    const W = 700, H = 300, L = 72, R = 150, T = 18, B = 52;
    const xs = n => L + ((n - 1) / Math.max(1, maxN - 1)) * (W - L - R), ys = v => T + (1 - v) * (H - T - B);
    const svg = s('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Line chart of cumulative attack success rate by attempt number, one line per defense.' });
    for (const t of [0, 0.25, 0.5, 0.75, 1]) {
      svg.append(s('line', { x1: L, x2: W - R, y1: ys(t), y2: ys(t), stroke: '#D2D9E0' }), s('text', { x: L - 10, y: ys(t) + 4, 'text-anchor': 'end', text: pct(t) }));
    }
    const step = maxN <= 12 ? 1 : Math.ceil(maxN / 8);
    for (let n = 1; n <= maxN; n += step) svg.append(s('text', { x: xs(n), y: H - B + 18, 'text-anchor': 'middle', text: String(n) }));
    svg.append(s('text', { class: 'axis-title', x: (L + W - R) / 2, y: H - 10, 'text-anchor': 'middle', text: 'Attempt number' }),
      s('text', { class: 'axis-title', transform: `translate(18 ${(T + H - B) / 2}) rotate(-90)`, 'text-anchor': 'middle', text: 'Cumulative attack success' }));
    const ends = [];
    for (const ser of series) {
      if (!ser.values.length) continue;
      const col = DEFENSE_COLOR[ser.defense_id];
      svg.append(s('polyline', { fill: 'none', stroke: col, 'stroke-width': 2.5, points: ser.values.map((v, i) => `${xs(i + 1)},${ys(v)}`).join(' ') }));
      let ly = ys(ser.values[ser.values.length - 1]) + 4;
      for (const y of ends) if (Math.abs(y - ly) < 14) ly = y + 15;
      ends.push(ly);
      svg.append(s('text', { class: 'point-label', x: xs(ser.values.length) + 8, y: ly, text: defenseLabel(ser.defense_id) }));
    }
    return svg;
  }

  // ------------------------------------------------------------------ compare
  function viewCompare(m) {
    m.append(pageHead('Compare defenses', 'Attack success and legitimate-task completion, side by side, at matched attempt budgets.'));
    if (!state.runId) { m.append(emptyState('No run selected', 'Run an experiment first, or choose an earlier run from the list on the left.', 'Go to Configure', () => setView('configure'))); return; }
    if (!state.summary || !state.stats) { m.append(emptyState('Results are not ready', 'The comparison appears when the run finishes.', 'Watch the run', () => setView('live'))); return; }
    const man = state.summary.manifest, cmp = state.cmp;
    const modes = man.attack_modes;
    if (!cmp.mode || !modes.includes(cmp.mode)) cmp.mode = modes[0];
    if (cmp.scenario !== '__all__' && !man.scenario_ids.includes(cmp.scenario)) cmp.scenario = '__all__';

    m.append(h('div', { class: 'controls' },
      h('div', null, h('span', { class: 'field-title', text: 'Attacker' }),
        h('div', { class: 'seg', role: 'group', 'aria-label': 'Attacker' }, modes.map(md => h('button', { class: 'seg-btn', type: 'button', 'aria-pressed': String(cmp.mode === md), text: MODE_LABEL[md] || md, onclick: () => { cmp.mode = md; render(); } })))),
      h('div', null, h('label', { class: 'field-title', for: 'cmpScenario', text: 'Scenario' }),
        h('select', { class: 'select', id: 'cmpScenario', onchange: e => { cmp.scenario = e.target.value; render(); } },
          h('option', { value: '__all__', text: 'All scenarios, pooled', selected: cmp.scenario === '__all__' ? true : null }),
          ...man.scenario_ids.map(id => h('option', { value: id, text: scenarioTitle(id), selected: cmp.scenario === id ? true : null }))))));

    const defs = man.defenses;
    const statsFor = did => {
      const row = cmp.scenario === '__all__'
        ? state.stats.pooled.find(r => r.attack_mode === cmp.mode && r.defense_id === did)
        : state.stats.per_scenario.find(r => r.scenario_id === cmp.scenario && r.attack_mode === cmp.mode && r.defense_id === did);
      return row ? row.stats : {};
    };
    const campaigns = state.summary.campaigns.filter(c => !c.is_demo_fallback && c.attack_mode === cmp.mode && (cmp.scenario === '__all__' || c.scenario_id === cmp.scenario));

    // trade-off chart
    const points = [];
    for (const did of defs) {
      const st = statsFor(did), a = st.campaign_average_asr, l = st.legitimate_task_completion_rate;
      if (!a || !l || a.mean == null || l.mean == null) continue;
      points.push({ defense_id: did, label: defenseLabel(did), x: l.mean, y: 1 - a.mean,
        xlo: l.ci_95_low, xhi: l.ci_95_high, ylo: a.ci_95_high != null ? 1 - a.ci_95_high : null, yhi: a.ci_95_low != null ? 1 - a.ci_95_low : null });
      if (cmp.scenario === '__all__') {
        for (const r of state.stats.per_scenario.filter(q => q.attack_mode === cmp.mode && q.defense_id === did)) {
          const ra = r.stats.campaign_average_asr, rl = r.stats.legitimate_task_completion_rate;
          if (ra && rl && ra.mean != null && rl.mean != null) points.push({ faint: true, defense_id: did, label: defenseLabel(did), scenario_id: r.scenario_id, x: rl.mean, y: 1 - ra.mean });
        }
      }
    }
    m.append(h('h2', { text: 'Security against usability' }));
    if (points.some(p => !p.faint)) {
      m.append(tradeoffChart(points),
        h('p', { class: 'chart-caption', text: 'Each large point is one defense; up and to the right is better. Whiskers are 95% intervals when at least three seeds ran. Faint points are individual scenarios. Attacks stopped is one minus the attack success rate.' }));
    } else {
      m.append(h('p', { class: 'muted', text: 'This selection has no attack rounds, so there is no security measurement to plot. The benign block rate in the table below still applies.' }));
    }

    // table
    const cols = [
      ['Attack success', 'campaign_average_asr', 'Share of valid attack rounds where the attacker reached its goal, averaged over the whole campaign.'],
      ['Final-window success', 'final_window_asr', 'Attack success over the last 20% of rounds (at least 3), a measure of what the attacker learned.'],
      ['Legitimate task completed', 'legitimate_task_completion_rate', 'Share of rounds where the user task still finished correctly.'],
      ['Safe utility', 'safe_utility_rate', 'Share of rounds where the task finished and no unauthorized action ran.'],
      ['Benign block rate (false positives)', 'benign_block_rate', 'Share of harmless control rounds that a defense wrongly interfered with.'],
      ['Unauthorized: attempted', 'unauthorized_action_attempted_rate', 'Share of valid attack rounds where the target proposed an unauthorized write at all, whether or not it ran.'],
      ['Unauthorized: blocked', 'unauthorized_action_blocked_rate', 'Of those attempts, the share the defense actually stopped before it took effect.'],
      ['Unauthorized: executed', 'unauthorized_action_executed_rate', 'Of those attempts, the share that changed the environment anyway. This is the one that matters most for security, and it can never exceed "attempted".'],
    ];
    const latencyCol = ['Defense latency', 'mean_defense_latency_ms', 'Average milliseconds the defense hook added per tool call.'];
    const first = did => {
      const cs = campaigns.filter(c => c.defense_id === did && c.metrics.attempts_to_first_success != null).map(c => c.metrics.attempts_to_first_success).sort((a, b) => a - b);
      const all = campaigns.filter(c => c.metrics.attack_rounds_valid > 0).length;
      if (!all) return 'n/a';
      if (!cs.length) return `Never reached (0 of ${all} campaigns)`;
      const med = cs[Math.floor((cs.length - 1) / 2)];
      return `${cs.length} of ${all} campaigns reached it, median at attempt ${med}`;
    };
    // Attempted vs. blocked vs. executed, grouped per defense so the three can never be read as one number
    function unauthorizedBar(defs) {
      const W = 700, barH = 26, gap = 14, L = 190, R = 60, T = 10;
      const H = T + defs.length * (barH + gap) + 34;
      const xs = v => L + v * (W - L - R);
      const svg = s('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img',
        'aria-label': 'Bar chart of unauthorized-action rate per defense, split into attempted, blocked and executed segments.' });
      for (const t of [0, 0.25, 0.5, 0.75, 1]) svg.append(s('line', { x1: xs(t), x2: xs(t), y1: T, y2: H - 24, stroke: '#E2E7EC' }),
        s('text', { x: xs(t), y: H - 8, 'text-anchor': 'middle', text: pct(t) }));
      defs.forEach((did, i) => {
        const st = statsFor(did), y = T + i * (barH + gap);
        const att = st.unauthorized_action_attempted_rate && st.unauthorized_action_attempted_rate.mean;
        const blk = st.unauthorized_action_blocked_rate && st.unauthorized_action_blocked_rate.mean;
        const exe = st.unauthorized_action_executed_rate && st.unauthorized_action_executed_rate.mean;
        svg.append(s('text', { x: L - 10, y: y + barH / 2 + 4, 'text-anchor': 'end', text: defenseLabel(did) }));
        if (att == null) { svg.append(s('text', { x: L, y: y + barH / 2 + 4, text: 'no attack rounds' })); return; }
        svg.append(s('rect', { x: L, y, width: xs(att) - L, height: barH, fill: '#F3D7A8' }),  // full bar = attempted
          s('rect', { x: L, y, width: xs(exe) - L, height: barH, fill: DEFENSE_COLOR[did] }),   // overlaid = executed (the dangerous share)
          s('rect', { x: xs(exe), y, width: xs(att) - xs(exe), height: barH, fill: '#B7D9C7' }), // remainder = blocked
          s('title', { text: `${defenseLabel(did)}: ${pct(att)} attempted, ${pct(blk)} blocked, ${pct(exe)} executed` }));
      });
      return svg;
    }
    const anyUnauthorized = defs.some(did => { const v = statsFor(did).unauthorized_action_attempted_rate; return v && v.mean != null; });
    if (anyUnauthorized) {
      m.append(h('h2', { text: 'Unauthorized actions: attempted, blocked, executed' }), unauthorizedBar(defs),
        h('div', { class: 'legend' },
          h('span', { class: 'legend-item' }, h('span', { class: 'cell', style: 'background:#F3D7A8' }), 'Attempted (full bar)'),
          h('span', { class: 'legend-item' }, h('span', { class: 'cell', style: 'background:#B7D9C7' }), 'Blocked'),
          h('span', { class: 'legend-item' }, h('span', { class: 'cell', style: 'background:#6B7785' }), 'Executed (the dangerous share)')),
        h('p', { class: 'chart-caption', text: 'Each bar is the same "attempted" length; the colored-in portion is what actually executed, so a defense can never look better than it is by hiding executed actions inside a shorter bar.' }));
    }

    m.append(h('h2', { text: 'All measurements' }),
      h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { text: 'Defense' }), cols.map(([t, , tip]) => h('th', { class: 'num', title: tip, text: t })),
          h('th', { class: 'num', title: latencyCol[2], text: latencyCol[0] }),
          h('th', { class: 'num', title: 'Estimated model or inference cost. Simulated and deterministic components have no real cost, so this reads n/a rather than a fabricated number.', text: 'Cost' }),
          h('th', { text: 'First success' }))),
        h('tbody', null, defs.map(did => {
          const st = statsFor(did);
          const lat = st[latencyCol[1]];
          const forDef = campaigns.filter(c => c.defense_id === did);
          const costs = forDef.map(c => c.cost && c.cost.total_estimated_cost).filter(v => v != null);
          const currency = (forDef.map(c => c.cost && c.cost.currency).find(v => v) ) || null;
          const costText = costs.length
            ? (costs.every(v => v === 0) ? `${currency || '$'}0 (simulated)` : `${currency || '$'}${(costs.reduce((a,b)=>a+b,0) / costs.length).toFixed(4)} avg`)
            : 'n/a';
          return h('tr', null,
            h('td', null, h('span', { class: 'defense-name' }, h('span', { class: 'dot', style: `background:${DEFENSE_COLOR[did]}` }), defenseLabel(did))),
            cols.map(([, key]) => statCell(st[key])),
            h('td', { class: 'num' }, lat && lat.mean != null ? `${lat.mean.toFixed(2)} ms` : 'n/a'),
            h('td', { class: 'num muted', text: costText }),
            h('td', { class: 'small first-col', text: first(did) }));
        })))),
      h('p', { class: 'chart-caption', text: 'n is the number of independent campaigns, meaning one seeded run each. Rounds inside a campaign are never treated as independent. Intervals default to a percentile bootstrap, which cannot leave a rate\'s true range because it only ever averages values that were themselves in range, and are omitted below three campaigns — the per-campaign row instead shows a bounded Wilson interval over that campaign\'s own rounds, a descriptive supplement rather than a between-campaign interval. Each interval names its method. '
        + (cmp.scenario === '__all__' ? 'In the pooled view each scenario and seed counts once, so intervals include the spread between scenarios.' : 'Here the spread comes from seeds only.') }));

    // adaptation curve
    const series = defs.map(did => {
      const curves = campaigns.filter(c => c.defense_id === did).map(c => c.metrics.adaptation_curve.map(p => p.cumulative_asr));
      const len = Math.max(0, ...curves.map(x => x.length));
      const values = [];
      for (let i = 0; i < len; i++) { const at = curves.filter(x => x.length > i).map(x => x[i]); values.push(at.reduce((a, b) => a + b, 0) / at.length); }
      return { defense_id: did, values };
    });
    const maxN = Math.max(0, ...series.map(x => x.values.length));
    if (maxN > 1) {
      m.append(h('h2', { text: 'How attack success builds over attempts' }), adaptationChart(series, maxN),
        h('p', { class: 'chart-caption', text: 'Cumulative attack success after each attempt, averaged over campaigns. An adaptive attacker that learns should pull away from the static set as attempts accumulate.' }));
    }

    // static vs adaptive
    if (modes.includes('static') && modes.length > 1) {
      const all = state.stats.static_vs_adaptive;
      const DIRECTION = { adaptive_higher: 'Adaptive attacker did better', static_higher: 'Static set did better', null_or_undetermined: 'No detectable difference', descriptive_only: 'Too few seeds for an interval' };
      const signed = v => (v == null ? 'n/a' : `${v >= 0 ? '+' : ''}${(v * 100).toFixed(1)} points`);
      const defCell = did => h('td', null, h('span', { class: 'defense-name' }, h('span', { class: 'dot', style: `background:${DEFENSE_COLOR[did]}` }), defenseLabel(did)));
      let table = null;
      if (cmp.scenario === '__all__') {
        const rows = defs.map(did => {
          const rs = all.filter(r => r.defense_id === did), usable = rs.filter(r => r.mean != null);
          return { did, total: rs.length, mean: usable.length ? usable.reduce((acc, r) => acc + r.mean, 0) / usable.length : null,
            adaptive: rs.filter(r => r.direction === 'adaptive_higher').length, staticBetter: rs.filter(r => r.direction === 'static_higher').length };
        }).filter(r => r.total);
        if (rows.length) table = h('table', null,
          h('thead', null, h('tr', null, ['Defense', 'Average difference', 'Adaptive did better', 'Static did better', 'No detectable difference'].map((t, i) => h('th', { class: i ? 'num' : null, text: t })))),
          h('tbody', null, rows.map(r => h('tr', null, defCell(r.did), h('td', { class: 'num', text: signed(r.mean) }),
            h('td', { class: 'num', text: `${r.adaptive} of ${r.total} scenarios` }), h('td', { class: 'num', text: `${r.staticBetter} of ${r.total} scenarios` }),
            h('td', { class: 'num', text: `${r.total - r.adaptive - r.staticBetter} of ${r.total} scenarios` })))));
      } else {
        const rows = all.filter(r => r.scenario_id === cmp.scenario);
        if (rows.length) table = h('table', null,
          h('thead', null, h('tr', null, ['Defense', 'Mean difference', 'Seeds', 'Reading'].map((t, i) => h('th', { class: i === 1 || i === 2 ? 'num' : null, text: t })))),
          h('tbody', null, rows.map(r => h('tr', null, defCell(r.defense_id), h('td', { class: 'num', text: signed(r.mean) }),
            h('td', { class: 'num', text: String(r.n) }), h('td', { text: DIRECTION[r.direction] || r.direction })))));
      }
      if (table) m.append(h('h2', { text: 'Does adaptation help the attacker?' }),
        h('p', { class: 'lede', text: 'Adaptive minus static attack success, paired by seed at the same attempt budget. Each scenario is judged separately from its own seeds, and a null result is reported as a null result.' }),
        h('div', { class: 'table-wrap' }, table));
    }
  }

  // ------------------------------------------------------------------ audit
  async function loadCampaign(id) {
    const a = state.audit;
    a.campaignId = id; a.detail = null; a.round = null; a.loading = true; a.error = null;
    if (state.view === 'audit') render();
    try {
      a.detail = await api(`/api/experiments/${state.runId}/campaigns/${encodeURIComponent(id)}`);
      a.round = a.detail.rounds.length ? 0 : null;
    } catch (e) { a.error = e.message; }
    a.loading = false;
    if (state.view === 'audit') render();
  }
  function viewAudit(m) {
    m.append(pageHead('Audit a campaign', 'Open any campaign, pick a round, and see exactly what the attacker sent, what the agent did, and what each defense decided.'));
    if (!state.runId) { m.append(emptyState('No run selected', 'Run an experiment first, or choose an earlier run from the list on the left.', 'Go to Configure', () => setView('configure'))); return; }
    if (!state.summary) { m.append(emptyState('Results are not ready', 'Campaigns can be audited when the run finishes.', 'Watch the run', () => setView('live'))); return; }
    const a = state.audit, camps = state.summary.campaigns;
    if (!a.campaignId && camps.length && !a.loading) {
      const pick = camps.find(c => c.metrics.attack_rounds_valid > 0 && c.defense_id !== 'baseline') || camps[0];
      loadCampaign(pick.campaign_id);
    }
    const byScenario = new Map();
    for (const c of camps) { if (!byScenario.has(c.scenario_id)) byScenario.set(c.scenario_id, []); byScenario.get(c.scenario_id).push(c); }
    m.append(h('div', { class: 'field' }, h('label', { for: 'auditPick', text: 'Campaign' }),
      h('select', { class: 'select', id: 'auditPick', style: 'max-width:560px', onchange: e => loadCampaign(e.target.value) },
        ...[...byScenario].map(([sid, list]) => h('optgroup', { label: scenarioTitle(sid) },
          ...list.map(c => h('option', { value: c.campaign_id, selected: c.campaign_id === a.campaignId ? true : null, text: `${defenseLabel(c.defense_id)}, ${MODE_LABEL[c.attack_mode] || c.attack_mode}, seed ${c.seed}` })))))));
    if (a.loading) { m.append(h('p', { class: 'muted', text: 'Loading campaign.' })); return; }
    if (a.error) { m.append(h('div', { class: 'notice-error', role: 'alert', text: a.error })); return; }
    if (!a.detail) return;

    const d = a.detail, mt = d.metrics;
    m.append(h('dl', { class: 'kv' },
      h('dt', { text: 'Defense' }), h('dd', { text: `${defenseLabel(d.defense_id)} (${d.defense.intervention_point.replace(/_/g, ' ')}, ${d.defense.provenance})` }),
      h('dt', { text: 'Attacker' }), h('dd', { text: `${MODE_LABEL[d.attack_mode] || d.attack_mode} (${d.attacker_stats.provenance})` }),
      h('dt', { text: 'Attack success' }), h('dd', { text: `${pct(mt.campaign_average_asr)} over ${mt.attack_rounds_valid} valid attack rounds` }),
      h('dt', { text: 'Legitimate task completed' }), h('dd', { text: pct(mt.legitimate_task_completion_rate) }),
      h('dt', { text: 'First success' }), h('dd', { text: mt.attempts_to_first_success == null ? 'Never reached in this campaign' : `Attempt ${mt.attempts_to_first_success}` })));
    m.append(h('h2', { text: 'Rounds' }), legend(['success', 'blocked', 'ignored', 'offobj', 'benign-ok', 'benign-blocked', 'invalid']));
    let firstBenign = true;
    m.append(h('div', { class: 'strip', role: 'group', 'aria-label': 'Rounds in this campaign' }, d.rounds.map((r, i) => {
      const cls = roundClass(r);
      const btn = h('button', { class: `cell ${cls}`, type: 'button', 'aria-pressed': String(a.round === i),
        'aria-label': `Round ${r.round_number}, ${r.phase}, ${CELL_LABEL[cls]}`, title: `Round ${r.round_number}: ${CELL_LABEL[cls]}`,
        onclick: () => { a.round = i; render(); } });
      if (r.phase === 'benign' && firstBenign) { firstBenign = false; return [h('span', { class: 'cell gap' }), btn]; }
      return btn;
    })));
    if (a.round != null) m.append(roundDetail(d.rounds[a.round]));
  }
  function roundDetail(r) {
    const cls = roundClass(r);
    const box = h('section', { class: 'detail', 'aria-live': 'polite' });
    box.append(h('h2', { text: `Round ${r.round_number}, ${r.phase === 'attack' ? 'attack' : 'benign control'}`, style: 'margin-top:0' }));
    if (!r.valid) {
      box.append(h('div', { class: 'notice-info', text: `This round is invalid and excluded from every metric: ${r.error_category}. ${r.error_detail || ''}` }));
      return box;
    }
    box.append(h('p', null, h('span', { class: `tag ${cls === 'success' ? 'tag-bad' : 'tag-ok'}`, text: CELL_LABEL[cls] }), ' ', ORACLE_TEXT[r.oracle.oracle_code] || r.oracle.oracle_code));
    box.append(h('div', { class: 'subhead', text: r.phase === 'attack' ? `Payload injected into the retrieved content (${r.strategy_id})` : `Benign text injected (${r.strategy_id})` }),
      h('pre', { class: 'payload', text: r.payload || '' }));
    box.append(h('div', { class: 'subhead', text: 'Tool calls' }));
    if (!r.tool_calls.length) box.append(h('p', { class: 'muted', text: 'The agent made no tool calls.' }));
    else box.append(h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Step', 'Time (UTC)', 'Tool', 'Arguments', 'Defense decision', 'Ran', 'Authorized by task'].map(t => h('th', { text: t })))),
      h('tbody', null, r.tool_calls.map(c => h('tr', null,
        h('td', { text: String(c.step) }),
        h('td', { class: 'mono small', text: (c.timestamp || '').replace('T', ' ').replace('Z', '') }),
        h('td', { class: 'mono', text: c.tool }),
        h('td', null, h('span', { class: 'mono', text: JSON.stringify(c.arguments) }),
          c.output_seen_by_agent ? h('details', null, h('summary', { text: 'What the agent saw' }), h('pre', { class: 'payload', text: c.output_seen_by_agent })) : null),
        h('td', null, c.kind === 'write' ? `${c.defense_decision} (${c.defense_reason_code})` : (c.content_blocked ? `content withheld (risk ${c.content_risk_score})` : (c.content_risk_score != null ? `content allowed (risk ${c.content_risk_score})` : 'read, not gated'))),
        h('td', { text: c.executed ? 'yes' : 'no' }),
        h('td', { text: c.kind !== 'write' ? 'not applicable' : (c.ground_truth_authorized ? 'yes' : 'no') })))))));
    box.append(h('div', { class: 'subhead', text: 'Agent response' }), h('pre', { class: 'payload', text: r.response_text || '(empty)' }),
      h('dl', { class: 'kv' },
        h('dt', { text: 'Round seed' }), h('dd', { class: 'mono', text: String(r.round_seed) }),
        h('dt', { text: 'Target' }), h('dd', { text: r.target_provenance }),
        h('dt', { text: 'Legitimate task completed' }), h('dd', { text: r.oracle.legitimate_task_completed ? 'yes' : 'no' })));
    return box;
  }

  // ------------------------------------------------------------------ provenance
  function viewProvenance(m) {
    m.append(pageHead('Provenance', 'What produced these numbers, and what is needed to reproduce them.'));
    if (!state.runId) { m.append(emptyState('No run selected', 'Run an experiment first, or choose an earlier run from the list on the left.', 'Go to Configure', () => setView('configure'))); return; }
    if (!state.summary) { m.append(emptyState('Results are not ready', 'The manifest is finalized when the run finishes.', 'Watch the run', () => setView('live'))); return; }
    const sm = state.summary, man = sm.manifest, prov = sm.provenance;
    m.append(h('h2', { text: 'Components', style: 'margin-top:0' }),
      h('p', { text: prov.demonstration_warning ? 'Some components in this run are simulations or demonstration fixtures, so the results illustrate the method and are not research evidence.' : 'Every component in this run used real models or fixed rule sets.' }),
      h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, ['Role', 'Component', 'Provenance', 'Status'].map(t => h('th', { text: t })))),
        h('tbody', null, prov.components.map(c => h('tr', null,
          h('td', { text: c.role }), h('td', { text: c.role === 'Defense' ? defenseLabel(c.name) : (MODE_LABEL[c.name] || c.name) }),
          h('td', { class: 'mono', text: c.provenance }),
          h('td', null, h('span', { class: `tag ${c.is_demonstration ? 'tag-demo' : 'tag-ok'}`, text: c.is_demonstration ? 'Demonstration' : 'Real or fixed rules' }))))))));

    m.append(h('h2', { text: 'Reproducibility manifest' }), h('dl', { class: 'kv' },
      ...[['Experiment', sm.experiment_id], ['Schema version', man.schema_version], ['Platform version', man.platform_version],
        ['Scenario suite', `${man.suite_id} ${man.suite_version}`], ['Suite content hash', man.suite_content_hash],
        ['Source-tree hash', man.source_tree_hash], ['Git', man.git ? `${man.git.commit} (dirty: ${man.git.dirty === null ? 'not checked' : man.git.dirty})` : 'not a Git checkout'],
        ['Dependency versions', Object.keys(man.dependency_versions || {}).length ? JSON.stringify(man.dependency_versions) : 'none (zero third-party dependencies by design)'],
        ['Model-failure policy', man.model_failure_policy],
        ['Scenarios', man.scenario_ids.join(', ')], ['Defenses', man.defenses.join(', ')], ['Attackers', man.attack_modes.join(', ')],
        ['Target mode', man.target_mode], ['Attack budget per campaign', String(man.attack_budget)], ['Seeds', man.seeds.join(', ')],
        ['Final window', `${Math.round(man.final_window_fraction * 100)}% of valid rounds, at least ${man.final_window_minimum}`],
        ['Attacker model', man.model_config ? JSON.stringify(man.model_config) : 'none'], ['Target model', man.real_target_config ? JSON.stringify(man.real_target_config) : 'none'],
        ['Network allowlist', man.network_allowlist.join(', ')], ['Python', man.runtime_environment.python_version], ['Platform', man.runtime_environment.platform],
        ['Generated', man.generated_at], ['Run status', man.run_status || 'complete']]
        .flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: 'mono', text: v })])),
      h('p', { class: 'small muted', text: 'Downloaded JSON and CSV reports each get a companion .hashes.json file with their SHA-256 hash, written after the fact so the hash is never stored inside the file it describes.' }));

    const unmatched = sm.matched_budget.filter(b => !b.matched);
    const budgetTable = h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Scenario', 'Attacker', 'Result'].map(t => h('th', { text: t })))),
      h('tbody', null, sm.matched_budget.map(b => h('tr', null, h('td', { text: scenarioTitle(b.scenario_id) }), h('td', { text: MODE_LABEL[b.attack_mode] || b.attack_mode }),
        h('td', null, h('span', { class: `tag ${b.matched ? 'tag-ok' : 'tag-bad'}`, text: b.matched ? 'Matched' : b.detail })))))));
    m.append(h('h2', { text: 'Matched attempt budgets' }),
      h('p', { text: unmatched.length
        ? `${unmatched.length} of ${sm.matched_budget.length} scenario and attacker groups did not give every defense the same number of attack rounds. Comparisons for those groups are not fair.`
        : `All ${sm.matched_budget.length} scenario and attacker groups gave every defense the same number of attack rounds.` }),
      unmatched.length ? budgetTable : h('details', null, h('summary', { text: 'Show every group' }), budgetTable));

    const excluded = state.stats ? state.stats.excluded_runs : [];
    m.append(h('h2', { text: 'Invalid and excluded runs' }),
      excluded.length
        ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Campaign', 'Status', 'Invalid rounds', 'Errors'].map(t => h('th', { text: t })))),
          h('tbody', null, excluded.map(e => h('tr', null, h('td', { class: 'mono', text: e.campaign_id }), h('td', { text: e.status }), h('td', { text: String(e.attack_rounds_invalid) }), h('td', { class: 'mono', text: JSON.stringify(e.error_counts) }))))))
        : h('p', { class: 'muted', text: 'No campaign had invalid rounds, and none was cancelled.' }));

    const fallbacks = sm.campaigns.filter(c => c.is_demo_fallback);
    if (fallbacks.length) {
      m.append(h('h2', { text: 'Demonstration-fallback campaigns' }),
        h('p', { text: 'Each of these ran because model_failure_policy was set to restart_as_separate_demo_campaign and the model-backed attacker became unavailable mid-campaign. Every one is a separate campaign with its own id, using the deterministic demo attacker, and none of them is combined with the aborted campaign or pooled into any comparison above.' }),
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, ['Fallback campaign', 'Original campaign', 'Reason the original campaign aborted'].map(t => h('th', { text: t })))),
          h('tbody', null, fallbacks.map(f => h('tr', null,
            h('td', { class: 'mono', text: f.campaign_id }),
            h('td', { class: 'mono', text: f.fallback_of }),
            h('td', { text: (sm.campaigns.find(c => c.campaign_id === f.fallback_of) || {}).abort_reason || 'n/a' })))))));
    }

    m.append(h('h2', { text: 'Export' }), h('p', null,
      h('a', { href: `/api/experiments/${state.runId}`, download: `${sm.experiment_id}.json`, text: 'Download the full report as JSON' }), ' includes every round and tool call. ',
      h('a', { href: `/api/experiments/${state.runId}/comparison.csv`, text: 'Download the comparison table as CSV' }), ' has one row per campaign.'));
  }

  // ------------------------------------------------------------------ init
  async function init() {
    $('#runSelect').addEventListener('change', e => { if (e.target.value) selectRun(e.target.value, state.view === 'configure' ? 'live' : null); });
    window.addEventListener('hashchange', () => { const v = location.hash.slice(1); if (VIEWS.some(x => x.id === v) && v !== state.view) { state.view = v; render(); } });
    try {
      state.suite = await api('/api/suite');
      state.cfg.scenarios = new Set(state.suite.primary_ids);
    } catch (e) { state.initError = `Could not load the scenario suite: ${e.message}`; }
    await refreshRuns();
    const v = location.hash.slice(1);
    if (VIEWS.some(x => x.id === v)) state.view = v;
    updateBanner();
    render();
  }
  init();
})();
