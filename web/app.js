// OATH Receipt Explorer — interactive layer.

(function () {
  'use strict';

  const TOOL_DESCRIPTIONS = {
    parse_evtx:
      'Wraps EvtxECmd. Parses .evtx event logs into typed EvtxRecord objects ' +
      'with native logon_type / auth_package / source_ip extracted from the JSON Payload.',
    parse_registry:
      'Wraps RECmd batch-plugin mode. Parses Windows registry hives ' +
      '(SAM / SYSTEM / SOFTWARE / NTUSER / SECURITY) and emits typed RegistryFinding ' +
      'objects from the ~150 RECmd persistence + execution-residue plugins.',
    parse_mft:
      'Wraps MFTECmd. Parses the NTFS $MFT into typed MftEntry objects with ' +
      'all 8 NTFS timestamps preserved (the $SI/$FN timestomp tripwire).',
    parse_usnjrnl:
      'Wraps MFTECmd $J mode. Parses the NTFS USN journal into typed UsnRecord ' +
      'objects — surfaces file deletions, renames, and data-overwrites that ' +
      'attackers use to cover their tracks.',
    run_hayabusa:
      'Wraps Hayabusa 3.x with the super-verbose profile. Runs ~5,000 Sigma ' +
      'detection rules against a directory of .evtx files and emits typed SigmaHit ' +
      'objects with MITRE ATT&CK technique mapping.',
    plaso_supertimeline:
      'Wraps psort.py queries against a pre-built .plaso store. Returns a ' +
      'cross-source ordered timeline merging events from every parser plaso ' +
      'has (EVTX, registry, $MFT, Prefetch, browser, ...).',
    parse_amcache:
      'Wraps AmcacheParser. Parses Amcache.hve into typed AmcacheEntry objects ' +
      'with program-execution residue and SHA-1 hashes.',
    parse_prefetch:
      'Wraps PECmd. Parses Windows Prefetch (.pf) files into typed PrefetchEntry ' +
      'objects with up to 8 run-times per binary + referenced-files list.',
    vol3_query:
      'Wraps Volatility 3 plugin execution against a memory image. Surfaces ' +
      'process trees, network connections, LSASS handles, hashdumps, etc., ' +
      'as typed Vol3Row objects.',
    find_strings_on_image:
      'Wraps Sleuthkit fls + icat with a multi-encoding (ascii / utf-8 / ' +
      'utf-16-le / utf-16-be) byte-level pattern search. The evidence-operation ' +
      'surface for NIST String Search-style queries.',
    enumerate_credential_artifacts:
      'Pure-Python filesystem inventory of credential-bearing artifacts: ' +
      'registry hives, DPAPI keys, browser credential DBs, LSASS dumps, ' +
      'hiberfil/pagefile, NTDS.dit, SSH keys. The FIRST call in autonomous triage.',
  };

  const SUMMARIES = {
    parse_evtx: 'Authentication events extracted with native LogonType/AuthPackage/IpAddress from the JSON Payload.',
    parse_registry: 'Persistence + execution-residue findings — the suspect "informant" RID 1000 surfaces.',
    parse_mft: 'Full $MFT walk filtered to the suspect user. 5,347 entries with all 8 NTFS timestamps.',
    parse_usnjrnl: 'Delete-reason filter on the USN journal. Surfaced 28 Outlook OST temp files containing the suspect\'s email iaman.informant@nist.gov.',
    run_hayabusa: 'Sigma triage — high+ severity. T1098 admin-group additions on 2015-03-22, T1543.003 service persistence on the leak day.',
  };

  // --------------- helpers ---------------

  function el(html) {
    const t = document.createElement('template');
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      const original = btn.textContent;
      btn.textContent = '✓ copied';
      setTimeout(function () { btn.textContent = original; }, 1500);
    });
  }

  // --------------- render envelope cards ---------------

  function renderEnvelopes(envelopes) {
    const container = document.getElementById('envelopes-list');
    container.innerHTML = '';

    envelopes.forEach(function (env, idx) {
      const desc = SUMMARIES[env.tool_name] || 'Notarized envelope from a typed forensic call.';
      const card = el(
        '<div class="envelope-card" data-idx="' + idx + '">' +
          '<div class="verdict verdict-' + env.verdict.toLowerCase() + '">' +
            escapeHtml(env.verdict) +
          '</div>' +
          '<div>' +
            '<div>' +
              '<span class="tool-name">' + escapeHtml(env.tool_name) + '</span>' +
              '<span class="tool-version">v' + escapeHtml(env.tool_version) + '</span>' +
            '</div>' +
            '<div class="summary">' + escapeHtml(desc) + '</div>' +
            '<div class="summary" style="margin-top:6px;color:var(--text-dim);font-family:var(--font-mono);font-size:12px;">' +
              'envelope ' + escapeHtml(env.envelope_id.slice(0, 16)) + '… · stdout BLAKE3 ' + escapeHtml(env.stdout_blake3.slice(0, 16)) + '…' +
            '</div>' +
          '</div>' +
          '<div class="findings-count">' + env.n_records.toLocaleString() + ' records →</div>' +
        '</div>'
      );
      card.addEventListener('click', function () { openModal(env); });
      container.appendChild(card);
    });
  }

  // --------------- modal ---------------

  function openModal(env) {
    const desc = TOOL_DESCRIPTIONS[env.tool_name] || 'Typed MCP function output.';
    const sampleStr = JSON.stringify(env.sample_data, null, 2);
    const argsObj = (function () {
      try { return JSON.parse(env.args_canonical); }
      catch (_) { return env.args_canonical; }
    })();
    const argsStr = JSON.stringify(argsObj, null, 2);

    const html =
      '<div class="modal-tool">' + escapeHtml(env.tool_name) + '()</div>' +
      '<div class="modal-version">v' + escapeHtml(env.tool_version) + ' · ' + escapeHtml(env.n_records.toLocaleString()) + ' records · verdict <strong style="color:var(--verified)">' + escapeHtml(env.verdict) + '</strong></div>' +
      '<p style="color:var(--text-muted);margin:0 0 28px;font-size:15px;">' + escapeHtml(desc) + '</p>' +

      '<div class="modal-section">' +
        '<h4>Notarized envelope</h4>' +
        '<div class="field"><div class="field-key">envelope_id</div><div class="field-val field-val-mono">' + escapeHtml(env.envelope_id) + '</div></div>' +
        '<div class="field"><div class="field-key">image_sha256</div><div class="field-val field-val-mono">' + escapeHtml(env.image_sha256) + '</div></div>' +
        '<div class="field"><div class="field-key">stdout_blake3</div><div class="field-val field-val-mono">' + escapeHtml(env.stdout_blake3) + '</div></div>' +
        (env.data_blake3 ? '<div class="field"><div class="field-key">data_blake3</div><div class="field-val field-val-mono">' + escapeHtml(env.data_blake3) + '</div></div>' : '') +
        '<div class="field"><div class="field-key">model_id <span style="color:var(--text-muted);font-weight:normal">(Daubert binding)</span></div><div class="field-val field-val-mono">' + escapeHtml(env.model_id || '(none — deterministic; no LLM)') + '</div></div>' +
        '<div class="field"><div class="field-key">prompt_hash <span style="color:var(--text-muted);font-weight:normal">(Daubert binding)</span></div><div class="field-val field-val-mono">' + escapeHtml(env.prompt_hash || '(none — deterministic; no LLM)') + '</div></div>' +
        '<div class="field"><div class="field-key">prev (chain link)</div><div class="field-val field-val-mono">' + escapeHtml(env.prev || '(genesis — first envelope in run)') + '</div></div>' +
        '<div class="field"><div class="field-key">ed25519 signature</div><div class="field-val field-val-mono">' + escapeHtml(env.signature) + '</div></div>' +
        '<div class="field"><div class="field-key">timestamp (UTC)</div><div class="field-val">' + escapeHtml(env.ts) + '</div></div>' +
        '<div class="field"><div class="field-key">run_id</div><div class="field-val field-val-mono">' + escapeHtml(env.run_id) + '</div></div>' +
      '</div>' +

      '<div class="modal-section">' +
        '<h4>Canonical args (RFC 8785 JCS)</h4>' +
        '<pre><code>' + escapeHtml(argsStr) + '</code></pre>' +
      '</div>' +

      '<div class="modal-section">' +
        '<h4>Sample of data (first 3 records)</h4>' +
        '<pre><code>' + escapeHtml(sampleStr) + '</code></pre>' +
      '</div>' +

      '<div class="modal-verify">' +
        '<h4>Re-derive this envelope on your laptop</h4>' +
        '<p>' +
          'After installing OATH and mounting <code style="background:var(--bg);padding:2px 6px;border-radius:3px;">cfreds_2015_data_leakage_pc.E01</code>, run:' +
        '</p>' +
        '<code>oath verify ' + escapeHtml(env.envelope_id) + '</code>' +
      '</div>';

    document.getElementById('modal-content').innerHTML = html;
    document.getElementById('modal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    document.getElementById('modal').classList.add('hidden');
    document.body.style.overflow = '';
  }

  // --------------- boot ---------------

  document.addEventListener('DOMContentLoaded', function () {
    const data = window.OATH_DATA;
    if (!data) {
      document.getElementById('envelopes-list').innerHTML =
        '<div class="loader" style="color:var(--danger);">data.js failed to load — refresh.</div>';
      return;
    }

    // Update image SHA-256 in the hero
    const imgShaEl = document.getElementById('image-sha');
    if (imgShaEl && data.case) {
      imgShaEl.textContent = data.case.image_sha256.slice(0, 16) + '…';
      imgShaEl.title = data.case.image_sha256;
    }

    renderEnvelopes(data.envelopes);

    // Modal close handlers
    document.querySelectorAll('[data-close]').forEach(function (b) {
      b.addEventListener('click', closeModal);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeModal();
    });
  });
})();
