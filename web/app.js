const $ = (id) => document.getElementById(id);

let token = sessionStorage.getItem('aegisToken') || '';
let presets = {};
let organizations = [];
let projects = [];
let currentScan = null;
let pollTimer = null;

function escapeHtml(v=''){
  return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

async function api(path, options={}) {
  const headers = {'Content-Type':'application/json', ...(options.headers||{})};
  if(token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, {...options, headers});
  const data = await res.json().catch(()=>({}));
  if(res.status === 401 && path !== '/api/login') logout();
  if(!res.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map(x => `${(x.loc||[]).join('.')}: ${x.msg}`).join(' | ')
      : (data.detail || JSON.stringify(data));
    throw new Error(detail);
  }
  return data;
}

async function downloadReport(path, filename){
  const res = await fetch(path, {headers:{Authorization:`Bearer ${token}`}});
  if(!res.ok) throw new Error('Não foi possível gerar o relatório.');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href=url;
  a.download=filename;
  a.click();
  URL.revokeObjectURL(url);
}

function showApp(){
  $('loginView').classList.add('hidden');
  $('appView').classList.remove('hidden');
}

function showLogin(){
  $('appView').classList.add('hidden');
  $('loginView').classList.remove('hidden');
}

function logout(){
  if(pollTimer) clearTimeout(pollTimer);
  token='';
  sessionStorage.removeItem('aegisToken');
  currentScan=null;
  showLogin();
}

async function login(){
  $('loginError').textContent='';
  try{
    const data = await api('/api/login',{
      method:'POST',
      body:JSON.stringify({username:$('loginUser').value,password:$('loginPassword').value})
    });
    token=data.token;
    sessionStorage.setItem('aegisToken',token);
    showApp();
    await boot();
  }catch(e){
    $('loginError').textContent=e.message;
  }
}

async function refreshOrganizations(){
  organizations = await api('/api/organizations');
  const options = organizations.map(o => `<option value="${o.id}">${escapeHtml(o.name)}</option>`).join('');
  $('organizationSelect').innerHTML = options || '<option value="">Nenhuma organização</option>';
  $('projectOrganizationSelect').innerHTML = options || '<option value="">Nenhuma organização</option>';
}

async function refreshProjects(){
  projects = await api('/api/projects');
  const orgNames = Object.fromEntries(organizations.map(o => [o.id,o.name]));
  $('projectSelect').innerHTML = projects.map(p =>
    `<option value="${p.id}">${escapeHtml(orgNames[p.organization_id] || 'Org')} / ${escapeHtml(p.name)}</option>`
  ).join('');
  if(!projects.length){
    $('projectSelect').innerHTML = '<option value="">Nenhum projeto disponível</option>';
  }
}

async function refreshTargets(){
  const targets = await api('/api/targets');
  $('targetSelect').innerHTML = targets.map(t =>
    `<option value="${t.id}">${escapeHtml(t.name)} · ${escapeHtml(t.provider)} · ${escapeHtml(t.capabilities.join('/'))}</option>`
  ).join('');
  if(!targets.length) $('targetSelect').innerHTML='<option value="">Nenhum target</option>';
  $('statTargets').textContent=targets.length;
}

async function refreshHistory(){
  const scans=await api('/api/scans');
  $('statScans').textContent=scans.length;
  if(scans.length){
    $('statScore').textContent=scans[0].score==null?'--':`${scans[0].score}/100`;
    $('statCritical').textContent=scans[0].findings.filter(f=>f.severity==='CRITICAL').length;
  } else {
    $('statScore').textContent='--';
    $('statCritical').textContent='0';
  }

  if(!scans.length){
    $('history').innerHTML='<p class="muted">Nenhum scan ainda.</p>';
    return;
  }

  $('history').innerHTML=scans.map(s=>{
    const r=s.regression||{};
    let reg='aguardando execução';
    if(s.status === 'completed'){
      reg=r.baseline?'baseline':`+${r.new||0} novos · -${r.resolved||0} resolvidos · Δ ${r.score_delta??0}`;
    } else if(s.status === 'failed') {
      reg='falhou';
    }
    return `<button class="history-row" data-scan="${s.id}">
      <span>#${s.id}</span>
      <span>${escapeHtml(s.status)}</span>
      <span class="mini-score">${s.score??'--'}</span>
      <span>${escapeHtml(reg)}</span>
    </button>`;
  }).join('');

  document.querySelectorAll('[data-scan]').forEach(btn=>{
    btn.onclick=async()=>renderScan(await api(`/api/scans/${btn.dataset.scan}`));
  });
}

async function refreshIntegrations(){
  try{
    const data = await api('/api/integrations');
    $('integrations').innerHTML = Object.entries(data).map(([name, item])=>{
      const available = !!item.available;
      return `<article class="integration-card">
        <strong><span class="status-dot ${available?'on':'off'}"></span>${escapeHtml(name)}</strong>
        <span class="tag">${escapeHtml(item.mode || 'unknown')}</span>
        <p class="muted">${escapeHtml(item.detail || '')}</p>
      </article>`;
    }).join('');
  }catch(e){
    $('integrations').innerHTML=`<p class="error">${escapeHtml(e.message)}</p>`;
  }
}

async function refreshAuditEvents(){
  try{
    const events = await api('/api/audit-events?limit=30');
    if(!events.length){
      $('auditEvents').innerHTML='<p class="muted">Nenhum evento ainda.</p>';
      return;
    }
    $('auditEvents').innerHTML=events.map(ev=>{
      const when = ev.created_at ? new Date(ev.created_at).toLocaleString() : '';
      return `<div class="audit-row">
        <span>${escapeHtml(when)}</span>
        <span><code>${escapeHtml(ev.action)}</code> · ${escapeHtml(ev.entity_type)}${ev.entity_id ? ' #'+ev.entity_id : ''}</span>
        <span>${escapeHtml(ev.actor)}</span>
      </div>`;
    }).join('');
  }catch(e){
    $('auditEvents').innerHTML=`<p class="error">${escapeHtml(e.message)}</p>`;
  }
}

function providerChanged(){
  const p=presets[$('provider').value];
  if(!p) return;
  $('url').value=p.url;
  $('template').value=JSON.stringify(p.template,null,2);
  $('responsePath').value=p.response_path||'';
  $('authHint').textContent=p.auth_hint||'';
}

function renderScan(scan){
  currentScan=scan;
  $('scanMeta').textContent=`Scan #${scan.id} · ${scan.status}` + (scan.error ? ` · ${scan.error}` : '');
  $('score').textContent=scan.score==null?'--':`${scan.score}/100`;

  const r=scan.regression||{};
  if(scan.status === 'queued'){
    $('regression').textContent='Scan enfileirado. O worker vai iniciar em instantes.';
  } else if(scan.status === 'running'){
    $('regression').textContent='Worker executando os probes de segurança…';
  } else if(scan.status === 'failed'){
    $('regression').textContent='O scan falhou. Veja a mensagem acima.';
  } else {
    $('regression').textContent=r.baseline
      ? 'Primeiro scan deste alvo — este resultado vira a baseline.'
      : `Comparado ao scan #${r.previous_scan_id}: ${r.new} novo(s), ${r.resolved} resolvido(s), ${r.unchanged} inalterado(s), score Δ ${r.score_delta}.`;
  }

  $('resultActions').classList.toggle('hidden', scan.status !== 'completed');

  if(scan.status !== 'completed'){
    $('findings').innerHTML='<p class="muted">Aguardando conclusão do scan…</p>';
    return;
  }

  if(!scan.findings.length){
    $('findings').innerHTML='<p class="success">Nenhuma vulnerabilidade foi detectada pelos probes executados.</p>';
    return;
  }

  $('findings').innerHTML = scan.findings.map(f=>`<article class="finding ${f.severity}">
    <div>
      <span class="tag">${escapeHtml(f.severity)}</span>
      <span class="tag">${escapeHtml(f.category)}</span>
      <span class="tag">confiança ${escapeHtml(f.confidence)}</span>
    </div>
    <h3>${escapeHtml(f.title)}</h3>
    <p>${escapeHtml(f.description)}</p>
    <p><b>Evidência:</b> ${escapeHtml(f.evidence)}</p>
    <p><b>Correção:</b> ${escapeHtml(f.remediation)}</p>
    <div>${f.standard_refs.map(x=>`<span class="tag">${escapeHtml(x)}</span>`).join('')}</div>
  </article>`).join('');
}

async function pollScan(scanId){
  if(pollTimer) clearTimeout(pollTimer);
  try{
    const scan = await api(`/api/scans/${scanId}`);
    renderScan(scan);
    await refreshHistory();
    if(scan.status === 'queued' || scan.status === 'running'){
      pollTimer=setTimeout(()=>pollScan(scanId),1000);
    } else {
      await refreshAuditEvents();
    }
  }catch(e){
    $('scanMeta').textContent=e.message;
  }
}

$('loginBtn').onclick=login;
$('loginPassword').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
$('logoutBtn').onclick=logout;
$('provider').onchange=providerChanged;
$('refreshIntegrations').onclick=refreshIntegrations;

$('createOrganization').onclick=async()=>{
  $('organizationResult').className='muted';
  try{
    const name=$('organizationName').value.trim();
    if(name.length<2) throw new Error('Digite um nome de organização.');
    const org=await api('/api/organizations',{method:'POST',body:JSON.stringify({name})});
    $('organizationResult').textContent=`Organização #${org.id} criada.`;
    $('organizationName').value='';
    await refreshOrganizations();
    await refreshProjects();
    await refreshAuditEvents();
  }catch(e){
    $('organizationResult').className='error';
    $('organizationResult').textContent=e.message;
  }
};

$('createProject').onclick=async()=>{
  $('projectResult').className='muted';
  try{
    const organizationId=Number($('projectOrganizationSelect').value);
    const name=$('projectName').value.trim();
    if(!organizationId) throw new Error('Selecione uma organização.');
    if(name.length<2) throw new Error('Digite um nome de projeto.');
    const project=await api('/api/projects',{
      method:'POST',
      body:JSON.stringify({
        organization_id:organizationId,
        name,
        description:$('projectDescription').value.trim() || null
      })
    });
    $('projectResult').textContent=`Projeto #${project.id} criado.`;
    $('projectName').value='';
    $('projectDescription').value='';
    await refreshProjects();
    $('projectSelect').value=String(project.id);
    await refreshAuditEvents();
  }catch(e){
    $('projectResult').className='error';
    $('projectResult').textContent=e.message;
  }
};

$('createTarget').onclick = async () => {
  $('targetResult').className='';
  try{
    const projectId=Number($('projectSelect').value);
    if(!projectId) throw new Error('Selecione um projeto.');
    const capabilities=[...document.querySelectorAll('.cap:checked')].map(x=>x.value);
    const body={
      project_id:projectId,
      name:$('name').value,
      url:$('url').value,
      method:$('method').value,
      provider:$('provider').value,
      capabilities,
      request_template:JSON.parse($('template').value),
      response_path:$('responsePath').value||null,
      authorized:$('authorized').checked
    };
    const t=await api('/api/targets',{method:'POST',body:JSON.stringify(body)});
    $('targetResult').textContent=`Alvo #${t.id} cadastrado com capacidades ${t.capabilities.join(', ')}.`;
    await refreshTargets();
    $('targetSelect').value=String(t.id);
    await refreshAuditEvents();
  }catch(e){
    $('targetResult').className='error';
    $('targetResult').textContent=e.message;
  }
};

$('runScan').onclick = async () => {
  try{
    const targetId=Number($('targetSelect').value);
    if(!targetId) throw new Error('Cadastre e selecione um target antes de executar o scan.');
    $('scanMeta').textContent='Enfileirando scan defensivo…';
    $('findings').innerHTML='';
    $('regression').textContent='';
    const headers=JSON.parse($('headers').value||'{}');
    const scan=await api('/api/scans',{
      method:'POST',
      body:JSON.stringify({target_id:targetId,engine:'builtin',headers,categories:[]})
    });
    renderScan(scan);
    await pollScan(scan.id);
  }catch(e){
    $('scanMeta').textContent=e.message;
  }
};

$('retestBtn').onclick=async()=>{
  if(!currentScan) return;
  try{
    const headers=JSON.parse($('headers').value||'{}');
    $('scanMeta').textContent=`Enfileirando retest do scan #${currentScan.id}…`;
    const scan=await api(`/api/scans/${currentScan.id}/retest`,{
      method:'POST',
      body:JSON.stringify({headers})
    });
    renderScan(scan);
    await pollScan(scan.id);
  }catch(e){
    $('scanMeta').textContent=e.message;
  }
};

$('jsonReportBtn').onclick=()=>currentScan&&downloadReport(`/api/scans/${currentScan.id}/report.json`,`aegis-scan-${currentScan.id}.json`);
$('sarifReportBtn').onclick=()=>currentScan&&downloadReport(`/api/scans/${currentScan.id}/report.sarif`,`aegis-scan-${currentScan.id}.sarif`);

$('auditMcp').onclick=async()=>{
  $('mcpResults').innerHTML='<p class="muted">Analisando manifest…</p>';
  try{
    const manifest=JSON.parse($('mcpManifest').value);
    const risks=await api('/api/mcp/audit',{method:'POST',body:JSON.stringify({manifest})});
    if(!risks.length){
      $('mcpResults').innerHTML='<p class="success">Nenhum risco foi identificado pelas regras estáticas atuais.</p>';
    } else {
      $('mcpResults').innerHTML=risks.map(r=>`<article class="risk-card ${r.severity}">
        <div><span class="tag">${escapeHtml(r.severity)}</span><span class="tag">tool: ${escapeHtml(r.tool)}</span></div>
        <h3>${escapeHtml(r.title)}</h3>
        <p>${escapeHtml(r.description)}</p>
        <p><b>Evidência:</b> ${escapeHtml(r.evidence)}</p>
        <p><b>Correção:</b> ${escapeHtml(r.remediation)}</p>
      </article>`).join('');
    }
    await refreshAuditEvents();
  }catch(e){
    $('mcpResults').innerHTML=`<p class="error">${escapeHtml(e.message)}</p>`;
  }
};

async function boot(){
  try{
    const health=await api('/api/health');
    $('health').textContent=`API online · ${health.version} · ${health.queue}`;
    presets=await api('/api/provider-presets');
    $('provider').innerHTML=Object.entries(presets).map(([k,v])=>`<option value="${k}">${escapeHtml(v.label)}</option>`).join('');
    $('provider').value='generic';
    $('authHint').textContent='Use headers efêmeros apenas ao executar o scan.';
    await refreshOrganizations();
    await refreshProjects();
    await refreshTargets();
    await refreshHistory();
    await refreshIntegrations();
    await refreshAuditEvents();
  }catch(e){
    if(token) $('health').textContent=`API com erro: ${e.message}`;
  }
}

(async()=>{
  if(token){
    showApp();
    await boot();
  } else {
    showLogin();
  }
})();
