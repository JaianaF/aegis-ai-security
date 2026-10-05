const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem('aegisToken') || '';
let presets = {};
let currentScan = null;

function escapeHtml(v=''){return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}

async function api(path, options={}) {
  const headers = {'Content-Type':'application/json', ...(options.headers||{})};
  if(token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, {...options, headers});
  const data = await res.json().catch(()=>({}));
  if(res.status === 401 && path !== '/api/login') logout();
  if(!res.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

async function downloadReport(path, filename){
  const res = await fetch(path, {headers:{Authorization:`Bearer ${token}`}});
  if(!res.ok) throw new Error('Não foi possível gerar o relatório.');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=filename; a.click();
  URL.revokeObjectURL(url);
}

function showApp(){ $('loginView').classList.add('hidden'); $('appView').classList.remove('hidden'); }
function showLogin(){ $('appView').classList.add('hidden'); $('loginView').classList.remove('hidden'); }
function logout(){ token=''; sessionStorage.removeItem('aegisToken'); currentScan=null; showLogin(); }

async function login(){
  $('loginError').textContent='';
  try{
    const data = await api('/api/login',{method:'POST',body:JSON.stringify({username:$('loginUser').value,password:$('loginPassword').value})});
    token=data.token; sessionStorage.setItem('aegisToken',token); showApp(); await boot();
  }catch(e){$('loginError').textContent=e.message;}
}

async function refreshTargets(){
  const targets = await api('/api/targets');
  $('targetSelect').innerHTML = targets.map(t => `<option value="${t.id}">${escapeHtml(t.name)} · ${escapeHtml(t.provider)} · ${escapeHtml(t.capabilities.join('/'))}</option>`).join('');
  $('statTargets').textContent=targets.length;
}

async function refreshHistory(){
  const scans=await api('/api/scans');
  $('statScans').textContent=scans.length;
  if(scans.length){
    $('statScore').textContent=scans[0].score==null?'--':`${scans[0].score}/100`;
    $('statCritical').textContent=scans[0].findings.filter(f=>f.severity==='CRITICAL').length;
  }
  if(!scans.length){$('history').innerHTML='<p class="muted">Nenhum scan ainda.</p>'; return;}
  $('history').innerHTML=scans.map(s=>{
    const r=s.regression||{};
    const reg=r.baseline?'baseline':`+${r.new||0} novos · -${r.resolved||0} resolvidos · Δ ${r.score_delta??0}`;
    return `<button class="history-row" data-scan="${s.id}"><span>#${s.id}</span><span>${escapeHtml(s.status)}</span><span class="mini-score">${s.score??'--'}</span><span>${escapeHtml(reg)}</span></button>`;
  }).join('');
  document.querySelectorAll('[data-scan]').forEach(btn=>btn.onclick=async()=>renderScan(await api(`/api/scans/${btn.dataset.scan}`)));
}

function providerChanged(){
  const p=presets[$('provider').value]; if(!p) return;
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
  $('regression').textContent=r.baseline?'Primeiro scan deste alvo — este resultado vira a baseline.':`Comparado ao scan #${r.previous_scan_id}: ${r.new} novo(s), ${r.resolved} resolvido(s), ${r.unchanged} inalterado(s), score Δ ${r.score_delta}.`;
  $('resultActions').classList.remove('hidden');
  if(!scan.findings.length){$('findings').innerHTML='<p class="success">Nenhuma vulnerabilidade foi detectada pelos probes executados.</p>';return;}
  $('findings').innerHTML = scan.findings.map(f=>`<article class="finding ${f.severity}">
    <div><span class="tag">${escapeHtml(f.severity)}</span><span class="tag">${escapeHtml(f.category)}</span><span class="tag">confiança ${escapeHtml(f.confidence)}</span></div>
    <h3>${escapeHtml(f.title)}</h3>
    <p>${escapeHtml(f.description)}</p>
    <p><b>Evidência:</b> ${escapeHtml(f.evidence)}</p>
    <p><b>Correção:</b> ${escapeHtml(f.remediation)}</p>
    <div>${f.standard_refs.map(x=>`<span class="tag">${escapeHtml(x)}</span>`).join('')}</div>
  </article>`).join('');
}

$('loginBtn').onclick=login;
$('loginPassword').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
$('logoutBtn').onclick=logout;
$('provider').onchange=providerChanged;

$('createTarget').onclick = async () => {
  $('targetResult').className='';
  try{
    const capabilities=[...document.querySelectorAll('.cap:checked')].map(x=>x.value);
    const body={name:$('name').value,url:$('url').value,method:$('method').value,provider:$('provider').value,capabilities,request_template:JSON.parse($('template').value),response_path:$('responsePath').value||null,authorized:$('authorized').checked};
    const t=await api('/api/targets',{method:'POST',body:JSON.stringify(body)});
    $('targetResult').textContent=`Alvo #${t.id} cadastrado com capacidades ${t.capabilities.join(', ')}.`;
    await refreshTargets();
  }catch(e){$('targetResult').className='error';$('targetResult').textContent=e.message;}
};

$('runScan').onclick = async () => {
  try{
    $('scanMeta').textContent='Executando probes defensivos…'; $('findings').innerHTML=''; $('regression').textContent='';
    const headers=JSON.parse($('headers').value||'{}');
    const scan=await api('/api/scans',{method:'POST',body:JSON.stringify({target_id:Number($('targetSelect').value),headers,categories:[]})});
    renderScan(scan); await refreshHistory();
  }catch(e){$('scanMeta').textContent=e.message;}
};

$('retestBtn').onclick=async()=>{
  if(!currentScan) return;
  try{
    const headers=JSON.parse($('headers').value||'{}');
    $('scanMeta').textContent=`Retestando a partir do scan #${currentScan.id}…`;
    const scan=await api(`/api/scans/${currentScan.id}/retest`,{method:'POST',body:JSON.stringify({headers})});
    renderScan(scan); await refreshHistory();
  }catch(e){$('scanMeta').textContent=e.message;}
};
$('jsonReportBtn').onclick=()=>currentScan&&downloadReport(`/api/scans/${currentScan.id}/report.json`,`aegis-scan-${currentScan.id}.json`);
$('sarifReportBtn').onclick=()=>currentScan&&downloadReport(`/api/scans/${currentScan.id}/report.sarif`,`aegis-scan-${currentScan.id}.sarif`);

async function boot(){
  try{
    const health=await api('/api/health'); $('health').textContent=`API online · ${health.version}`;
    presets=await api('/api/provider-presets');
    $('provider').innerHTML=Object.entries(presets).map(([k,v])=>`<option value="${k}">${escapeHtml(v.label)}</option>`).join('');
    $('provider').value='generic';
    $('authHint').textContent='Use headers efêmeros apenas ao executar o scan.';
    await refreshTargets(); await refreshHistory();
  }catch(e){ if(token) $('health').textContent='API offline'; }
}

(async()=>{ if(token){showApp(); await boot();} else showLogin(); })();
