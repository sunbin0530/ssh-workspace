'use strict';
const $ = id => document.getElementById(id);
const token = location.hash.slice(1) || sessionStorage.getItem('ssh-ui-token');
if (location.hash) { sessionStorage.setItem('ssh-ui-token', token); history.replaceState(null, '', '/'); }
let profiles = [], sessions = [], current = null, socket = null;
let activePrompt = null;
let answeringPrompt = false;
let pendingApprovals = [];
let refreshId = 0, appliedRefresh = 0;
let connecting = false;
let connectorState = 'online';
const stageLabels = {
  connecting:'正在连接 SSH', ssh_authenticating:'SSH 认证中', disconnected:'已断开',
  menu:'请在终端完成堡垒机认证', submitted:'堡垒机资产菜单', shell:'已进入 Shell',
};
const term = new Terminal({cursorBlink:true, fontFamily:'Consolas, monospace', fontSize:14, scrollback:5000, theme:{background:'#10131b'}});
const fit = new FitAddon.FitAddon(); term.loadAddon(fit); term.open($('terminal')); fit.fit();
function notice(text) {
  if (connectorState === 'online') $('message').textContent = text;
}
async function api(path, body) {
  const response = await fetch(path, {method:body ? 'POST':'GET', headers:{Authorization:'Bearer '+token, 'Content-Type':'application/json'}, body:body ? JSON.stringify(body):undefined});
  const value = await response.json(); if (!response.ok) throw new Error(value.error || '请求失败'); return value;
}
function send(value) {
  if (connectorState !== 'online' || socket?.readyState !== WebSocket.OPEN) return false;
  socket.send(JSON.stringify(value));
  return true;
}
function size() { fit.fit(); send({type:'resize',cols:term.cols,rows:term.rows}); }
function takeOverBastionLogin(session) {
  if (session?.stage !== 'menu' || session.human_active || socket?.readyState !== WebSocket.OPEN
      || socket.loginTakeoverRequested) return;
  socket.loginTakeoverRequested = true;
  send({type:'takeover', automatic:true});
}
new ResizeObserver(size).observe($('terminal'));
term.options.disableStdin = true;
term.onData(data => {
  const session = sessions.find(s=>s.session_id===current);
  if (session?.connected && socket?.humanOwned) send({type:'input',data});
});
function selectSession(id, attempt = sessions.find(session => session.session_id === id)?.connection_attempt) {
  if (current === id && socket?.connectionAttempt === attempt &&
      [WebSocket.CONNECTING, WebSocket.OPEN].includes(socket?.readyState)) return;
  if (activePrompt) clearPrompt();
  current = id;
  if (id) sessionStorage.setItem('ssh-ui-session', id);
  else sessionStorage.removeItem('ssh-ui-session');
  term.options.disableStdin = true;
  socket?.close();
  socket = null;
  term.reset();
  if (!id) return;
  const attached = new WebSocket(`ws://${location.host}/terminal/${id}`, [token]);
  attached.connectionAttempt = attempt;
  socket = attached;
  attached.binaryType = 'arraybuffer';
  attached.onopen = () => {
    if (socket !== attached) return;
    size();
    takeOverBastionLogin(sessions.find(session => session.session_id === current));
  };
  attached.onmessage = event => {
    if (socket !== attached) return;
    if (event.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(event.data));
    } else {
      const data = JSON.parse(event.data);
      if (data.reset) term.reset();
      if (data.error) notice(data.error);
      if (data.control) {
        attached.humanOwned = data.control === 'human';
        term.options.disableStdin = !attached.humanOwned || connectorState !== 'online';
        if (attached.humanOwned) {
          term.focus();
          const stage = sessions.find(session => session.session_id === current)?.stage;
          notice(stage === 'menu' ? '已人工接管，请按终端提示完成堡垒机认证。' : '已人工接管，可直接在终端输入。');
        } else {
          notice('已交还 Agent。目标 Shell 就绪后，Agent 会先核对主机名和 IP。');
        }
        appliedRefresh = ++refreshId;
        void refresh();
      }
    }
  };
  attached.onclose = () => {
    if (socket === attached && sessions.find(s=>s.session_id===current)?.stage !== 'disconnected') {
      attached.humanOwned = false;
      term.options.disableStdin = true;
      notice('终端视图已断开，可点击会话重新附着；SSH 是否存活请看会话状态。');
    }
  };
}
async function refresh() {
  if (connectorState === 'closing' || connectorState === 'closed') return;
  const id = ++refreshId;
  try {
    const [updatedSessions, prompts] = await Promise.all([api('/api/sessions'), api('/api/prompts')]);
    if (id < appliedRefresh) return;
    appliedRefresh = id;
    if (connectorState === 'offline') {
      connectorState = 'online';
      notice('');
    }
    const previousStage = sessions.find(s=>s.session_id===current)?.stage;
    sessions = updatedSessions;
    if (!sessions.some(session => session.session_id === current)) {
      const saved = sessionStorage.getItem('ssh-ui-session');
      const available = sessions.filter(session => !session.window_closed);
      const preferred = available.find(session => session.session_id === saved)
        || available.find(session => session.session_id === prompts[0]?.session_id)
        || available.find(session => session.connected)
        || available[0];
      if (preferred || current) selectSession(preferred?.session_id ?? null);
    } else {
      const selected = sessions.find(session => session.session_id === current);
      if (socket && socket.connectionAttempt !== selected.connection_attempt) {
        selectSession(current, selected.connection_attempt);
      }
    }
    const pending = prompts.filter(prompt => sessions.some(session =>
      session.session_id === prompt.session_id && session.stage !== 'disconnected'));
    updateApprovalButton(pending);
    showPrompt(pending);
    renderSessions(pending);
    const selected = sessions.find(session => session.session_id === current);
    takeOverBastionLogin(selected);
    if (previousStage === 'shell' && selected?.stage === 'submitted') {
      notice('目标 Shell 已结束，堡垒机仍连接。请接管终端重新选机，再交还 Agent。');
    } else if (previousStage === 'submitted' && selected?.stage === 'shell') {
      notice('已进入目标 Shell，操作完成后点击「交还 Agent」。');
    } else if (previousStage && previousStage !== 'disconnected' && selected?.stage === 'disconnected') {
      notice('SSH 已断开，终端历史仅供查看。点击「重新连接」可在此会话重新登录。');
    }
  } catch (error) {
    if (id < appliedRefresh) return;
    appliedRefresh = id;
    if (error instanceof TypeError) updateConnectorState('offline');
    else notice(error.message);
  }
}
function renderSessions(pending = []) {
    const online = connectorState === 'online';
    const sessionStage = session => connectorState === 'closed' ? '已断开'
      : online ? stageLabels[session.stage] || session.stage : '状态待确认';
    const nav=$('sessions'); nav.replaceChildren();
    for (const session of sessions) {
      const row = document.createElement('div');
      row.className = 'session-row';
      const b = document.createElement('button');
      b.textContent = `${session.name} · ${session.session_id.slice(0,6)}\n${sessionStage(session)}${online && session.human_active?' · 人工接管':''}${pending.some(p=>p.session_id===session.session_id)?' · 待处理':''}`;
      b.className = session.session_id === current ? 'active' : '';
      b.disabled = !online;
      b.onclick = async () => {
        selectSession(session.session_id);
        notice('');
        await sessionAction(session.session_id, 'select');
      };
      row.append(b);
      if (online && session.stage === 'disconnected') {
        const remove = document.createElement('button');
        remove.textContent = '删除';
        remove.setAttribute('aria-label', `删除会话 ${session.name} ${session.session_id.slice(0,6)}`);
        remove.onclick = async () => {
          if (!confirm(`删除本机会话记录「${session.name} · ${session.session_id.slice(0,6)}」？此会话的终端历史和任务结果会一起移除。`)) return;
          if (await sessionAction(session.session_id, 'remove')) notice('已删除本机会话记录。');
        };
        row.append(remove);
      }
      nav.append(row);
    }
    const session=sessions.find(s=>s.session_id===current);
    $('title').textContent=session ? `${session.username}@${session.host}` : '请选择连接配置';
    const targetStatus = session?.human_active ? '人工操作中'
      : session?.verified_host
      ? `当前主机 ${session.verified_host.hostname} (${session.verified_host.addresses.join(', ')})`
      : session?.target_confirmed ? 'Agent 已接管 · 等待核对主机'
      : session?.stage === 'shell' ? '等待完成交接' : '等待进入目标主机';
    $('status').textContent = online
      ? (session ? `${session.session_id} · ${sessionStage(session)} · ${targetStatus}` : '尚未连接')
      : {closing:'连接器正在退出', closed:'连接器已退出', offline:'连接器不可达 · 会话状态待确认'}[connectorState];
    for (const control of ['profiles', 'edit', 'new', 'quit']) $(control).disabled = !online;
    $('connect').disabled = !online || connecting;
    $('takeover').disabled=!online || !session?.connected || session.human_active;
    $('release').disabled=!online || !session?.connected || !socket?.humanOwned;
    $('release').textContent = session?.human_active ? '交还 Agent'
      : session?.target_confirmed ? 'Agent 已接管' : '交还 Agent';
    term.options.disableStdin = !online || !session?.connected || !socket?.humanOwned;
    const keepaliveEnabled = Boolean(session?.shell_keepalive);
    $('keepalive').textContent = keepaliveEnabled ? '关闭 Shell 保活' : '开启 Shell 保活';
    $('keepalive').setAttribute('aria-pressed', String(keepaliveEnabled));
    $('keepalive').disabled = !online || !session || (!keepaliveEnabled && !session.verified_host);
    $('share').disabled=!online || session?.stage !== 'submitted' || session.human_active;
    $('disconnect').disabled=!online || !session || session.stage === 'disconnected';
    $('reconnect').hidden = !online || session?.stage !== 'disconnected';
    $('reconnect').disabled = !online || connecting;
}
function updateConnectorState(state) {
  connectorState = state;
  appliedRefresh = ++refreshId;
  if (activePrompt) clearPrompt();
  $('pending-approval').hidden = true;
  $('profile-dialog').close();
  if (state === 'closed') {
    clearInterval(refreshTimer);
    const attached = socket;
    socket = null;
    attached?.close();
    sessionStorage.removeItem('ssh-ui-session');
  }
  renderSessions();
  $('message').textContent = {
    closing:'正在断开 SSH 会话并退出连接器。',
    closed:'SSH 会话已断开，终端历史仅供查看。可以关闭此页面。',
    offline:'暂时无法连接本机服务，正在重试。',
    online:'',
  }[state];
}
function clearPrompt() {
  activePrompt = null;
  $('prompt-secret').value = '';
  $('prompt-share').value = '';
  $('session-prompt').close();
  $('auth-panel').hidden = true;
  $('session-prompt').append($('prompt-form'));
}
function updateApprovalButton(prompts) {
  pendingApprovals = prompts.filter(prompt => prompt.kind === 'approval');
  $('pending-approval').hidden = pendingApprovals.length === 0;
  $('pending-approval').textContent = `待审批命令 (${pendingApprovals.length}) · 点击查看`;
}
function showPrompt(prompts) {
  const prompt = prompts.find(item => item.session_id === current);
  if (activePrompt && activePrompt.id === prompt?.id) return;
  if (activePrompt) clearPrompt();
  if (!prompt || answeringPrompt || $('profile-dialog').open) return;
  activePrompt = prompt;
  $('prompt-title').textContent = prompt.title;
  $('prompt-session').textContent = `${prompt.name} · ${prompt.session_id}`;
  $('prompt-content').textContent = prompt.kind === 'share' ? '请核对将共享给 Agent 的菜单文本。' : prompt.content;
  $('prompt-error').textContent = '';
  $('prompt-secret-label').hidden = prompt.kind !== 'secret';
  $('prompt-secret').required = prompt.kind === 'secret';
  $('prompt-share-label').hidden = prompt.kind !== 'share';
  $('prompt-share').value = prompt.kind === 'share' ? prompt.content : '';
  $('prompt-accept').textContent = prompt.kind === 'approval' ? '确认执行' : '确认';
  if (prompt.kind === 'secret' || prompt.kind === 'approval') {
    $('auth-panel').append($('prompt-form'));
    $('auth-panel').hidden = false;
  } else {
    $('session-prompt').showModal();
    $('prompt-cancel').focus();
  }
}
$('pending-approval').onclick = () => {
  const prompt = pendingApprovals.find(item => item.session_id === current) || pendingApprovals[0];
  if (!prompt) return;
  $('profile-dialog').close();
  selectSession(prompt.session_id);
  showPrompt([prompt]);
  $('prompt-form').scrollIntoView({block:'nearest'});
  $('prompt-accept').focus();
};
async function answerPrompt(approved) {
  if (!activePrompt || answeringPrompt) return;
  answeringPrompt = true;
  const prompt = activePrompt;
  const fields = {secret:'prompt-secret', share:'prompt-share'};
  const value = fields[prompt.kind] ? $(fields[prompt.kind]).value : '';
  try {
    await api('/api/prompt-answer', {session_id:prompt.session_id, prompt_id:prompt.id, approved, value:approved ? value : ''});
    updateApprovalButton(pendingApprovals.filter(item => item.id !== prompt.id));
    if (activePrompt === prompt) clearPrompt();
  } catch(error) {
    if (activePrompt === prompt) $('prompt-error').textContent = error.message;
  } finally {
    answeringPrompt = false;
  }
}
$('prompt-form').onsubmit = event => { event.preventDefault(); answerPrompt(true); };
$('prompt-cancel').onclick = () => answerPrompt(false);
$('session-prompt').oncancel = event => { event.preventDefault(); answerPrompt(false); };
async function loadProfiles(){profiles=await api('/api/profiles'); const selected=$('profiles').value; $('profiles').replaceChildren(); for(const p of profiles){const o=document.createElement('option');o.value=p.id;o.textContent=p.name;$('profiles').append(o);}if(profiles.some(p=>p.id===selected))$('profiles').value=selected;}
async function connect(path, body) {
  if (connectorState !== 'online' || connecting) return;
  connecting = $('connect').disabled = $('reconnect').disabled = true;
  try {
    const result = await api(path, body);
    if (connectorState !== 'online') return;
    appliedRefresh = ++refreshId;
    selectSession(result.session_id, result.connection_attempt);
    notice('请在此页面完成登录。');
  } catch(error) { notice(error.message); }
  finally {
    connecting = false;
    $('connect').disabled = connectorState !== 'online';
    await refresh();
  }
}
$('connect').onclick = () => {
  const profileId = $('profiles').value;
  if (profileId) connect('/api/connect', {profile_id:profileId});
};
$('reconnect').onclick = () => {
  if (current) connect('/api/action', {session_id:current, action:'reconnect'});
};
$('takeover').onclick = () => {
  const session = sessions.find(s => s.session_id === current);
  if (session?.active_job_id && !confirm('接管会使当前 Agent 任务结果标记为未知，确认接管？')) return;
  if (!send({type:'takeover'})) notice('终端视图未连接，请点击左侧会话重新附着。');
};
$('release').onclick = () => {
  if (!send({type:'release'})) notice('终端视图未连接，请点击左侧会话重新附着。');
};
async function sessionAction(sessionId, action, details = {}) {
  if (connectorState !== 'online') return false;
  try {
    await api('/api/action', {session_id:sessionId,action,...details});
    await refresh();
    return true;
  } catch(error) { notice(error.message); return false; }
}
for(const action of ['share','disconnect'])$(action).onclick=()=>sessionAction(current, action);
$('keepalive').onclick = async () => {
  const session = sessions.find(item => item.session_id === current);
  if (!session) return;
  const enabled = !session.shell_keepalive;
  if (await sessionAction(session.session_id, 'keepalive', {enabled}) && current === session.session_id) {
    notice(enabled ? 'Shell 保活已开启，空闲满 60 秒时发送冒号。' : 'Shell 保活已关闭。');
  }
};
$('quit').onclick = async () => {
  if (connectorState !== 'online' || !confirm('将断开此连接器的全部 SSH 会话，并停止本机服务。确认退出？')) return;
  updateConnectorState('closing');
  try {
    await api('/api/shutdown', {});
    updateConnectorState('closed');
  } catch (error) {
    updateConnectorState(error instanceof TypeError ? 'offline' : 'online');
    notice(error.message);
    await refresh();
  }
};
function edit(profile){const form=$('profile-form');form.reset();for(const [key,value] of Object.entries(profile||{}))if(form.elements.namedItem(key))form.elements.namedItem(key).value=value; form.elements.namedItem('id').readOnly=Boolean(profile);$('profile-dialog').showModal();}
$('new').onclick=()=>edit(null);$('edit').onclick=()=>edit(profiles.find(p=>p.id===$('profiles').value));$('cancel-edit').onclick=()=>$('profile-dialog').close();
$('profile-form').onsubmit=async event=>{event.preventDefault();const data=Object.fromEntries(new FormData(event.target));data.port=Number(data.port);try{await api('/api/profiles',data);$('profile-dialog').close();await loadProfiles();$('profiles').value=data.id;}catch(e){notice(e.message);}};
const refreshTimer = setInterval(refresh,1500);
loadProfiles().then(refresh).catch(error => {
  if (connectorState === 'closing' || connectorState === 'closed') return;
  if (error instanceof TypeError) updateConnectorState('offline');
  else notice(error.message);
});
