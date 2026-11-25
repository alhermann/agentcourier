(() => {
  const root = document.documentElement, form = document.querySelector('.ask'), panes = document.querySelector('.panes'), steps = document.getElementById('steps');
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const tool = { copilot: 'Copilot', claude: 'Claude Code', codex: 'Codex' };
  const how = {
    claude: 'With the channels flag, the message appears in the running session.',
    codex: 'Codex reads it with courier_inbox. Tell it "check agentcourier".',
    copilot: 'VS Code shows a notice; one click asks Copilot to read it.'
  };
  const add = {
    claude: ['The flag is needed on every start, because channels are a research preview.', 'claude mcp add --scope user agentcourier -- agentcourier mcp --channel\nclaude --dangerously-load-development-channels server:agentcourier'],
    codex: ['In <code>~/.codex/config.toml</code>.', '[mcp_servers.agentcourier]\ncommand = "agentcourier"\nargs = ["mcp"]'],
    copilot: ['In your user <code>mcp.json</code> (Command Palette: MCP: Open User Configuration). Run <code>agentcourier vscode</code> once for message notices.', '{\n  "servers": {\n    "agentcourier": {\n      "type": "stdio",\n      "command": "agentcourier",\n      "args": ["mcp"]\n    }\n  }\n}']
  };
  const set = (k, v) => document.querySelectorAll(`[data-t="${k}"]`).forEach(e => { e.textContent = v; });
  const step = (title, note, code) => `<li><h3>${title}</h3>${note ? `<p>${note}</p>` : ''}<pre><code>${code}</code></pre></li>`;
  function show() {
    const { from: { value: f }, to: { value: t }, where: { value: w } } = form.elements;
    const here = w === 'here', me = `${f}-frontend`, you = `${t}-backend`;
    const addr = here ? you : `${you}@${w}`, back = here ? me : `${me}@${w === 'jana' ? 'max' : 'laptop'}`;
    const ask = `Ask ${w === 'jana' ? "Jana's agent" : w === 'server' ? `my ${tool[t]} on server` : you} which fields GET /orders returns.`;
    set('fromTool', tool[f]); set('toTool', tool[t]); set('fromName', me); set('toName', you); set('addr', addr); set('reply', back); set('ask', ask); set('how', how[t]);
    set('arrive', t === 'claude' ? `← agentcourier: ${back}` : t === 'copilot' ? `agentcourier: new message from ${back}` : `courier_inbox: message from ${back}`);
    set('pair', `${f === t ? `two ${tool[f]} sessions` : `${tool[f]} and ${tool[t]}`} ${here ? 'on one laptop' : w === 'server' ? 'on a laptop and a server' : 'on your machine and a colleague\'s'}`);
    const s = [step(here ? 'Install' : 'Install on both machines', '', 'pip install agentcourier')];
    if (here) [...new Set([f, t])].forEach(x => s.push(step(`Add it to ${tool[x]}`, ...add[x])));
    else {
      s.push(step(`Here, add it to ${tool[f]}`, ...add[f]));
      s.push(step(`${w === 'server' ? 'On the server' : "On Jana's machine"}, add it to ${tool[t]}`, ...add[t]));
      s.push(w === 'server'
        ? step('On the server, make a code', 'It works once, for 10 minutes.', 'agentcourier invite laptop')
        : step('On Jana\'s machine, make a code', 'It works once, for 10 minutes. Send it through a channel you trust.', 'agentcourier invite max'));
      s.push(step('Here, join', 'The address is how this machine reaches the other one, here through an SSH tunnel.', w === 'server'
        ? 'ssh -N -L 17312:127.0.0.1:7312 you@server\nagentcourier join agentcourier-… server 127.0.0.1:17312'
        : 'ssh -N -L 17312:127.0.0.1:7312 you@janas-machine\nagentcourier join agentcourier-… jana 127.0.0.1:17312'));
    }
    s.push(step('Say it', '', ask));
    steps.innerHTML = s.join('');
  }
  form.addEventListener('submit', e => e.preventDefault());
  form.addEventListener('change', () => {
    if (still) return show();
    panes.classList.add('swap');
    setTimeout(() => { show(); panes.classList.remove('swap'); }, 180);
  });
  if (still) { document.querySelectorAll('video').forEach(v => { v.removeAttribute('autoplay'); v.pause(); v.controls = true; }); return; }
  if (!('IntersectionObserver' in window)) return;
  root.classList.add('js');
  const groups = '.say .lead,.say .act,.ask,.pane,.setup h2,.setup .lead,.setup li,.row h2,.row p,.frag,.film h2,.film video,.faq h2,details,.close>*';
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('on'); io.unobserve(e.target); } }), { rootMargin: '0px 0px -6% 0px' });
  document.querySelectorAll(groups).forEach(e => {
    const i = [...e.parentNode.children].indexOf(e);
    e.classList.add('in'); e.style.setProperty('--d', `${Math.min(i, 6) * 80}ms`); io.observe(e);
  });
})();
