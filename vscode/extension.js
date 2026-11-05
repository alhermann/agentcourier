// Shows a notice when an agentwire message arrives for this window's Copilot session.
// It only sees sender and recipient names; message text never passes through here.
const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PROMPT = 'Check my agentwire inbox with wire_inbox and show me the new messages.';

let proc;
let stopped = false;
let unread = 0;
let status;

function program() {
  const configured = vscode.workspace.getConfiguration('agentwire').get('path');
  if (configured) return configured;
  const local = path.join(os.homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'agentwire.exe' : 'agentwire');
  return fs.existsSync(local) ? local : 'agentwire';
}

// Same rule as agentwire's own naming: lowercase ASCII, other characters become single dashes.
function slug(s) {
  let out = '';
  for (const ch of s.toLowerCase()) {
    const c = /[a-z0-9._]/.test(ch) ? ch : '-';
    if (!(c === '-' && out.endsWith('-'))) out += c;
  }
  return out.replace(/^-+|-+$/g, '').slice(0, 40);
}

function isMine(to, about) {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) return /^copilot(-\d+)?$/.test(to) || (about || '').startsWith('VS Code Copilot');
  const name = 'copilot-' + slug(folder.name);
  return to === name || new RegExp('^' + name.replace(/\./g, '\\.') + '-\\d+$').test(to) || about === 'VS Code Copilot, project ' + folder.name;
}

function render() {
  status.text = unread > 0 ? `$(mail) agentwire ${unread}` : '$(mail) agentwire';
  status.tooltip = unread > 0 ? `${unread} new agentwire message(s) for this window. Click to read them in Copilot Chat.` : 'agentwire: no new messages';
  status.backgroundColor = unread > 0 ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
}

async function openInbox() {
  try {
    await vscode.commands.executeCommand('workbench.action.chat.open', { query: PROMPT, mode: 'agent' });
  } catch {
    await vscode.commands.executeCommand('workbench.action.chat.open', PROMPT);
  }
}

function onEvent(ev) {
  const auto = vscode.workspace.getConfiguration('agentwire').get('autoRead', true);
  if (ev.ev === 'unread') {
    unread = Object.entries(ev.unread || {}).filter(([to, v]) => isMine(to, v.about)).reduce((n, [, v]) => n + v.count, 0);
    if (auto && unread > 0) wake();
  } else if (ev.ev === 'arrived' && isMine(ev.to, ev.about)) {
    unread += 1;
    const what = ev.file ? 'file' : 'message';
    if (auto) {
      vscode.window.setStatusBarMessage(`agentwire: new ${what} from ${ev.from}`, 8000);
      wake();
    } else {
      vscode.window.showInformationMessage(`agentwire: new ${what} from ${ev.from}`, 'Show in Copilot Chat').then((c) => {
        if (c) openInbox();
      });
    }
  } else if (ev.ev === 'read' && isMine(ev.to)) {
    unread = 0;
  }
  render();
}

// Several messages in quick succession wake Copilot once; it reads them all with wire_inbox.
let wakeTimer;
function wake() {
  clearTimeout(wakeTimer);
  wakeTimer = setTimeout(() => {
    if (unread > 0) openInbox();
  }, 3000);
}

function start() {
  if (stopped) return;
  proc = cp.spawn(program(), ['watch'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
  let buf = '';
  proc.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      try {
        onEvent(JSON.parse(line));
      } catch {}
    }
  });
  proc.on('error', () => {});
  proc.on('exit', () => setTimeout(start, 5000));
}

function activate(context) {
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = 'agentwire.openInbox';
  render();
  status.show();
  context.subscriptions.push(status, vscode.commands.registerCommand('agentwire.openInbox', () => {
    openInbox();
  }));
  start();
}

function deactivate() {
  stopped = true;
  if (proc) proc.kill();
}

module.exports = { activate, deactivate };
