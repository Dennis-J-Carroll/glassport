"""
console_html.py — the Glassport Console frontend, one self-contained
HTML document. Lives in a module constant so `pip install .` ships it
with zero packaging configuration and the page can never 404.

Design constraints, all deliberate:
  * No external requests of any kind (fonts, CDNs, analytics). The
    console must work air-gapped, and a security tool whose UI phones
    home would be its own finding. System monospace + CSS does the CRT.
  * Everything the server sends is treated as hostile: session logs
    carry attacker-controlled strings (tool names, hosts, snippets).
    All dynamic content lands in the DOM via textContent or esc();
    innerHTML only ever receives escaped or constant markup.
  * Same ViewModel as the curses TUI, same keyboard dialect (j/k, /,
    f, d, a, tab) extended for the web (1-9 tabs, x grid, e export).
"""

CONSOLE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>glassport console</title>
<style>
:root{
  --bg:#050805; --fg:#39ff6e; --fg-dim:#1d8f44; --fg-faint:#116230;
  --hot:#ff4444; --warn:#ffd24a; --info:#39ff6e; --sel:#0f2417;
  --panel:#081208; --border:#1d8f44;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg); color:var(--fg);
  font:13px/1.45 "DejaVu Sans Mono","Liberation Mono",Menlo,Consolas,monospace;
  overflow:hidden; text-shadow:0 0 6px rgba(57,255,110,.35);
}
/* CRT dressing: scanlines + vignette + flicker */
body::after{
  content:""; position:fixed; inset:0; pointer-events:none; z-index:99;
  background:repeating-linear-gradient(0deg,
    rgba(0,0,0,.22) 0 1px, transparent 1px 3px);
  mix-blend-mode:multiply;
}
body::before{
  content:""; position:fixed; inset:0; pointer-events:none; z-index:98;
  background:radial-gradient(ellipse at center,
    transparent 60%, rgba(0,0,0,.55) 100%);
}
@keyframes flicker{0%,100%{opacity:1}97%{opacity:1}98%{opacity:.92}}
#app{display:flex;flex-direction:column;height:100%;
     animation:flicker 7s infinite}
header{
  background:var(--fg); color:#031007; padding:2px 8px;
  display:flex; gap:14px; white-space:nowrap; overflow:hidden;
  text-shadow:none; font-weight:bold;
}
header .live{color:#a00}
#bar2{background:var(--panel);border-bottom:1px solid var(--border);
      padding:1px 8px;display:flex;gap:14px;color:var(--fg-dim);
      white-space:nowrap;overflow:hidden}
#tabs{padding:1px 8px;border-bottom:1px solid var(--fg-faint);
      display:flex;gap:6px;overflow:hidden;color:var(--fg-dim)}
#tabs .tab{cursor:pointer;padding:0 4px}
#tabs .tab.active{background:var(--sel);color:var(--fg);
      outline:1px solid var(--border)}
main{flex:1;display:flex;min-height:0}
#grid{flex:1;display:none;grid-template-columns:1fr 1fr;
      grid-template-rows:1fr 1fr;gap:4px;padding:4px;min-height:0}
#grid.on{display:grid}
#single{flex:1;display:flex;min-width:0;min-height:0}
#single.off{display:none}
#timeline{flex:1;overflow-y:auto;padding:2px 8px;min-width:0}
#side{width:42%;max-width:560px;border-left:1px solid var(--border);
      background:var(--panel);overflow-y:auto;padding:4px 8px;
      display:none;min-width:0}
#side.open{display:block}
#findings{border-top:1px solid var(--border);max-height:9.5em;
      overflow-y:auto;padding:2px 8px;background:var(--panel)}
footer{background:var(--panel);border-top:1px solid var(--fg-faint);
      color:var(--fg-dim);padding:1px 8px;white-space:nowrap;
      overflow:hidden}
.row{white-space:pre;cursor:default}
.row.sev3{color:var(--hot);font-weight:bold}
.row.sev1,.row.sev2{color:var(--warn)}
.row.info{color:var(--info);font-weight:bold}
.row.dim{color:var(--fg-faint)}
.row.sel{background:var(--sel);outline:1px solid var(--fg-faint)}
.row.hit{text-decoration:underline}
.frow{cursor:pointer}
.pane{border:1px solid var(--border);background:var(--panel);
      overflow:hidden;display:flex;flex-direction:column;min-height:0}
.pane .ptitle{background:var(--fg-faint);color:var(--fg);
      padding:0 6px;white-space:nowrap;overflow:hidden}
.pane .pbody{flex:1;overflow-y:auto;padding:2px 6px}
.pane.focus{border-color:var(--fg)}
h3{color:var(--fg);border-bottom:1px solid var(--fg-faint);
   margin:6px 0 3px;font-size:13px;text-transform:uppercase}
.gauge{display:block;margin:6px auto}
.heat{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
      gap:6px;margin:6px 0}
.cell{border:1px solid var(--fg-faint);padding:4px 6px;overflow:hidden}
.cell.h0{border-color:var(--fg-faint)}
.cell.h1,.cell.h2{border-color:var(--warn);color:var(--warn)}
.cell.h3{border-color:var(--hot);color:var(--hot);font-weight:bold}
.cell .big{font-size:17px}
button,.btn{background:var(--panel);color:var(--fg);
      border:1px solid var(--border);font:inherit;cursor:pointer;
      padding:2px 8px;margin:2px 4px 2px 0;text-shadow:none}
button:hover{background:var(--sel)}
a{color:var(--fg)}
#overlay{position:fixed;inset:6% 12%;background:var(--bg);
      border:1px solid var(--fg);z-index:50;display:none;
      flex-direction:column;box-shadow:0 0 40px rgba(57,255,110,.25)}
#overlay.open{display:flex}
#overlay .otitle{background:var(--fg);color:#031007;padding:2px 8px;
      text-shadow:none;font-weight:bold}
#overlay .obody{flex:1;overflow:auto;padding:6px 10px;white-space:pre-wrap}
#picker{padding:12px;overflow-y:auto}
#picker .sess{cursor:pointer;padding:2px 6px}
#picker .sess:hover{background:var(--sel)}
#picker .sess .lv{color:var(--hot);font-weight:bold}
.md h2{font-size:14px;color:var(--fg);margin:8px 0 4px}
.md h3{text-transform:none;border:none}
.md li{margin-left:18px}
.md code{background:var(--sel);padding:0 3px}
kbd{border:1px solid var(--fg-faint);padding:0 4px;margin:0 2px}
.mut{color:var(--fg-dim)}
</style>
</head>
<body>
<div id="app">
  <header>
    <span>GLASSPORT CONSOLE</span>
    <span id="h-title" class="mut"></span>
    <span id="h-live"></span>
    <span id="h-declared"></span>
    <span id="h-frames"></span>
  </header>
  <div id="bar2">
    <span id="c-fab"></span><span id="c-vio"></span>
    <span id="c-srv"></span><span id="c-gate"></span>
    <span id="c-tail"></span><span id="c-conn"></span>
  </div>
  <div id="tabs"></div>
  <main>
    <div id="picker"></div>
    <div id="single" class="off">
      <div id="timeline" tabindex="0"></div>
      <div id="side"></div>
    </div>
    <div id="grid"></div>
  </main>
  <div id="findings"></div>
  <footer id="foot"></footer>
</div>
<div id="overlay">
  <div class="otitle" id="o-title"></div>
  <div class="obody" id="o-body"></div>
</div>
<script>
"use strict";
/* ── tiny DOM + escaping helpers — hostile data everywhere ───── */
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const el=(tag,cls,text)=>{const e=document.createElement(tag);
  if(cls)e.className=cls; if(text!==undefined)e.textContent=text; return e;};

/* ── state ───────────────────────────────────────────────────── */
const S={
  ws:null, connected:false,
  sessions:[],          // /api/sessions listing
  tabs:[],              // attached session names, in order
  active:-1,            // index into tabs
  vms:{},               // name -> vm payload
  grid:false,
  panel:null,           // "drift"|"audit"|"heatmap"|null  (side panel)
  overlay:null,         // "sarif"|"advisory"|"export"|"help"|null
  follow:true, selected:-1, search:"", searching:false,
};

/* ── websocket ───────────────────────────────────────────────── */
function connect(){
  const ws=new WebSocket(`ws://${location.host}/ws`);
  S.ws=ws;
  ws.onopen=()=>{S.connected=true; renderBars();
    S.tabs.forEach(n=>ws.send(JSON.stringify({attach:n})));};
  ws.onclose=()=>{S.connected=false; renderBars();
    setTimeout(connect,1500);};
  ws.onmessage=ev=>{
    let m; try{m=JSON.parse(ev.data);}catch(e){return;}
    if(m.type==="vm"){S.vms[m.session]=m.vm; render();}
  };
}
function attach(name){
  if(!S.tabs.includes(name)){
    S.tabs.push(name);
    if(S.connected)S.ws.send(JSON.stringify({attach:name}));
  }
  S.active=S.tabs.indexOf(name);
  S.follow=true; S.selected=-1;
  render();
}
function detach(i){
  const name=S.tabs[i]; if(name===undefined)return;
  S.tabs.splice(i,1); delete S.vms[name];
  if(S.connected)S.ws.send(JSON.stringify({detach:name}));
  S.active=Math.min(S.active,S.tabs.length-1);
  render();
}

/* ── session picker ──────────────────────────────────────────── */
async function refreshSessions(){
  try{
    const r=await fetch("/api/sessions");
    S.sessions=await r.json();
  }catch(e){S.sessions=[];}
  renderPicker();
}
setInterval(refreshSessions,5000);

/* ── rendering ───────────────────────────────────────────────── */
const cur=()=>S.vms[S.tabs[S.active]];

function rowClass(r,idx,hits){
  let c="row";
  if(r.severity>=3)c+=" sev3";
  else if(r.severity>=1)c+=" sev"+r.severity;
  else if(r.is_info)c+=" info";
  if(idx===S.selected)c+=" sel";
  if(hits&&hits.has(idx))c+=" hit";
  return c;
}
function searchHits(vm){
  if(!S.search)return null;
  const q=S.search.toLowerCase(), h=new Set();
  vm.rows.forEach((r,i)=>{if(r.text.toLowerCase().includes(q))h.add(i);});
  return h;
}
function renderTimeline(){
  const vm=cur(), tl=$("timeline");
  tl.replaceChildren();
  if(!vm)return;
  const hits=searchHits(vm);
  if(vm.collapsed_rows>0)
    tl.appendChild(el("div","row dim",
      `… ${vm.collapsed_rows} earlier frame(s) collapsed …`));
  vm.rows.forEach((r,i)=>{
    const d=el("div",rowClass(r,i,hits),r.text);
    d.onclick=()=>{S.selected=i;S.follow=false;render();};
    tl.appendChild(d);
  });
  if(S.follow)tl.scrollTop=tl.scrollHeight;
  else{const s=tl.querySelector(".sel");if(s)s.scrollIntoView({block:"nearest"});}
}
function renderFindings(){
  const vm=cur(), f=$("findings");
  f.replaceChildren();
  if(!vm||!vm.findings.length)return;
  vm.findings.forEach(fd=>{
    const d=el("div",rowClass(fd,-1,null)+" frow",fd.text);
    d.onclick=()=>{
      S.selected=fd.row_index-(vm.first_row_index||0);
      S.follow=false;render();};
    f.appendChild(d);
  });
  if(vm.more_findings>0)
    f.appendChild(el("div","row dim",`… and ${vm.more_findings} more`));
}
function renderBars(){
  const vm=cur();
  $("h-title").textContent=vm?vm.title:"no session";
  $("h-live").textContent=vm?(vm.live?"LIVE ▮":"IDLE"):"";
  $("h-live").className=vm&&vm.live?"live":"";
  $("h-declared").textContent=vm?("declared: "+
    (vm.declared.join(", ")||"—")):"";
  $("h-frames").textContent=vm?("frames "+vm.counters.frames):"";
  $("c-fab").textContent=vm?("fabricated "+vm.counters.fabricated):"";
  $("c-vio").textContent=vm?("violations "+vm.counters.violations):"";
  $("c-srv").textContent=vm?("server-req "+vm.counters.server_requests):"";
  let g=vm?("gate: "+(vm.gate_on?"on":"off")):"";
  if(vm&&vm.gate_override!==null&&vm.gate_override!==undefined)
    g+=" · override: "+(vm.gate_override?"enforce":"DISABLED");
  $("c-gate").textContent=g;
  $("c-tail").textContent=vm&&vm.tail_only?"TAIL-ONLY":"";
  $("c-conn").textContent=S.connected?"ws ●":"ws ○ reconnecting…";
}
function renderTabs(){
  const t=$("tabs"); t.replaceChildren();
  S.tabs.forEach((n,i)=>{
    const d=el("span","tab"+(i===S.active?" active":""),
      `${i+1}:${n}`);
    d.onclick=()=>{S.active=i;render();};
    t.appendChild(d);
  });
  if(S.tabs.length)
    t.appendChild(el("span","mut","  (0: picker · x: grid)"));
}
function renderPicker(){
  const p=$("picker");
  const show=S.active<0||!S.tabs.length;
  p.style.display=show?"block":"none";
  $("single").className=show||S.grid?"off":"";
  if(!show)return;
  p.replaceChildren();
  p.appendChild(el("h3",null,"sessions"));
  if(!S.sessions.length)
    p.appendChild(el("div","mut","no sessions — wrap a server first"));
  S.sessions.forEach(s=>{
    const d=el("div","sess");
    const lv=el("span","lv",s.live?"LIVE ▮ ":"       ");
    d.appendChild(lv);
    d.appendChild(document.createTextNode(
      `${s.name}  (${s.frames} frames)`));
    d.onclick=()=>attach(s.name);
    p.appendChild(d);
  });
}
function renderGrid(){
  const g=$("grid");
  g.className=S.grid?"on":"";
  if(!S.grid){g.replaceChildren();return;}
  $("single").className="off";
  g.replaceChildren();
  S.tabs.slice(0,4).forEach((n,i)=>{
    const vm=S.vms[n];
    const pane=el("div","pane"+(i===S.active?" focus":""));
    pane.appendChild(el("div","ptitle",
      `${i+1}:${n} ${vm?(vm.live?"· LIVE":"· idle"):""} ` +
      (vm?`· fab ${vm.counters.fabricated} · vio ${vm.counters.violations}`:"")));
    const body=el("div","pbody");
    if(vm)vm.rows.slice(-40).forEach((r,j)=>
      body.appendChild(el("div",rowClass(r,-1,null),r.text)));
    pane.appendChild(body);
    pane.onclick=()=>{S.active=i;render();};
    g.appendChild(pane);
    body.scrollTop=body.scrollHeight;
  });
}
function renderFoot(){
  const f=$("foot");
  if(S.searching||S.search){
    const vm=cur(); const n=vm?(searchHits(vm)||new Set()).size:0;
    f.textContent=`/${S.search}${S.searching?"▏":""}  (${n} match`+
      `${n===1?"":"es"})${S.searching?"":" · n/N jump · esc clear"}`;
    f.style.color="var(--warn)";
  }else{
    f.style.color="";
    f.textContent=" j/k move · / search · f follow · d drift · a audit"+
      " · h heatmap · s sarif · v advisory · e export · x grid"+
      " · 1-9 tabs · 0 picker · w close tab · ? help";
  }
}
function render(){
  renderBars();renderTabs();renderPicker();
  if(S.grid){renderGrid();}
  else if(S.active>=0){
    $("single").className="";$("grid").className="";
    renderTimeline();
  }
  renderFindings();renderFoot();renderSide();
}

/* ── side panel: drift / audit / heatmap ─────────────────────── */
async function renderSide(){
  const side=$("side");
  side.className=S.panel?"open":"";
  if(!S.panel){side.replaceChildren();return;}
  const name=S.tabs[S.active];
  if(!name){side.replaceChildren();return;}
  if(S.panel==="drift"){
    side.replaceChildren(el("h3",null,"drift vs baseline"));
    try{
      const r=await fetch(`/api/drift?session=${encodeURIComponent(name)}`);
      (await r.json()).forEach(l=>{
        const c=l.severity>=3?"row sev3":l.severity>=1?"row sev1":"row dim";
        side.appendChild(el("div",c,l.text||" "));
      });
    }catch(e){side.appendChild(el("div","row dim","drift unavailable"));}
  }else if(S.panel==="audit"){
    side.replaceChildren(el("h3",null,"static audit"));
    try{
      const r=await fetch("/api/audit");
      const a=await r.json();
      if(!a.available){
        side.appendChild(el("div","mut",
          "no --audit path given at launch"));
      }else{
        side.appendChild(gauge(a.score,a.grade));
        side.appendChild(el("div","mut",
          `rubric v${a.rubric_version} · ${a.findings.length} finding(s)`));
        a.findings.forEach(f=>{
          const sev={critical:3,high:3,medium:2,low:1}[f.severity]||0;
          const c=sev>=3?"row sev3":sev>=1?"row sev1":"row dim";
          side.appendChild(el("div",c,
            `[${f.severity}] ${f.rule} — ${f.path}:${f.line}`+
            (f.count>1?` ×${f.count}`:"")));
        });
      }
    }catch(e){side.appendChild(el("div","row dim","audit unavailable"));}
    const vm=cur();
    side.appendChild(el("h3",null,"runtime findings"));
    if(vm)vm.findings.forEach(fd=>
      side.appendChild(el("div",rowClass(fd,-1,null),fd.text)));
  }else if(S.panel==="heatmap"){
    side.replaceChildren(el("h3",null,"per-tool risk"));
    const vm=cur();
    const heat=el("div","heat");
    (vm?vm.heatmap:[]).forEach(t=>{
      const c=el("div","cell h"+t.max_severity);
      c.appendChild(el("div","big",t.tool));
      c.appendChild(el("div",null,
        `${t.calls} call(s) · ${t.errors} err`+
        (t.fabricated?" · FABRICATED":"")));
      heat.appendChild(c);
    });
    side.appendChild(heat);
    if(!vm||!vm.heatmap.length)
      side.appendChild(el("div","mut","no tool calls yet"));
  }
}
function gauge(score,grade){
  const ns="http://www.w3.org/2000/svg";
  const svg=document.createElementNS(ns,"svg");
  svg.setAttribute("viewBox","0 0 120 70");
  svg.setAttribute("width","220");svg.setAttribute("class","gauge");
  const arc=(r,frac,color,w)=>{
    const a0=Math.PI,a1=Math.PI*(1-frac);
    const x0=60+r*Math.cos(a0),y0=62+r*Math.sin(a0)*-1-0;
    const p=document.createElementNS(ns,"path");
    const x1=60+r*Math.cos(a1),y1=62-r*Math.sin(a1);
    p.setAttribute("d",`M ${x0} ${62-r*Math.sin(a0)*-0} A ${r} ${r} 0 0 1 ${x1} ${y1}`);
    p.setAttribute("d",`M ${60-r} 62 A ${r} ${r} 0 0 1 ${x1} ${y1}`);
    p.setAttribute("fill","none");p.setAttribute("stroke",color);
    p.setAttribute("stroke-width",w);
    return p;
  };
  svg.appendChild(arc(50,1,"var(--fg-faint)",8));
  const col=score>=90?"var(--fg)":score>=70?"var(--warn)":"var(--hot)";
  svg.appendChild(arc(50,Math.max(0.001,score/100),col,8));
  const t=document.createElementNS(ns,"text");
  t.setAttribute("x","60");t.setAttribute("y","58");
  t.setAttribute("text-anchor","middle");t.setAttribute("fill",col);
  t.setAttribute("font-size","20");
  t.textContent=`${score} ${grade}`;
  svg.appendChild(t);
  return svg;
}

/* ── overlays: sarif / advisory / export / help ──────────────── */
async function openOverlay(kind){
  const name=S.tabs[S.active];
  const o=$("overlay"),body=$("o-body"),title=$("o-title");
  S.overlay=kind;o.className="open";body.replaceChildren();
  body.className="obody";
  if(kind==="help"){
    title.textContent=" keys — esc to close ";
    body.innerHTML=
      "<b>1-9</b> switch/attach tab   <b>0</b> session picker   "+
      "<b>w</b> close tab<br><b>j/k</b> move   <b>f</b> follow   "+
      "<b>/</b> search   <b>n/N</b> jump matches<br>"+
      "<b>d</b> drift panel   <b>a</b> audit panel   <b>h</b> heatmap<br>"+
      "<b>s</b> SARIF viewer   <b>v</b> advisory   <b>e</b> export menu<br>"+
      "<b>x</b> 2×2 grid   <b>Ctrl+L</b> redraw   <b>esc</b> close";
    return;
  }
  if(!name){body.textContent="attach a session first";return;}
  if(kind==="sarif"){
    title.textContent=` SARIF — ${name} — esc to close `;
    try{
      const r=await fetch(`/api/sarif?session=${encodeURIComponent(name)}`);
      const doc=await r.json();
      const run=doc.runs[0];
      const rules={};
      (run.tool.driver.rules||[]).forEach(x=>rules[x.id]=x);
      (run.results||[]).forEach(res=>{
        const lvl=res.level||"note";
        const c=lvl==="error"?"row sev3":lvl==="warning"?"row sev1":"row dim";
        const loc=(res.locations||[])[0];
        const where=loc?`${loc.physicalLocation.artifactLocation.uri}:`+
          `${loc.physicalLocation.region.startLine}`:"";
        body.appendChild(el("div",c,
          `[${lvl}] ${res.ruleId}  ${where}`));
        body.appendChild(el("div","mut",
          "   "+(res.message&&res.message.text||"")));
      });
      if(!(run.results||[]).length)
        body.appendChild(el("div","mut","no results — clean session"));
    }catch(e){body.textContent="sarif unavailable";}
  }else if(kind==="advisory"){
    title.textContent=` advisory — ${name} — esc to close `;
    try{
      const r=await fetch(`/api/advise?session=${encodeURIComponent(name)}`);
      const md=await r.text();
      const btn=el("button",null,"copy to clipboard");
      btn.onclick=()=>navigator.clipboard.writeText(md)
        .then(()=>btn.textContent="copied ✓");
      body.appendChild(btn);
      const div=el("div","md");
      div.innerHTML=mdRender(md);
      body.appendChild(div);
    }catch(e){body.textContent="advisory unavailable";}
  }else if(kind==="export"){
    title.textContent=" export — esc to close ";
    const q=encodeURIComponent(name);
    [["HTML report",`/api/report?session=${q}`],
     ["SARIF (runtime)",`/api/sarif?session=${q}`],
     ["Advisory markdown",`/api/advise?session=${q}`]]
    .forEach(([label,href])=>{
      const a=document.createElement("a");
      a.className="btn";a.textContent=label;a.href=href;
      a.target="_blank";a.style.display="inline-block";
      body.appendChild(a);
    });
  }
}
function closeOverlay(){S.overlay=null;$("overlay").className="";}
/* minimal markdown: escape FIRST, then transform — advisory text may
   quote hostile content; it must render inert */
function mdRender(md){
  return esc(md).split("\n").map(line=>{
    if(line.startsWith("## "))return `<h2>${line.slice(3)}</h2>`;
    if(line.startsWith("### "))return `<h3>${line.slice(4)}</h3>`;
    let l=line
      .replace(/\*\*([^*]+)\*\*/g,"<b>$1</b>")
      .replace(/`([^`]+)`/g,"<code>$1</code>")
      .replace(/^_(.*)_$/,"<i>$1</i>");
    if(l.startsWith("- "))return `<li>${l.slice(2)}</li>`;
    return l+"<br>";
  }).join("");
}

/* ── keyboard ────────────────────────────────────────────────── */
document.addEventListener("keydown",ev=>{
  if(ev.ctrlKey&&ev.key==="l"){ev.preventDefault();render();return;}
  if(ev.ctrlKey||ev.metaKey||ev.altKey)return;
  if(S.searching){
    if(ev.key==="Enter")S.searching=false;
    else if(ev.key==="Escape"){S.searching=false;S.search="";}
    else if(ev.key==="Backspace")S.search=S.search.slice(0,-1);
    else if(ev.key.length===1)S.search+=ev.key;
    ev.preventDefault();render();return;
  }
  if(ev.key==="Escape"){
    if(S.overlay){closeOverlay();return;}
    if(S.panel){S.panel=null;render();return;}
    if(S.search){S.search="";render();return;}
    return;
  }
  if(S.overlay)return;
  const vm=cur();
  switch(ev.key){
    case"/":S.searching=true;S.search="";render();break;
    case"n":case"N":{
      if(!vm||!S.search)break;
      const hits=[...(searchHits(vm)||[])].sort((a,b)=>a-b);
      if(!hits.length)break;
      const next=ev.key==="n"
        ?(hits.find(i=>i>S.selected)??hits[0])
        :([...hits].reverse().find(i=>i<S.selected)??hits[hits.length-1]);
      S.selected=next;S.follow=false;render();break;}
    case"j":if(vm){S.selected=Math.min((S.selected<0?vm.rows.length-1:S.selected)+1,
      vm.rows.length-1);S.follow=false;render();}break;
    case"k":if(vm){S.selected=Math.max((S.selected<0?vm.rows.length:S.selected)-1,0);
      S.follow=false;render();}break;
    case"f":S.follow=!S.follow;render();break;
    case"d":S.panel=S.panel==="drift"?null:"drift";render();break;
    case"a":S.panel=S.panel==="audit"?null:"audit";render();break;
    case"h":S.panel=S.panel==="heatmap"?null:"heatmap";render();break;
    case"s":openOverlay("sarif");break;
    case"v":openOverlay("advisory");break;
    case"e":openOverlay("export");break;
    case"?":openOverlay("help");break;
    case"x":S.grid=!S.grid;render();break;
    case"w":detach(S.active);break;
    case"0":S.active=-1;render();break;
    default:
      if(/^[1-9]$/.test(ev.key)){
        const i=+ev.key-1;
        if(i<S.tabs.length){S.active=i;S.grid=false;render();}
        else if(S.sessions[i-S.tabs.length])   /* attach next from list */
          attach(S.sessions[i-S.tabs.length].name);
      }
  }
});

/* ── boot ────────────────────────────────────────────────────── */
refreshSessions().then(()=>{ render(); });
connect();
</script>
</body>
</html>
"""
