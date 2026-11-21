package eval

import (
	"encoding/json"
	"os"

	"topomap/internal/probe"
	"topomap/internal/sim"
)

// WriteHTML renders the interactive report page: the diamond graph at both
// device and interface level, fork widths and branch delays, and the raw
// probe records behind any node.
func WriteHTML(path string, sc *sim.Scenario, res *probe.Result, tr *TruthReport) error {
	payload := map[string]any{
		"scenario": sc.Name,
		"desc":     sc.Desc,
		"src":      sc.Src,
		"dest":     sc.Dest,
		"result":   res,
		"truth":    tr,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(htmlHead); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	_, err = f.WriteString(htmlTail)
	return err
}

const htmlHead = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>topomap — 多路径拓扑测绘</title>
<style>
:root{
  --bg:#0b0e14;--panel:#111722;--panel2:#0e1420;--line:#22304a;--line2:#1a2536;
  --fg:#e6edf7;--dim:#7f90ab;--acc:#4fa3ff;--acc2:#39d0a4;--warn:#e3b341;--bad:#f26d6d;
  --ok:#3fb950;--mono:"SF Mono",ui-monospace,Menlo,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--fg);font:13px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;overflow:hidden}
header{display:flex;align-items:center;gap:16px;padding:10px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0;font-size:16px;font-weight:650;letter-spacing:.2px}
h1 em{font-style:normal;color:var(--acc)}
.sub{color:var(--dim);font-size:12px}
.spacer{flex:1}
.seg{display:flex;border:1px solid var(--line);border-radius:7px;overflow:hidden}
.seg button{background:transparent;border:0;color:var(--dim);padding:5px 12px;font-size:12px;cursor:pointer}
.seg button.on{background:#1b2942;color:var(--fg)}
main{display:grid;grid-template-columns:minmax(0,1fr) 430px;height:calc(100vh - 53px)}
#stage{position:relative;overflow:auto;padding:18px 22px;background:
  radial-gradient(circle at 20% 10%,#111a29 0,transparent 55%),
  radial-gradient(circle at 85% 80%,#0f1a24 0,transparent 50%),
  var(--bg)}
#stage svg{display:block}
#side{border-left:1px solid var(--line);background:var(--panel);overflow:auto;padding:14px 16px}
h3{margin:16px 0 6px;font-size:12px;font-weight:600;color:var(--acc);text-transform:uppercase;letter-spacing:.8px}
h3:first-child{margin-top:0}
.kv{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid var(--line2);font-size:12px}
.kv b{font-variant-numeric:tabular-nums;font-family:var(--mono);font-weight:600}
.good{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.dim{color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:11px;margin:6px 0 10px}
th{color:var(--dim);font-weight:500;text-align:left;padding:3px 5px;border-bottom:1px solid var(--line)}
td{padding:3px 5px;border-bottom:1px solid var(--line2);font-family:var(--mono);font-size:10.5px;white-space:nowrap}
tr.sel td{background:#16233a}
.badge{display:inline-block;padding:0 6px;border-radius:8px;font-size:10px;background:#1b2740;color:var(--dim);margin-left:4px;font-family:var(--mono)}
.lbl{fill:var(--dim);font-size:9.5px;font-family:var(--mono)}
.node{cursor:pointer}
.node rect{fill:#141d2e;stroke:#283b5c;stroke-width:1.3;rx:7}
.node:hover rect{stroke:var(--acc)}
.node.sel rect{stroke:var(--acc);stroke-width:2.2}
.node text{fill:var(--fg);font-size:11px;pointer-events:none;font-family:var(--mono)}
.node .meta{fill:var(--dim);font-size:9px}
.node.unknown rect{stroke:var(--warn);stroke-dasharray:4 3}
.link{fill:none;stroke:#33507c;stroke-opacity:.75}
.link.gap{stroke:var(--warn);stroke-dasharray:5 4;stroke-opacity:.8}
.link.hot{stroke:var(--acc);stroke-opacity:1}
.linkg{transition:opacity .12s}
.dimlinks .linkg{opacity:.25}
.dimlinks .linkg.hot{opacity:1}
.anom{position:absolute;pointer-events:none}
.tip{position:fixed;pointer-events:none;z-index:20;background:#0f1621;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:11px;max-width:340px;box-shadow:0 8px 24px rgba(0,0,0,.5);display:none}
.tip b{color:var(--acc)}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px;color:var(--dim);font-size:11px}
.legend i{display:inline-block;width:22px;height:0;border-top:2px solid #33507c;vertical-align:middle;margin-right:5px}
.legend i.gap{border-top:2px dashed var(--warn)}
.lanes{width:100%;overflow-x:auto;margin-top:4px}
.rawbar{display:flex;gap:8px;align-items:center;margin:6px 0}
.rawbar input{background:#0c1220;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:4px 8px;font-size:11px;width:100%;font-family:var(--mono)}
.note{font-size:11px;color:var(--dim);margin:4px 0 8px}
.pill{font-size:10px;padding:1px 7px;border-radius:9px;border:1px solid var(--line);color:var(--dim);font-family:var(--mono)}
.pill.ok{border-color:#245b3c;color:var(--ok)}
.pill.warn{border-color:#5b4b1f;color:var(--warn)}
.pill.bad{border-color:#5b2626;color:var(--bad)}
.forkrow{display:flex;align-items:center;gap:6px;padding:3px 0;font-size:11px;font-family:var(--mono)}
.bar{height:7px;border-radius:4px;background:var(--acc);opacity:.55}
</style>
</head>
<body>
<header>
  <h1>topomap <em id="scen"></em></h1>
  <span class="sub" id="route"></span>
  <span class="spacer"></span>
  <div class="seg">
    <button id="devBtn" class="on">设备级</button>
    <button id="ifBtn">出接口级</button>
  </div>
</header>
<main>
  <div id="stage"><svg id="g"></svg><div class="legend" id="legend"></div></div>
  <aside id="side"></aside>
</main>
<div class="tip" id="tip"></div>
<script id="data" type="application/json">`

const htmlTail = `</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const R = D.result, G = R.graph, T = D.truth;
document.getElementById("scen").textContent = D.scenario;
document.getElementById("route").textContent = D.desc;

const NS = "http://www.w3.org/2000/svg";
let level = "device";      // device | iface
let selected = null;

function el(name, attrs, parent){ const e=document.createElementNS(NS,name);
  for(const k in attrs) e.setAttribute(k, attrs[k]); if(parent) parent.appendChild(e); return e; }
function fmt(n,d){ return (n==null?0:n).toFixed(d==null?2:d); }

// ---------- graph model ----------
// Device-level: nodes from G.nodes, links from G.links, branches from G.branches.
// Interface-level: each device expands into its observed addresses; edges are
// device edges re-expressed between the addresses that were actually seen
// answering on each side.
function deviceModel(){
  return {nodes:G.nodes, links:G.links, branches:G.branches||[], kind:"device"};
}
function ifaceModel(){
  const nodes=[], links=[];
  const byAddr={};
  // Source
  nodes.push({id:"if:src", label:D.src, addrs:[D.src], level:0, kind:"src", alias_confidence:1});
  const devIface={};
  (G.ifaces||[]).forEach(x=>{ (devIface[x.device]=devIface[x.device]||[]).push(x); });
  G.nodes.forEach(n=>{
    if(n.id==="src") return;
    if(n.kind==="dst"){
      const id="if:dst"; nodes.push({id, label:n.label, addrs:n.addrs, level:n.level, kind:"dst", alias_confidence:1});
      n.addrs.forEach(a=>byAddr[a]=id);
      return;
    }
    const xs=devIface[n.id]||[];
    if(xs.length===0){
      const id="if:"+n.id; nodes.push({id, label:n.label, addrs:n.addrs, level:n.level, kind:n.kind, alias_confidence:n.alias_confidence});
      n.addrs.forEach(a=>byAddr[a]=id);
      return;
    }
    xs.forEach(x=>{
      const id="if:"+x.addr;
      nodes.push({id, label:x.addr, addrs:[x.addr], level:n.level, kind:"iface", dev:n.id,
                  devLabel:n.label, alias_confidence:n.alias_confidence});
      byAddr[x.addr]=id;
    });
  });
  // Rebuild edges between interface nodes using the raw path traces.
  const seen={};
  (G.paths||[]).forEach(p=>{
    let prevId="if:src";
    for(let t=1;t<p.hops.length;t++){
      const a=p.hops[t]; if(!a||a==="?") { continue; }
      const id=byAddr[a]||null; if(!id) continue;
      if(id===prevId) continue;
      const k=prevId+"→"+id;
      if(!seen[k]){ seen[k]={from:prevId,to:id,samples:0,rtts:[],skipped:0}; links.push(seen[k]); }
      seen[k].samples++;
      if(p.rtt_ms && p.rtt_ms[t]>0) seen[k].rtts.push(p.rtt_ms[t]);
      prevId=id;
    }
  });
  links.forEach(l=>{
    if(l.rtts && l.rtts.length){
      const s=[...l.rtts].sort((a,b)=>a-b);
      l.min_rtt_ms=s[0]; l.med_rtt_ms=s[Math.floor(s.length/2)]; l.max_rtt_ms=s[s.length-1];
    }
    l.width=1;
  });
  const out={}; links.forEach(l=>out[l.from]=(out[l.from]||0)+1);
  links.forEach(l=>l.width=out[l.from]||1);
  return {nodes, links, branches:[], kind:"iface"};
}

// ---------- layout ----------
const stage=document.getElementById("stage");
const svg=document.getElementById("g");
let model=null;

function layout(m){
  const levels={};
  m.nodes.forEach(n=>{ (levels[n.level]=levels[n.level]||[]).push(n); });
  const maxCount=Math.max(1,...Object.values(levels).map(a=>a.length));
  const colW=190, rowH=96, padX=80, padY=40;
  const H=Math.max(420, maxCount*rowH+padY*2);
  const maxLv=Math.max(...m.nodes.map(n=>n.level),1);
  const W=Math.max(stage.clientWidth-8, padX*2+maxLv*colW);
  const pos={};
  Object.keys(levels).forEach(lv=>{
    const arr=levels[lv].sort((a,b)=>(a.label||"").localeCompare(b.label||""));
    arr.forEach((n,i)=>{
      pos[n.id]={x:padX+Number(lv)*colW, y:padY+(H-padY*2)*(arr.length===1?0.5:i/(arr.length-1))};
    });
  });
  return {pos,W,H};
}

function draw(){
  model = level==="device" ? deviceModel() : ifaceModel();
  const L=layout(model);
  svg.setAttribute("width",L.W); svg.setAttribute("height",L.H);
  svg.setAttribute("viewBox","0 0 "+L.W+" "+L.H);
  svg.innerHTML="";
  const linkG=el("g",{class:"linkg"},svg);
  const edgeG=el("g",{},svg);

  // curvature per (from,to) pair so parallel edges are distinguishable
  const pairs={};
  model.links.forEach(l=>{ const k=l.from+"|"+l.to; pairs[k]=(pairs[k]||0)+1; });

  const maxima={};
  model.links.forEach(l=>{ maxima[l.from]=Math.max(maxima[l.from]||0, l.samples||1); });

  model.links.forEach(l=>{
    const a=L.pos[l.from], b=L.pos[l.to];
    if(!a||!b) return;
    const mx=(a.x+b.x)/2;
    const gap=l.skipped_hops>0;
    const cls="link"+(gap?" gap":"");
    const w=Math.max(1.1, Math.min(8, 1.1+2.2*Math.log2(1+(l.samples||1))));
    el("path",{d:"M"+(a.x+66)+","+a.y+" C"+(mx+34)+","+a.y+" "+(mx-34)+","+b.y+" "+(b.x-66)+","+b.y,
      class:cls,"stroke-width":w,"data-from":l.from,"data-to":l.to},linkG);
    const yy=(a.y+b.y)/2-7;
    const share=maxima[l.from]>1 ? " "+(100*(l.samples||1)/maxima[l.from]).toFixed(0)+"%" : "";
    const rtt=l.med_rtt_ms?(" · "+fmt(l.med_rtt_ms,1)+"ms"):"";
    el("text",{x:mx,y:yy,class:"lbl","text-anchor":"middle"},linkG).textContent=
      "w="+(l.width||1)+(l.samples?(" ×"+l.samples):"")+share+rtt+(gap?" ⇢":"" );
  });

  if(level==="device"){
    (model.branches||[]).forEach(b=>{
      const a=L.pos[b.fork], c=L.pos[b.to];
      if(!a||!c) return;
      const y=(a.y+c.y)/2+10;
      el("text",{x:(a.x+c.x)/2, y:y, class:"lbl","text-anchor":"middle"},linkG).textContent=
        "share "+Math.round(b.share*100)+"%  Δ"+fmt(b.extra_rtt_ms,1)+"ms";
    });
  }

  model.nodes.forEach(n=>{
    const p=L.pos[n.id]; if(!p) return;
    const w=132, h=46;
    const g=el("g",{class:"node"+(n.kind==="unknown"?" unknown":"")+(selected===n.id?" sel":""),
      "data-id":n.id, transform:"translate("+(p.x-w/2)+","+(p.y-h/2)+")"},edgeG);
    el("rect",{width:w,height:h},g);
    const label=(n.label||"").length>19?(n.label||"").slice(0,18)+"…":(n.label||"");
    el("text",{x:9,y:17},g).textContent=label;
    let meta=n.kind;
    if(n.addrs&&n.addrs.length>1) meta+=" · "+(n.addrs.length-1)+" more";
    el("text",{x:9,y:32,class:"meta"},g).textContent=meta;
    if(n.alias_confidence!=null)
      el("text",{x:w-9,y:32,class:"meta","text-anchor":"end"},g).textContent=Math.round(n.alias_confidence*100)+"%";
    g.addEventListener("click",()=>select(n.id));
    g.addEventListener("mousemove",ev=>tip(ev,n));
    g.addEventListener("mouseleave",()=>hideTip());
  });

  document.querySelectorAll(".linkg path").forEach(p=>{
    p.addEventListener("mousemove",ev=>{
      const f=p.dataset.from, t=p.dataset.to;
      const l=model.links.find(x=>x.from===f&&x.to===t);
      if(l) tipEdge(ev,l);
    });
    p.addEventListener("mouseleave",()=>hideTip());
  });
  if(selected) highlight(selected);
  renderLegend();
}

const tipEl=document.getElementById("tip");
function tip(ev,n){
  const dev=(G.ifaces||[]).find(x=>x.addr===n.label);
  tipEl.innerHTML="<b>"+n.label+"</b><br>"+(n.addrs||[]).map(a=>a).join("<br>")+
    "<br><span class='dim'>层级 "+n.level+" · "+n.kind+"</span>"+
    (n.alias_confidence!=null?"<br>同设备置信 "+Math.round(n.alias_confidence*100)+"%":"");
  tipEl.style.display="block";
  tipEl.style.left=Math.min(ev.clientX+14, innerWidth-360)+"px";
  tipEl.style.top=(ev.clientY+14)+"px";
}
function tipEdge(ev,l){
  tipEl.innerHTML="<b>"+l.from+" → "+l.to+"</b><br>"+
    "分支宽度 w="+(l.width||1)+" · 样本 "+(l.samples||0)+
    (l.min_rtt_ms?"<br>时延 "+fmt(l.min_rtt_ms,1)+" / "+fmt(l.med_rtt_ms,1)+" / "+fmt(l.max_rtt_ms,1)+" ms":"")+
    (l.skipped_hops?"<br><span class='warn'>跨过 "+l.skipped_hops+" 个无应答跳</span>":"");
  tipEl.style.display="block";
  tipEl.style.left=Math.min(ev.clientX+14, innerWidth-360)+"px";
  tipEl.style.top=(ev.clientY+14)+"px";
}
function hideTip(){ tipEl.style.display="none"; }

function highlight(id){
  const linkg=svg.querySelector(".linkg");
  if(linkg) linkg.classList.add("dimlinks");
  svg.querySelectorAll(".link").forEach(p=>{
    const on=p.dataset.from===id||p.dataset.to===id;
    p.classList.toggle("hot",on);
  });
}

// ---------- side panel ----------
function pct(x){ return (100*x).toFixed(1)+"%"; }
function metric(label,value,cls){
  const d=document.createElement("div"); d.className="kv";
  d.innerHTML="<span>"+label+"</span><b class='"+(cls||"")+"'>"+value+"</b>";
  return d;
}

function overview(){
  const side=document.getElementById("side");
  side.innerHTML="";
  side.appendChild(h3("验收"));
  const ifs=T.interface, dev=T.device;
  side.appendChild(metric("出接口级 准确率", pct(ifs.precision), ifs.precision>=0.9?"good":(ifs.precision>=0.7?"warn":"bad")));
  side.appendChild(metric("出接口级 遗漏率", pct(1-ifs.recall), ifs.recall>=0.9?"good":"bad"));
  side.appendChild(metric("设备级 准确率", pct(dev.precision), dev.precision>=0.9?"good":(dev.precision>=0.7?"warn":"bad")));
  side.appendChild(metric("设备级 遗漏率", pct(1-dev.recall), dev.recall>=0.9?"good":"bad"));
  side.appendChild(metric("假链路（断言的错误邻接）", T.false_links, T.false_links===0?"good":"bad"));
  side.appendChild(metric("跨静默跳的边（已标注）", T.gap_edges, T.gap_edges>0?"warn":"good"));
  side.appendChild(metric("共发探测报文", T.probes, ""));
  side.appendChild(metric("使用的流数量", T.flows, ""));
  if(T.unobservable_devices && T.unobservable_devices.length)
    side.appendChild(metric("路径上完全不应答的设备", T.unobservable_devices.join(", "), "warn"));

  side.appendChild(h3("对比：普通 traceroute"));
  side.appendChild(metric("假链路", T.classic.false_links, T.classic.false_links>0?"bad":"good"));
  side.appendChild(metric("设备召回", pct(T.classic.device_recall), T.classic.device_recall<dev.recall?"bad":""));
  side.appendChild(metric("探测报文", T.classic.probes, ""));

  side.appendChild(h3("分流字段（哪些字段决定走哪条路）"));
  const ft=document.createElement("table");
  ft.innerHTML="<tr><th>字段</th><th>判定</th><th>影响</th><th>置信</th></tr>";
  (R.fields||[]).forEach(f=>{
    const cls=f.verdict==="steers"?"good":(f.verdict==="ignored"?"dim":"warn");
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+f.field+"</td><td class='"+cls+"'>"+f.verdict+"</td><td>"+fmt(f.influence,2)+"</td><td>"+fmt(f.confidence,2)+"</td>";
    ft.appendChild(tr);
  });
  side.appendChild(ft);
  side.appendChild(divNote("同一组流内，这些字段保持不变；要探别的分支就只改它们中真正参与哈希的那些。"));

  side.appendChild(h3("每跳分流方式"));
  const lt=document.createElement("table");
  lt.innerHTML="<tr><th>TTL</th><th>方式</th><th>分支</th><th>参与字段</th></tr>";
  (R.lb||[]).forEach(l=>{
    const tr=document.createElement("tr");
    const cls=l.mode==="per-packet"?"warn":(l.mode==="silent"?"dim":"good");
    tr.innerHTML="<td>"+l.ttl+"</td><td class='"+cls+"'>"+l.mode+"</td><td>"+l.branches+"</td><td>"+((l.fields||[]).join(",")||"—")+"</td>";
    lt.appendChild(tr);
  });
  side.appendChild(lt);

  side.appendChild(h3("每跳下一跳数量的统计估计"));
  const et=document.createElement("table");
  et.innerHTML="<tr><th>TTL</th><th>观测</th><th>估计</th><th>区间</th><th>样本</th><th>完成</th></tr>";
  (G.hop_estimates||[]).forEach(e=>{
    if(!e.reached && !e.probes) return;
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+e.ttl+"</td><td>"+e.observed+"</td><td>"+e.estimate+"</td><td>["+e.lower+","+e.upper+"]</td><td>"+e.probes+"</td><td class='"+(e.complete?"good":"warn")+"'>"+(e.complete?"✓":"…")+"</td>";
    et.appendChild(tr);
  });
  side.appendChild(et);

  side.appendChild(h3("同设备地址归并（IP-ID 递增规律）"));
  (R.clusters||[]).forEach(c=>{
    const d=document.createElement("div"); d.className="note";
    const badge=(c.methods||[]).map(m=>"<span class='badge'>"+m+"</span>").join("");
    d.innerHTML="<b>"+c.addrs[0]+"</b> "+badge+" <span class='dim'>"+c.ipid_mode+" · 置信 "+Math.round(c.confidence*100)+"%</span><br>"+
      "<span class='dim'>"+(c.addrs.length>1?c.addrs.slice(1).join(", "):"—")+"</span>";
    side.appendChild(d);
  });

  side.appendChild(h3("识别出的异常（普通工具会画错的原因）"));
  (G.anomalies||[]).forEach(a=>{
    const d=document.createElement("div"); d.className="kv";
    d.innerHTML="<span><span class='warn'>"+a.kind+"</span> @hop "+a.ttl+"</span>";
    side.appendChild(d);
    const n=document.createElement("div"); n.className="note"; n.textContent=a.detail; side.appendChild(n);
  });

  side.appendChild(h3("分叉宽度与分支时延"));
  const label=id=>{ const n=(G.nodes||[]).find(x=>x.id===id); return n?n.label:id; };
  const bt=document.createElement("table");
  bt.innerHTML="<tr><th>分叉</th><th>分支→</th><th>宽度</th><th>占比</th><th>时延</th><th>相对</th></tr>";
  (G.branches||[]).forEach(b=>{
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+label(b.fork)+"</td><td>"+label(b.to)+"</td><td>"+b.width+"</td><td>"+
      Math.round(b.share*100)+"%</td><td>"+fmt(b.min_rtt_ms,1)+"ms</td><td>"+
      (b.extra_rtt_ms>0?("+"+fmt(b.extra_rtt_ms,1)+"ms"):"—")+"</td>";
    bt.appendChild(tr);
  });
  side.appendChild(bt);

  side.appendChild(h3("测到的路径（每行一条不同路径）"));
  side.appendChild(lanes());
}

function h3(t){ const e=document.createElement("h3"); e.textContent=t; return e; }
function divNote(t){ const e=document.createElement("div"); e.className="note"; e.textContent=t; return e; }

function lanes(){
  const wrap=document.createElement("div"); wrap.className="lanes";
  const paths=(G.paths||[]).filter(p=>p.hops.some(h=>h));
  if(!paths.length) return wrap;
  const maxTtl=Math.max(...paths.map(p=>p.hops.length-1),1);
  const cw=126, rh=24;
  const s=document.createElementNS(NS,"svg");
  s.setAttribute("width",(maxTtl+1)*cw+16);
  s.setAttribute("height",paths.length*rh+16);
  const colors=["#4fa3ff","#39d0a4","#e3b341","#c08cff","#f26d6d","#4ecbd8","#e08a4a"];
  paths.forEach((p,pi)=>{
    const y=12+pi*rh;
    let px=8, py=y;
    for(let t=1;t<p.hops.length;t++){
      const h=p.hops[t];
      if(h==="?"){ el("text",{x:8+t*cw, y:y+3, class:"lbl","text-anchor":"middle"},s).textContent="·"; continue; }
      if(!h) continue;
      const x=8+t*cw;
      el("line",{x1:px,y1:py,x2:x,y2:y,stroke:colors[pi%colors.length],"stroke-width":1.5,"stroke-opacity":.45},s);
      el("rect",{x:x-48,y:y-8,width:96,height:16,rx:4,fill:"#141d2e",stroke:colors[pi%colors.length],"stroke-width":.8},s);
      el("text",{x:x,y:y+3,"text-anchor":"middle",fill:"#cfe0f7","font-size":8,"font-family":"var(--mono)"},s).textContent=h;
      px=x; py=y;
    }
    el("text",{x:8,y:y-12,fill:"#5d6e88","font-size":8},s).textContent="×"+p.weight;
  });
  wrap.appendChild(s);
  return wrap;
}

function select(id){
  selected=id;
  svg.querySelectorAll(".node").forEach(e=>e.classList.toggle("sel",e.dataset.id===id));
  highlight(id);
  const n=model.nodes.find(x=>x.id===id);
  if(!n) return;
  const side=document.getElementById("side");
  side.innerHTML="";
  side.appendChild(h3("选中的跳"));
  const kv=document.createElement("div"); kv.className="kv";
  kv.innerHTML="<span>"+n.label+"</span><span class='dim'>层级 "+n.level+" · "+n.kind+"</span>";
  side.appendChild(kv);
  const addrs=n.addrs||[];
  const a=document.createElement("div"); a.className="note";
  a.innerHTML="地址: "+addrs.join(", ")+
    (n.alias_confidence!=null?" <span class='badge'>同设备 "+Math.round(n.alias_confidence*100)+"%</span>":"");
  side.appendChild(a);

  if(level==="device" && addrs.length>1){
    side.appendChild(h3("该设备的全部地址"));
    const t=document.createElement("table");
    t.innerHTML="<tr><th>地址</th><th>来源</th></tr>";
    (R.clusters||[]).filter(c=>c.addrs.some(x=>addrs.includes(x))).forEach(c=>{
      c.addrs.forEach(x=>{
        const tr=document.createElement("tr");
        tr.innerHTML="<td>"+x+"</td><td>"+(c.methods||[]).join(",")+"</td>";
        t.appendChild(tr);
      });
    });
    side.appendChild(t);
  }

  // Fork arms out of this node.
  const arms=(G.branches||[]).filter(b=>b.fork===id);
  if(arms.length){
    side.appendChild(h3("此处分叉"));
    arms.forEach(b=>{
      const row=document.createElement("div"); row.className="forkrow";
      row.innerHTML="<span style='width:52px'>→ "+b.to+"</span><span>宽度 "+b.width+" · "+Math.round(b.share*100)+"% · "+fmt(b.min_rtt_ms,1)+"ms</span>";
      side.appendChild(row);
    });
  }

  side.appendChild(h3("原始探测记录"));
  renderRaw(n);
}

let rawFilter="";
function renderRaw(n){
  const side=document.getElementById("side");
  const addrSet=new Set(n.addrs||[]);
  const recs=(R.records||[]).filter(r=>addrSet.has(r.reply_addr));
  const bar=document.createElement("div"); bar.className="rawbar";
  const inp=document.createElement("input"); inp.placeholder="按 TTL / 流 / 端口过滤…"; inp.value=rawFilter;
  inp.addEventListener("input",()=>{ rawFilter=inp.value; });
  inp.addEventListener("change",()=>{ rawFilter=inp.value; renderRawRefresh(n); });
  bar.appendChild(inp); side.appendChild(bar);
  const shown=recs.filter(r=>!rawFilter||
    String(r.ttl)===rawFilter||r.flow_group.includes(rawFilter)||String(r.src_port).includes(rawFilter)||
    r.reply_addr.includes(rawFilter)||r.reply_kind.includes(rawFilter));
  const note=document.createElement("div"); note.className="note";
  note.textContent="共 "+recs.length+" 条，显示 "+Math.min(shown.length,300)+" 条。";
  side.appendChild(note);
  const t=document.createElement("table");
  t.innerHTML="<tr><th>ttl</th><th>流</th><th>源端口</th><th>应答地址</th><th>IP-ID</th><th>外TTL</th><th>RTT</th><th>类型</th></tr>";
  shown.slice(0,300).forEach(r=>{
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+r.ttl+"</td><td>"+short(r.flow_group)+"</td><td>"+r.src_port+"</td><td>"+r.reply_addr+
      "</td><td>"+r.reply_ipid+"</td><td>"+r.outer_ttl+"</td><td>"+fmt(r.rtt_ms,2)+"</td><td>"+
      (r.reply_kind==="none"?"<span class='dim'>无应答</span>":r.reply_kind)+"</td>";
    t.appendChild(tr);
  });
  side.appendChild(t);
}

function renderRawRefresh(n){
  // Re-render only the raw section by re-running select; scroll is preserved by browser.
  const sc=document.getElementById("side").scrollTop;
  select(n.id);
  document.getElementById("side").scrollTop=sc;
}

function short(f){ return f && f.length>12?f.slice(0,11)+"…":(f||""); }

function renderLegend(){
  const lg=document.getElementById("legend");
  lg.innerHTML="<span><i></i>邻接边，粗细=分支宽度</span>"+
    "<span><i class='gap'></i>跨静默跳的边</span>"+
    "<span>点击设备查看原始探测记录</span>"+
    "<span>当前视图：<b class='dim'>"+(level==="device"?"设备级":"出接口级")+"</b></span>";
}

// ---------- boot ----------
document.getElementById("devBtn").onclick=()=>{ level="device"; selected=null; setView(); };
document.getElementById("ifBtn").onclick=()=>{ level="iface"; selected=null; setView(); };
function setView(){
  document.getElementById("devBtn").classList.toggle("on",level==="device");
  document.getElementById("ifBtn").classList.toggle("on",level==="iface");
  overview(); draw();
}
window.addEventListener("resize",()=>{ if(!selected) draw(); });
overview(); draw();
</script>
</body>
</html>`
