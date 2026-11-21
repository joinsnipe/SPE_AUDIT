// Exercise the shipped JS with a DOM test double and a real loopback server.
// All cases and operations are simulated; this is not a browser rendering test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

class Element {
  constructor() { this.children=[]; this.attrs={}; this.textContent=''; this.value=''; this.hidden=false; this.disabled=false; }
  setAttribute(k,v) { this.attrs[k]=v; }
  appendChild(x) { this.children.push(x); }
  replaceChildren() { this.children=[]; }
  focus() {}
}

async function main() {
  const [origin,token]=process.argv.slice(2);
  const page=await (await fetch(origin)).text();
  const nodes=Object.fromEntries([...page.matchAll(/\bid="([\w-]+)"/g)].map(m=>[m[1],new Element()]));
  const document={getElementById:id=>nodes[id],documentElement:{},createElement:()=>new Element(),addEventListener(){}};
  const ctx={document,crypto:webcrypto,location:{hash:'#'+token,pathname:'/'},history:{replaceState(){}},
    sessionStorage:{setItem(){}},window:{confirm:()=>true},setInterval:()=>{},setTimeout,clearTimeout,
    fetch:(url,opts)=>fetch(origin+url,{...opts,headers:{...opts.headers,Origin:origin}})};
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(__dirname,'desk.js'),'utf8'),ctx);
  async function settled(fn) {
    await fn();
    for(let i=0;i<5;i++){await vm.runInContext('chain',ctx);await new Promise(resolve=>setImmediate(resolve));}
  }
  await settled(async()=>{});
  assert.ok(nodes.work.hidden);
  await settled(()=>nodes.start.onclick());
  assert.ok(!nodes.work.hidden);
  assert.match(nodes.contextKind.textContent,/redactaron/);
  assert.ok(!nodes.quote.children.some(n=>n.className==='cue'));
  nodes.en.onclick();
  assert.equal(nodes.title.textContent,'Review desk');
  nodes.phrase.value='landed';nodes.find.onclick();
  assert.ok(nodes.quote.children.some(n=>n.className==='own'&&n.textContent==='landed'));
  nodes.note.value='SIMULATED evidence';nodes.note.oninput();nodes.choice.value='other';nodes.choice.onchange();
  await settled(()=>nodes.pause.onclick());assert.ok(nodes.work.hidden);
  await settled(()=>nodes.start.onclick());assert.equal(nodes.note.value,'SIMULATED evidence');
  await settled(()=>nodes.finish.onclick());
  assert.equal(nodes.progress.textContent,'Cases completed · 1 / 2');
  await settled(()=>nodes.start.onclick());assert.equal(nodes.mode.textContent,'Blind mode');
  await settled(()=>nodes.assist.onclick());assert.ok(nodes.quote.children.some(n=>n.className==='cue'));
  nodes.note.value='SIMULATED second reason';nodes.note.oninput();nodes.choice.value='indeterminate';nodes.choice.onchange();
  await settled(()=>nodes.finish.onclick());
  await settled(()=>nodes.seal.onclick());
  assert.equal(nodes.end.hidden,false);assert.match(nodes.receipt.textContent,/[0-9a-f]{64}/);
  console.log('PASS: embedded JS controls, bilingual panels, manual selection, blind and assisted cases, pause/resume, two saved decisions and receipt over real loopback HTTP.');
}
main().catch(e=>{console.error(e);process.exitCode=1});
