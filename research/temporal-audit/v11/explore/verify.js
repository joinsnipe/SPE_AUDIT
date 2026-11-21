/* Run from any directory with Node 18+. No packages or network access. */
"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const vm=require("node:vm");
const {webcrypto,createHash}=require("node:crypto");
const site=path.join(__dirname,"site");
const read=f=>fs.readFileSync(path.join(site,f),"utf8");
const c=require("./site/capture.js");
const data={window:{}};
vm.runInNewContext(read("data.js"),data);
const d=data.window.SPE_DATA;
const source=path.join(__dirname,"../../study/results/capsules.jsonl");
const records=fs.readFileSync(source,"utf8").trimEnd().split("\n").map(JSON.parse);

class Element {
  constructor(tag){this.tag=tag;this._text="";this.children=[];this.value="";this.attributes={};this.events={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[];this.append(...children);}
  addEventListener(event,handler){this.events[event]=handler;}
  setAttribute(key,value){this.attributes[key]=value;}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join("");}
  set textContent(v){this._text=String(v);this.children=[];}
  async fire(evt){await this.events[evt]?.({target:this}); await new Promise(resolve=>setImmediate(resolve));}
}
async function tests() {
  assert.equal(records.length,124);
  for(const stored of records){
    const r=JSON.parse(stored.request_utf8);
    const raw=c.request(r.cutoff,r.prompt,r.sources);
    assert.equal(c.decoder.decode(raw),stored.request_utf8);
    assert.deepEqual(await c.seal(raw,stored.output),stored);
  }
  for(const e of d.events){
    for(const [condition,baseline] of Object.entries(d.baselines[e.id])){
      const stored=records[baseline.line-1],r=JSON.parse(stored.request_utf8);
      const cards=condition==="after_without_outcome"?e.sources.filter(x=>x.id!==e.outcome_card):e.sources;
      const raw=c.request(r.cutoff,r.prompt,cards);
      assert.equal(c.latest(raw),stored.output);
      assert.deepEqual(await c.seal(raw,c.latest(raw)),stored);
    }
  }
  const localHash=s=>createHash("sha256").update(s).digest("hex");
  const utfSamples=["", "abc", "á🚀\n", "\uFEFFheader", ...[55,56,64,128,100001].map(n=>"x".repeat(n))];
  for(const s of utfSamples){assert.equal(c.sha256Local(c.bytes(s)),localHash(s));assert.equal(await c.sha(c.bytes(s)),localHash(s));}
  const vector=c.request("2026-03-03",'Prueba "\\n" · 元',[{id:"omega",date:"2026-03-03",text:"Été\n🚀",url:"urn:example:unicode"}]);
  assert.equal(c.decoder.decode(vector),'{"cutoff":"2026-03-03","policy_id":"source-publication-date-on-or-before-cutoff/1","prompt":"Prueba \\"\\\\n\\" · 元","sources":[{"date":"2026-03-03","id":"omega","text":"Été\\n🚀","url":"urn:example:unicode"}]}');
  assert.equal(c.validDay("2023-02-29"),false);
  assert.equal(c.validDay("2024-02-29"),true);
  const html=read("index.html");
  const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
  assert.equal(new Set(ids).size,ids.length);
  const els=Object.fromEntries(ids.map(id=>[id,new Element(id)]));
  function Option(label,value){const el=new Element("option");el.textContent=label;el.value=value;return el;}
  const context={window:{},document:{getElementById:id=>{assert.ok(els[id],id);return els[id];},createElement:tag=>new Element(tag),documentElement:{}},Option,location:{search:""},URLSearchParams,TextEncoder,TextDecoder,Uint8Array,DataView,URL,Blob,Date,setTimeout,crypto:webcrypto};
  vm.createContext(context);
  for(const script of ["data.js","capture.js","app.js"])vm.runInContext(read(script),context);
  async function settled(){
    for(let i=0;els.download.disabled&&i<200;i++)await new Promise(r=>setTimeout(r,2));
    assert.equal(els.download.disabled,false);
  }
  await settled();assert.equal(els.mission.value,"dart");
  assert.equal(els.hashes.children.length,3);assert.ok(els.hashes.children.every(el=>el.textContent.includes("idénticos")));
  assert.equal(els.summary.children.length,7);
  assert.equal(els.row.children.length,48);
  assert.equal(els.example.textContent.includes("v001"),true);
  const baseOutput=els.output.value;
  await els.byte.fire("click");await settled();
  assert.equal(els.output.value,baseOutput+" ");
  assert.ok(els.hashes.children[0].textContent.includes("idénticos"));
  assert.ok(els.hashes.children.slice(1).every(el=>el.textContent.includes("Difiere")));
  await els.oneday.fire("click");await settled();
  assert.equal(els.cutoff.value,"2022-09-26");assert.equal(JSON.parse(els.raw.textContent).sources.length,1);
  els.cutoff.value="2022-09-27";await els.cutoff.fire("change");await settled();
  assert.equal(JSON.parse(els.raw.textContent).sources.length,2);
  els.slider.value=Date.parse("2021-11-23T00:00:00Z")/86400000;await els.slider.fire("input");await settled();
  assert.equal(els.output.value,"No eligible source.");
  await els.restore.fire("click");await settled();
  assert.equal(els.output.value,baseOutput);
  for(const e of d.events){els.mission.value=e.id;await els.mission.fire("change");await settled();assert.ok(els.hashes.children.every(el=>el.textContent.includes("idénticos")));}
  await els.en.fire("click");await settled();assert.equal(context.document.documentElement.lang,"en");assert.ok(els.pdf.href.endsWith("SUPPLEMENT_EN.pdf"));
  for(const [g,n] of [["constructed",96],["old_challenge",16],["new_challenge",48]]){els.group.value=g;await els.group.fire("change");assert.equal(els.row.children.length,n);}
  els.row.value="v038";await els.row.fire("change");assert.ok(els.example.textContent.includes("No acepto esa premisa."));
  await els["canary-run"].fire("click");assert.ok(els["canary-result"].textContent.includes("No eligible source."));assert.ok(els["canary-result"].textContent.includes("MICA · marker 47"));
  for(const s of [...html.matchAll(/(?:src|href)="([^"#]+)"/g)].map(m=>m[1])) assert.ok(fs.existsSync(path.join(site,s)),s);
  console.log("124/124 Python records match, 12/12 intervention replays, SHA-256 checks, four missions, cutoff boundary, byte edit, restore, canary, two languages, 160 case rows and local assets verified.");
}
tests().catch(e=>{console.error(e);process.exit(1);});
