/* Offline release check. Node 18+, no dependencies. Executes the shipped UI against a DOM test double. */
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const folder = __dirname;
const sourceDir = process.argv[2] || path.resolve(folder,'../../v11');
const html = fs.readFileSync(path.join(folder,'index.html'),'utf8');
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length,2);
const data = JSON.parse(scripts[0][2]);
const script = scripts[1][2];
const read = f=>fs.readFileSync(path.join(sourceDir,f));
const parse = f=>JSON.parse(read(f));
const rows = f=>read(f).toString().trim().split('\n').map(s=>JSON.parse(s));
const digest = (v,h='sha256')=>crypto.createHash(h).update(v).digest('hex');
const pins = {
 'holdout/cases.json':'4647641138fb72423a7fe7af7c5f91274b263076',
 'holdout/events.json':'17b7ab5896fd4a42da0b2646b781e9c5dbf510f3',
 'holdout/labels.json':'274d9090171d4cddee7e62df8a0bdf0093e8eeb6',
 'reader/answers.json':'bde70a637284f2f9086f384ef79950448279c6f0',
 'results/predictions.jsonl':'2617a02ee2805752a64371d91d3516497541e2be',
 'results/learned_traces.jsonl':'4c31ffe9a234097a23f268338f7d3ff92545ef7d',
 'results/reader_metrics.json':'5b4ca023b71a0e9158e80cba1dbe956e2b20fb1b'
};
assert.deepEqual(Object.keys(data.files).sort(),Object.keys(pins).sort());
for(const [f,h] of Object.entries(pins)){
 const raw=read(f);assert.equal(digest(raw),data.files[f]);assert.equal(digest(Buffer.concat([Buffer.from('blob '+raw.length+'\0'),raw]),'sha1'),h);
}
const cases=parse('holdout/cases.json'),events=parse('holdout/events.json'),labels=parse('holdout/labels.json');
const pp=rows('results/predictions.jsonl'),nets=rows('results/learned_traces.jsonl'),reader=parse('reader/answers.json');
assert.equal(cases.length,48);assert.equal(reader.length,48);
assert.deepEqual(data.cases.map(x=>x.id),['v038','v003','v013','v031','v019','v044']);
assert.equal(new Set(data.cases.map(x=>x.event_id)).size,6);
assert.equal(data.cases.filter(c=>c.language==='en').length,3);
assert.equal(data.cases.filter(c=>c.reference==='INDETERMINATE').length,3);
const metrics=parse('results/reader_metrics.json').all;
assert.equal(metrics.confusion.POST_ASSERTION.POST_ASSERTION+metrics.confusion.OTHER.OTHER,42);
assert.equal(metrics.confusion.INDETERMINATE.REVIEW,6);
const at=(f,line)=>read(f).toString().split('\n')[line-1];
for(const c of data.cases){
 const src=cases.find(x=>x.id===c.id), e=events.find(x=>x.id===c.event_id);
 for(const k of Object.keys(src))assert.equal(c[k],src[k],c.id+' '+k);
 assert.equal(c.event,e.name);assert.equal(c.event_date,e.event_date);assert.equal(c.source,e.source_url);
 const p=pp.find(x=>x.group==='new_challenge'&&x.id===c.id);
 const n=nets.find(x=>x.group==='new48'&&x.method==='neural'&&x.id===c.id)||nets.find(x=>x.method==='neural'&&x.id===c.id);
 assert.equal(c.year,p.choices.year_rule);assert.equal(c.proposition,p.choices.proposition);assert.equal(c.neural,n.prediction.decision);
 assert.ok(p.explanation.clauses.some(s=>s.text===c.rule_excerpt));assert.ok(c.text.includes(c.rule_excerpt));
 assert.equal(c.reader.key,digest('spe-1.1-reader|'+c.id).slice(0,10));
 assert.deepEqual(c.reader,reader.find(r=>r.key===c.reader.key));assert.equal(c.reference,labels[c.id]);
 for(const [f,k,key] of [['holdout/cases.json','case',c.id],['holdout/events.json','event',e.id],['holdout/labels.json','reference',c.id],['reader/answers.json','reader',c.reader.key],['results/predictions.jsonl','rule',c.id]])assert.ok(at(f,c.lines[k]).includes(key));
}
assert.ok(!/<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)=/i.test(html));
assert.ok(!/\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|localStorage|sessionStorage|indexedDB|document\.cookie)\b/.test(script));
const allIds=[...html.matchAll(/\bid="([\w-]+)"/g)].map(m=>m[1]);
assert.equal(new Set(allIds).size,allIds.length);
class Item{
 constructor(id){this.id=id;this.textContent='';this.value='';this.children=[];this.dataset={};this.attrib={};this.checked=false;}
 setAttribute(k,v){this.attrib[k]=v} replaceChildren(){this.children=[]} appendChild(n){this.children.push(n)} focus(){this.focused=true}
}
function session(url,locale){
 const location=new URL(url), nodes=Object.fromEntries(allIds.map(id=>[id,new Item(id)]));
 const document={documentElement:{dataset:{paperLocale:locale}},getElementById:k=>nodes[k],createElement:()=>new Item()};
 nodes.dataset.textContent=scripts[0][2];
 for(const [k,v] of [['positive','POST_ASSERTION'],['other','OTHER'],['indet','INDETERMINATE']])nodes[k].value=v;
 const links=[];const history={replaceState:(_unused,_title,link)=>links.push(link)};
 vm.runInNewContext(script,{document,location,history,URL,URLSearchParams});
 return {nodes,document,links};
}
function select(nodes,id){for(const r of ['positive','other','indet'])nodes[r].checked=(r===id);nodes[id].onchange()}
function choose(nodes,id){nodes.case.value=id;nodes.case.onchange()}
for(const lc of ['es','en']){
 const {nodes:n,document:d,links}=session('https://www.spetrace.com/'+(lc==='es'?'es/':'')+'research/temporal-audit/review-desk?case=v038');
 assert.equal(d.documentElement.lang,lc);assert.equal(n.archived.hidden,true);assert.equal(n.case.children.length,6);
 assert.equal(n.caseId.textContent,'v038');assert.equal(n.flag.dataset.status,'POST_ASSERTION');
 n.save.onclick();assert.ok(n.positive.focused);select(n,'other');n.note.value='SIMULATED LOCAL NOTE';n.note.oninput();n.save.onclick();
 assert.match(n.localStatus.textContent,lc==='es'?/antes de ver/:/before viewing/);
 n.reveal.onclick();assert.equal(n.archived.hidden,false);assert.equal(n.reveal.attrib['aria-expanded'],'true');assert.match(n.compare.textContent,lc==='es'?/coincide/:/matches/);
 assert.equal(n.rationale.textContent,data.cases[0].reader.rationale);
 n.reveal.onclick();assert.equal(n.archived.hidden,true);select(n,'indet');n.save.onclick();
 assert.match(n.localStatus.textContent,lc==='es'?/después de ver/:/after viewing/);
 choose(n,'v003');assert.equal(n.archived.hidden,true);assert.equal(n.note.value,'');n.reveal.onclick();select(n,'indet');n.save.onclick();
 assert.match(n.localStatus.textContent,lc==='es'?/después de ver/:/after viewing/);
 choose(n,'v038');assert.equal(n.note.value,'SIMULATED LOCAL NOTE');assert.ok(n.indet.checked);n.clear.onclick();assert.equal(n.note.value,'');assert.ok(!n.indet.checked);
 choose(n,'v031');assert.ok(n.back.href.endsWith('case=v031#casebook'));assert.ok(n.caseFile.href.includes(data.commit));
 n[lc==='en'?'es':'en'].onclick();assert.equal(d.documentElement.lang,lc==='en'?'es':'en');assert.ok(links.every(x=>!x.includes('SIMULATED')));
 for(const c of data.cases){choose(n,c.id);assert.equal(n.response.textContent,c.text);assert.equal(n.primary.href,c.source);assert.equal(n.clause.textContent,c.rule_excerpt);}
}
const overrides=session('https://www.spetrace.com/es/research/temporal-audit/review-desk?case=unknown&lang=en','es');
assert.equal(overrides.document.documentElement.lang,'en');assert.equal(overrides.nodes.caseId.textContent,'v038');
assert.equal(session('file:///tmp/index.html').document.documentElement.lang,'es');
console.log('PASS: six cases against seven pinned source files, archived quotes and anchors, six events and both languages, local annotation and exposure order, bilingual return/deep links, clean tab state, no submission or storage API. Simulated UI actions; zero human observations.');
