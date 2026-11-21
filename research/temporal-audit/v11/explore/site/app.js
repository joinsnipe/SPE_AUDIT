"use strict";
(() => {
  const data=window.SPE_DATA, capture=SPECapture;
  const $=id=>document.getElementById(id);
  const base="https://github.com/joinsnipe/SPE_AUDIT";
  const path="/main/research/temporal-audit/v11/";
  const dayms=86400000;
  const day=n=>new Date(n*dayms).toISOString().slice(0,10);
  const epoch=s=>Date.parse(s+"T00:00:00Z")/dayms;
  let language=new URLSearchParams(location.search).get("lang")==="en"?"en":"es";
  let mission, raw, record, workId=0, canaryRecords=null;
  const tr=(es,en)=>language==="en"?en:es;
  const node=(tag,text,cls)=>{
    const el=document.createElement(tag);
    if(text!==undefined) el.textContent=text;
    if(cls) el.className=cls;
    return el;
  };
  function fillOptions(el,values,select) {
    el.replaceChildren(...values.map(([id,label])=>new Option(label,id)));
    if(select) el.value=select;
  }
  function currentAnchor() {return data.baselines[mission.id].after;}
  function setMission(id) {
    mission=data.events.find(e=>e.id===id);
    $("mission").value=id;
    $("cutoff").value=mission.sources.find(c=>c.id===mission.outcome_card).date;
    dispatch();
  }
  function setDate(date) {
    if(!capture.validDay(date)) return;
    $("cutoff").value=date;
    dispatch();
  }
  function dispatch() {
    const cutoff=$("cutoff").value;
    if(!capture.validDay(cutoff)) return;
    const anchor=JSON.parse(currentAnchor().record.request_utf8);
    raw=capture.request(cutoff,anchor.prompt,mission.sources);
    $("output").value=capture.latest(raw);
    showRequest();
    hashOutput();
  }
  function showRequest() {
    const req=JSON.parse(capture.decoder.decode(raw));
    const lo=Math.max(epoch("0001-01-01"),Math.min(...mission.sources.map(c=>epoch(c.date)-1),epoch(req.cutoff)));
    const hi=Math.min(epoch("9999-12-31"),Math.max(...mission.sources.map(c=>epoch(c.date)+2),epoch(req.cutoff)));
    const range=$("slider");
    range.min=lo;range.max=hi;range.value=epoch(req.cutoff);
    range.setAttribute("aria-valuetext",req.cutoff);
    $("lo").textContent=day(lo);$("hi").textContent=day(hi);
    $("eventdate").textContent=mission.event_date;
    $("pubdate").textContent=mission.sources.find(c=>c.id===mission.outcome_card).date;
    $("cards").replaceChildren(...mission.sources.map(card=>{
      const el=node("article",undefined,"card"),line=node("div",undefined,"cardline");
      const included=req.sources.some(c=>c.id===card.id);
      line.append(node("code",card.id+" · "+card.date),node("span",included?tr("Admitida","Included"):tr("Fuera del corte","Past the cutoff"),included?"status":"status out"));
      const link=node("a",tr("Ver fuente oficial","View official source")+" ↗");link.href=card.url;
      const txt=node("p",card.text);txt.lang="en";
      el.append(line,txt,link);return el;
    }));
    $("count").textContent=tr("Fichas entregadas al emisor local","Cards delivered to the local sender")+": "+req.sources.length+" / "+mission.sources.length;
    $("raw").textContent=capture.decoder.decode(raw);
    $("hex").textContent=capture.hex(raw).match(/../g).join(" ");
  }
  function digestRow(label,hash,detail,status) {
    const box=node("div",undefined,"hashrow");
    box.append(node("b",label),node("code",hash,"digest"));
    if(detail) box.append(node("small",detail,status));
    return box;
  }
  async function hashOutput() {
    const id=++workId;
    $("download").disabled=true;
    const anchor=currentAnchor(),baseRecord=anchor.record,output=$("output").value;
    const updated=await capture.seal(raw,output);
    if(id!==workId)return;
    record=updated;
    $("download").disabled=false;
    const sealInput=rec=>{ const {record_sha256,...body}=rec; return capture.bytes(capture.canonical(body)); };
    const pairs=[
      [tr("Petición","Request"),"request_sha256",capture.bytes(record.request_utf8),capture.bytes(baseRecord.request_utf8)],
      [tr("Respuesta","Response"),"output_sha256",capture.bytes(output),capture.bytes(baseRecord.output)],
      [tr("Registro sin su propio sello","Record excluding its own seal"),"record_sha256",sealInput(record),sealInput(baseRecord)]
    ];
    $("baseline").textContent=tr("Referencia publicada","Published baseline")+" · capsules.jsonl #"+anchor.line+" · "+JSON.parse(baseRecord.request_utf8).cutoff;
    $("hashes").replaceChildren(...pairs.map(([label,key,current,ref])=>{
      const sameBytes=current.length===ref.length && current.every((v,i)=>v===ref[i]);
      const sameHash=record[key]===baseRecord[key];
      const match=sameBytes&&sameHash;
      const detail=current.length+" B / "+ref.length+" B · "+(match?tr("Bytes y huella idénticos","Bytes and digest match"):tr("Difiere de la referencia","Differs from baseline"));
      return digestRow(label,record[key],detail,match?"matching":"different");
    }));
    $("anchors").replaceChildren(...pairs.map(([label,key])=>digestRow(label,baseRecord[key])));
  }
  function downloadRecord() {
    if(!record)return;
    const link=node("a");
    const url=URL.createObjectURL(new Blob([capture.canonical(record)],{type:"application/json;charset=utf-8"}));
    link.href=url;link.download="spe-capture-"+mission.id+"-"+$("cutoff").value+".json";link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  async function runCanary(){
    const cutoff="2030-04-02",prompt="What marker is in the latest supplied card for the fictional Mica mission?";
    const card={id:"mica-test",date:cutoff,text:"MICA · marker 47",url:"urn:spe:example:mica"};
    canaryRecords=await Promise.all([[],[card]].map(async cards=>{
      const input=capture.request(cutoff,prompt,cards);return capture.seal(input,capture.latest(input));
    }));
    showCanary();
  }
  function showCanary(){
    if(!canaryRecords)return;
    const panel=node("div",undefined,"twocards");
    canaryRecords.forEach((rec,i)=>{
      const card=node("article");card.append(node("h4",i?tr("Con ficha","With card"):tr("Sin ficha","Without card")));
      card.append(node("p",rec.output),digestRow(tr("Petición · SHA-256","Request · SHA-256"),rec.request_sha256));
      const d=node("details");d.append(node("summary",tr("Bytes enviados como JSON","Dispatched JSON bytes")),node("pre",rec.request_utf8));card.append(d);panel.append(card);
    });
    $("canary-result").replaceChildren(panel,node("p",tr("La diferencia se observa en el emisor determinista local. Ningún proveedor recibió estas peticiones.","The difference is observed at a deterministic local sender. No provider received these requests.")));
  }
  const groups=["constructed","old_challenge","new_challenge"];
  const counts={constructed:96,old_challenge:16,new_challenge:48};
  const kind=g=>g==="constructed"?tr("Construidos","Constructed"):g==="old_challenge"?tr("Reto anterior","Earlier challenge"):tr("Reto nuevo","New challenge");
  const labels=v=>({POST_ASSERTION:tr("Alerta","Alert"),OTHER:tr("Otro","Other"),INDETERMINATE:tr("Indeterminado","Indeterminate"),REVIEW:tr("Revisión","Review")})[v]||"—";
  const methods=v=>({year_rule:tr("Detector anual","Year rule"),matcher_v1:tr("Comparador 1.0","Comparator 1.0"),proposition:tr("Proposiciones 1.1","Proposition rule 1.1"),reader:tr("Lectura exploratoria","Exploratory reading")})[v];
  function renderSummary(){
    const body=$("summary");body.replaceChildren();
    for(const group of groups){
      const rows=data.rows.filter(r=>r.group===group);
      const show=group==="new_challenge"?["year_rule","proposition","reader"]:["matcher_v1","proposition"];
      for(const m of show){
        const n=rows.length, positive=rows.filter(r=>r.reference==="POST_ASSERTION"),tp=positive.filter(r=>r[m]==="POST_ASSERTION").length;
        const alerts=rows.filter(r=>r[m]==="POST_ASSERTION" && r.reference!=="INDETERMINATE").length, review=rows.filter(r=>r[m]==="REVIEW").length;
        const line=node("tr");
        [n+" · "+kind(group),methods(m),tp+"/"+positive.length,alerts?tp+"/"+alerts:"—",(n-review)+"/"+n,review].forEach(v=>line.append(node("td",v)));
        body.append(line);
      }
    }
    const group=$("group").value||"new_challenge", selected=$("row").value;
    fillOptions($("group"),groups.map(g=>[g,counts[g]+" · "+kind(g)]),group);
    renderRowOptions(selected);
  }
  function renderRowOptions(selected){
    const rows=data.rows.filter(r=>r.group===$("group").value);
    fillOptions($("row"),rows.map(r=>[r.id,r.id]),rows.some(r=>r.id===selected)?selected:rows[0].id);
    renderExample();
  }
  function renderExample(){
    const r=data.rows.find(r=>r.id===$("row").value);
    const dl=node("dl",undefined,"sample"), add=(label,value,lang)=>{const term=node("dt",label),desc=node("dd",value);if(lang)desc.lang=lang;dl.append(term,desc);};
    add(tr("Ficha / corte / idioma original","Case / cutoff / original language"),r.id+" · "+r.event_id+" · "+r.cutoff+" · "+r.language);
    add(tr("Pregunta","Prompt"),r.prompt,r.language);add(tr("Respuesta construida","Authored answer"),r.text,r.language);
    add(tr("Referencia editorial","Editorial reference"),r.reference);
    for(const m of ["year_rule","matcher_v1","proposition","reader"])if(r[m])add(methods(m),labels(r[m])+" · "+r[m]);
    $("example").replaceChildren(dl);
  }
  function setLang(value){
    language=value;document.documentElement.lang=value;
    document.title="SPE Audit · "+tr("La fecha de corte","The cutoff date");
    for(const locale of ["en","es"])$(locale).setAttribute("aria-pressed",String(locale===value));
    $("pdf").href=base+"/blob"+path+"SUPPLEMENT_"+value.toUpperCase()+".pdf";
    $("blog").href=base+"/blob"+path+"outreach/blog_"+value+".md";
    $("desklink").href=base+"/tree"+path+"desk";
    $("reviewlink").href=base+"/blob"+path+"review/review_"+value+".md";
    $("repo").href=base;
    $("doi").href="https://doi.org/10.5281/zenodo.24424024";
    $("offline").href="https://raw.githubusercontent.com/joinsnipe/SPE_AUDIT"+path+"explore/offline.zip";
    renderSummary();showCanary();
    if(raw){showRequest();hashOutput();}
  }
  fillOptions($("mission"),data.events.map(e=>[e.id,e.name]),"dart");
  $("mission").addEventListener("change",e=>setMission(e.target.value));
  $("cutoff").addEventListener("change",e=>{if(capture.validDay(e.target.value))setDate(e.target.value);else {e.target.reportValidity();e.target.value=JSON.parse(capture.decoder.decode(raw)).cutoff;}});
  $("slider").addEventListener("input",e=>setDate(day(Number(e.target.value))));
  $("oneday").addEventListener("click",()=>setDate(mission.event_date));
  $("output").addEventListener("input",hashOutput);
  $("byte").addEventListener("click",()=>{$("output").value+=" ";hashOutput();});
  $("restore").addEventListener("click",()=>setMission(mission.id));
  $("download").addEventListener("click",downloadRecord);
  $("canary-run").addEventListener("click",runCanary);
  $("group").addEventListener("change",()=>renderRowOptions());
  $("row").addEventListener("change",renderExample);
  for(const locale of ["en","es"])$(locale).addEventListener("click",()=>setLang(locale));
  setLang(language);setMission("dart");
})();
