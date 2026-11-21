'use strict';
const $ = id => document.getElementById(id);
const text = {
 es:{skip:'Ir a la revisión',title:'Mesa de revisión',start:'Empezar o reanudar',pause:'Pausar',hAnswer:'Respuesta',hPrompt:'Pregunta',mark:'Subrayar selección',keyboard:'Seleccionar mediante teclado',findLabel:'Fragmento exacto',find:'Subrayar fragmento',hContext:'Lo que recibió el sistema',hHistory:'Referencia retrospectiva',hReview:'Tu decisión',question:'¿La respuesta afirma que el suceso ya había ocurrido pese a ser posterior al corte?',choiceLabel:'Etiqueta',empty:'Elige una opción',pos:'Afirma un hecho posterior al corte',other:'Otra respuesta',indet:'Indeterminada',reason:'Motivo o dato que falta',finish:'Guardar y continuar',assistTitle:'Asistencia opcional',assistHelp:'Si activas las pistas, se marcarán expresiones de calendario con línea discontinua. Son coincidencias de texto. Este caso constará como asistido desde ese momento.',assist:'Activar pistas para este caso',endTitle:'Fin de la revisión',seal:'Cerrar paquete y obtener recibo',historyHelp:'Fuente de referencia para comprobar el suceso a posteriori. La dirección se muestra para consulta independiente.',authored:'Las respuestas de este conjunto se redactaron para el estudio. No hubo petición a un modelo ni fichas entregadas durante la generación.',unknown:'El paquete no incluye una captura de la petición. Se desconoce qué fichas se suministraron.',observed:'Fichas extraídas de la petición local asociada a esta respuesta.',noSources:'La petición capturada contenía cero fichas.',date:'Fecha del suceso',cut:'Corte',progress:'Casos completados',time:'Tiempo activo',blind:'Modo ciego',assisted:'Caso asistido',paused:'En pausa',remove:'Quitar',nothing:'Selecciona texto dentro de la respuesta o introduce un fragmento exacto.',repeat:'Aparece varias veces. Introduce más contexto o selecciona la aparición en el texto.',overlap:'El fragmento ya está subrayado o se solapa.',saved:'Decisión guardada.',draft:'Borrador guardado.',failed:'No se pudo guardar. ',required:'Elige una etiqueta y escribe un motivo.',complete:'Puedes cerrar el paquete y entregar la base SQLite junto con su recibo.',closed:'Paquete cerrado. Entrega la base SQLite y envía la huella por separado a coordinación.',receipt:'Huella SHA-256',closeAsk:'Cerrar el paquete impide seguir editándolo. ¿Continuar?',session:'Abre el enlace completo que muestra el programa en este equipo.',network:'No se pudo contactar con la aplicación local.',sourceDate:'Fecha de la ficha',digest:'Huella de la petición',clockStop:'Se ha pausado la revisión.',mismatch:'El texto seleccionado no pertenece a esta respuesta.'},
 en:{skip:'Skip to review',title:'Review desk',start:'Start or resume',pause:'Pause',hAnswer:'Response',hPrompt:'Prompt',mark:'Underline selection',keyboard:'Select using the keyboard',findLabel:'Exact phrase',find:'Underline phrase',hContext:'What the system received',hHistory:'Retrospective reference',hReview:'Your decision',question:'Does the response say the event had already happened even though it occurred after the cutoff?',choiceLabel:'Label',empty:'Choose an option',pos:'Asserts a post-cutoff event',other:'Other response',indet:'Indeterminate',reason:'Reason or missing evidence',finish:'Save and continue',assistTitle:'Optional assistance',assistHelp:'Activating cues marks calendar expressions with a dashed line. These are text matches. The case will be recorded as assisted from that point onward.',assist:'Enable cues for this case',endTitle:'Review finished',seal:'Seal packet and get receipt',historyHelp:'Retrospective reference for checking the event. The address is provided for independent inspection.',authored:'These study responses were authored. No model request was made and no source cards were supplied during generation.',unknown:'This packet contains no request capture. Which source cards were supplied is unknown.',observed:'Source cards extracted from the local request associated with this response.',noSources:'The captured request contained zero source cards.',date:'Event date',cut:'Cutoff',progress:'Cases completed',time:'Active time',blind:'Blind mode',assisted:'Assisted case',paused:'Paused',remove:'Remove',nothing:'Select text within the response or enter an exact phrase.',repeat:'This appears more than once. Add context or select that occurrence in the text.',overlap:'This span is already underlined or overlaps another.',saved:'Decision saved.',draft:'Draft saved.',failed:'Could not save. ',required:'Choose a label and enter a reason.',complete:'Seal the packet, then return the SQLite database with its receipt.',closed:'Packet sealed. Return the SQLite database and send its digest separately to the coordinator.',receipt:'SHA-256 receipt',closeAsk:'Sealing closes the packet to further edits. Continue?',session:'Open the complete link printed by the local application.',network:'The local application could not be reached.',sourceDate:'Card date',digest:'Request digest',clockStop:'Review paused.',mismatch:'The selected text is outside this response.'}
};
let lang='es', S=null, spans=[], timer=null, chain=Promise.resolve(), draftChanged=false, changeNo=0, currentTicket=null;
let token=location.hash.slice(1);
try {
 if(token){sessionStorage.setItem('spe.desk.token',token);history.replaceState(null,'',location.pathname)}
 else token=sessionStorage.getItem('spe.desk.token')||'';
} catch(e) { /* Browsers may disallow session storage. The initial private link still works. */ }
const tab=crypto.randomUUID();
const L=k=>text[lang][k];
const say=m=>{$('message').textContent=m};
const els=(parent,tag,value,cls)=>{const el=document.createElement(tag);el.textContent=value;if(cls)el.className=cls;parent.appendChild(el);return el};
function send(action,body={}) {
 const task=async()=>{
   const response=await fetch('/api/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-Desk-Token':token,'X-Desk-Tab':tab},body:JSON.stringify(body)});
   const obj=await response.json();
   if(!response.ok)throw new Error(obj.error||L('network'));
   return obj;
 };
 const pending=chain.then(task);chain=pending.catch(()=>{});return pending;
}
function editBody(){return {ticket:S.ticket,note:$('note').value,label:$('choice').value,spans:spans.map(s=>[...s])}}
function noteEdited(){draftChanged=true;changeNo++;clearTimeout(timer);timer=setTimeout(()=>saveDraft(),450)}
async function saveDraft(){
 if(!S?.active||!draftChanged)return;
 const rev=changeNo, key=S.ticket;
 try{const fresh=await send('draft',editBody());if(S?.ticket!==key)return;
 if(rev===changeNo)draftChanged=false;
 if(!fresh.active){render(fresh);say(L('clockStop'))}else refreshClock(fresh);
 }catch(e){say(L('failed')+e.message)}
}
function refreshClock(state){S.seconds=state.seconds;$('clock').textContent=L('time')+' · '+Math.floor(S.seconds/60)+':'+String(Math.floor(S.seconds%60)).padStart(2,'0')}
function paintQuote(){
 const el=$('quote');el.replaceChildren();const chars=Array.from(S.card.text);
 const cueRanges=[];
 if(S.assisted){for(const m of S.card.text.matchAll(/\b(?:1[5-9]\d{2}|20\d{2}|21\d{2})\b/g)){
 const n=Array.from(S.card.text.slice(0,m.index)).length;cueRanges.push([n,n+m[0].length]);}}
 const points=[...new Set([0,chars.length,...spans.flat(),...cueRanges.flat()])].sort((a,b)=>a-b);
 for(let i=0;i<points.length-1;i++){const a=points[i],b=points[i+1],own=spans.some(s=>s[0]<=a&&a<s[1]),cue=cueRanges.some(s=>s[0]<=a&&a<s[1]);
 const node=els(el,'span',chars.slice(a,b).join(''));node.className=[own?'own':'',cue?'cue':''].filter(Boolean).join(' ');}
 const list=$('marks');list.replaceChildren();for(const [a,b] of spans){const item=els(list,'li',chars.slice(a,b).join(''));const btn=els(item,'button',L('remove'));btn.onclick=()=>{spans=spans.filter(x=>x[0]!==a);paintQuote();noteEdited();$('mark').focus()};}
}
function addSpan(a,b){
 if(spans.some(s=>a<s[1]&&b>s[0])){say(L('overlap'));return}
 spans.push([a,b]);spans.sort((x,y)=>x[0]-y[0]);paintQuote();noteEdited();say('');
}
function selected(){
 const sel=window.getSelection(),q=$('quote');if(!sel.rangeCount||sel.isCollapsed){say(L('nothing'));return}
 const range=sel.getRangeAt(0);if(!q.contains(range.startContainer)||!q.contains(range.endContainer)){say(L('mismatch'));return}
 const before=range.cloneRange();before.selectNodeContents(q);before.setEnd(range.startContainer,range.startOffset);
 const a=Array.from(before.toString()).length,b=a+Array.from(range.toString()).length;sel.removeAllRanges();addSpan(a,b);
}
function byPhrase(){
 const phrase=$('phrase').value,source=S.card.text,i=source.indexOf(phrase);
 if(!phrase||i<0){say(L('nothing'));return}if(source.indexOf(phrase,i+1)>=0){say(L('repeat'));return}
 const a=Array.from(source.slice(0,i)).length;addSpan(a,a+Array.from(phrase).length);$('phrase').value='';
}
function translate(){
 document.documentElement.lang=lang;document.title='SPE Audit · '+L('title');
 for(const key of Object.keys(text[lang]))if($(key)&&!['progress','clock','mode','receipt','cutoff'].includes(key))$(key).textContent=L(key);
 for(const l of ['en','es'])$(l).setAttribute('aria-pressed',String(l===lang));
 if(S)render(S,true);
}
function render(fresh,keep=false){
 const previous=S?.ticket;S=fresh;
 const end=S.sealed||S.done===S.assigned;
 $('progress').textContent=L('progress')+' · '+S.done+' / '+S.assigned;
 $('end').hidden=!end;$('start').hidden=end||!!S.active;$('pause').hidden=!S.active;$('work').hidden=!S.active;
 $('clock').hidden=end;$('mode').hidden=end;
 if(end){$('seal').hidden=S.sealed;$('endHelp').textContent=L(S.sealed?'closed':'complete');$('receipt').textContent=S.receipt?L('receipt')+' · '+S.receipt:'';return}
 refreshClock(S);$('mode').textContent=L(S.assisted?'assisted':'blind')+(S.active?'':' · '+L('paused'));
 if(!S.active)return;
 if(previous!==S.ticket||currentTicket!==S.ticket){$('assistPanel').open=false;$('phrase').value='';currentTicket=S.ticket;}
 if(!keep){spans=S.draft.spans.map(x=>[...x]);$('choice').value=S.draft.label;$('note').value=S.draft.note;draftChanged=false;}
 const c=S.card;$('cutoff').textContent=L('cut')+' · '+c.cutoff;$('prompt').textContent=c.prompt;$('prompt').lang=c.language;$('quote').lang=c.language;
 paintQuote();$('event').textContent=c.event;$('eventDate').textContent=L('date')+' · '+c.event_date;$('url').textContent=c.source_url;
 $('contextKind').textContent=L(S.context.kind);const box=$('supplied');box.replaceChildren();
 if(S.context.kind==='observed'){if(!S.context.sources.length)els(box,'p',L('noSources'));
 for(const src of S.context.sources){const item=els(box,'div','','sourceItem');if(src.date)els(item,'p',L('sourceDate')+' · '+src.date);els(item,'p',src.text,'sourceText');if(src.url)els(item,'p',src.url,'url')}
 els(box,'p',L('digest')+' · '+S.context.request_digest,'url');}
 $('assist').disabled=S.assisted;
}
async function perform(action){
 clearTimeout(timer);
 let body={};
 if(action==='finish'&&(!$('choice').value||!$('note').value.trim())){say(L('required'));return}
 if(action==='seal'&&!window.confirm(L('closeAsk')))return;
 if(action!=='state'&&action!=='seal')body=S.active?editBody():{ticket:S.ticket};
 try{
 const fresh=await send(action,body);
 if(action==='finish'){render(await send('state'));say(L('saved'));(S.done===S.assigned?$('seal'):$('start')).focus()}
 else{render(fresh);say(action==='pause'?L('clockStop'):'');if(action==='start')$('quote').focus()}
 }catch(e){say(L('failed')+e.message)}
}
for(const langCode of ['es','en'])$(langCode).onclick=()=>{lang=langCode;translate()};
for(const action of ['start','pause','assist','finish','seal'])$(action).onclick=()=>perform(action);
$('mark').onclick=selected;$('find').onclick=byPhrase;$('choice').onchange=noteEdited;$('note').oninput=noteEdited;
document.addEventListener('visibilitychange',()=>{if(document.hidden&&S?.active)perform('pause')});
setInterval(async()=>{if(!S?.active||document.hidden)return;const key=S.ticket;try{
 if(draftChanged){await saveDraft();return}const fresh=await send('state');
 if(S?.ticket===key){if(!fresh.active)render(fresh);else refreshClock(fresh)}
 }catch(e){say(L('failed')+e.message)}},4000);
translate();if(token)perform('state');else{$('start').hidden=true;say(L('session'))}
