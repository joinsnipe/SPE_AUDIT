/* Browser counterpart of study/capture.py for the published text-and-cards schema. */
"use strict";
const SPECapture = (() => {
  const policy = "source-publication-date-on-or-before-cutoff/1";
  const schema = "spe-temporal-capture/1";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", {fatal:true, ignoreBOM:true});
  const bytes = text => {
    const encoded = encoder.encode(text);
    if (decoder.decode(encoded) !== text) throw Error("Invalid Unicode");
    return encoded;
  };
  function canonical(value) {
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    if (value !== null && typeof value === "object") {
      return "{" + Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
    }
    return JSON.stringify(value);
  }
  const hex = data => Array.from(data, x => x.toString(16).padStart(2, "0")).join("");
  // SHA-256 fallback for browsers that withhold WebCrypto for a local file.
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const rotate = (x,n) => (x>>>n) | (x<<(32-n));
  function sha256Local(input) {
    const padded = new Uint8Array(Math.ceil((input.length+9)/64)*64);
    padded.set(input); padded[input.length]=128;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length-8, Math.floor(input.length / 0x20000000));
    view.setUint32(padded.length-4, (input.length*8)>>>0);
    const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const w = new Uint32Array(64);
    for (let off=0;off<padded.length;off+=64) {
      for(let i=0;i<16;i++) w[i]=view.getUint32(off+4*i);
      for(let i=16;i<64;i++){
        const u=w[i-15],v=w[i-2];
        w[i]=w[i-16]+(rotate(u,7)^rotate(u,18)^(u>>>3))+w[i-7]+(rotate(v,17)^rotate(v,19)^(v>>>10));
      }
      let [a,b,c,d,e,f,g,j]=h;
      for(let i=0;i<64;i++){
        const t=(j+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i])>>>0;
        const s=((rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
        j=g;g=f;f=e;e=(d+t)>>>0;d=c;c=b;b=a;a=(t+s)>>>0;
      }
      [a,b,c,d,e,f,g,j].forEach((v,i)=>h[i]=(h[i]+v)>>>0);
    }
    return h.map(v=>v.toString(16).padStart(8,"0")).join("");
  }
  async function sha(input) {
    return globalThis.crypto?.subtle ? hex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256",input))) : sha256Local(input);
  }
  function validDay(day) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day.startsWith("0000")) return false;
    const time=Date.parse(day+"T00:00:00Z");
    return Number.isFinite(time) && new Date(time).toISOString().slice(0,10)===day;
  }
  function request(cutoff, prompt, cards) {
    if (!validDay(cutoff) || !prompt.trim()) throw Error("Invalid request");
    const ids=new Set();
    for(const card of cards) {
      if(Object.keys(card).sort().join(",")!=="date,id,text,url" || Object.values(card).some(x=>typeof x!=="string"||!x.trim()) || ids.has(card.id) || !validDay(card.date)) throw Error("Invalid source card");
      ids.add(card.id);
    }
    const sources=cards.filter(c=>c.date<=cutoff).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    return bytes(canonical({cutoff,policy_id:policy,prompt,sources}));
  }
  function latest(input) {
    const {sources}=JSON.parse(decoder.decode(input));
    const ordered=sources.sort((a,b)=>a.date===b.date ? (a.id<b.id?-1:1) : (a.date<b.date?-1:1));
    return ordered.length ? ordered[ordered.length-1].text : "No eligible source.";
  }
  async function seal(raw, output) {
    const [request_sha256,output_sha256]=await Promise.all([sha(raw),sha(bytes(output))]);
    const body={schema,policy_id:policy,request_utf8:decoder.decode(raw),request_sha256,output,output_sha256};
    return {...body,record_sha256:await sha(bytes(canonical(body)))};
  }
  return {bytes,decoder,hex,canonical,sha,sha256Local,validDay,request,latest,seal};
})();
if(typeof module!=="undefined" && module.exports) module.exports=SPECapture;
