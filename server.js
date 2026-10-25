#!/usr/bin/env node
// nexoraict — تست واقعی پینگ پروکسی تلگرام (MTProto handshake واقعی، بدون وابستگی)
const net=require('net'),crypto=require('crypto'),http=require('http'),fs=require('fs'),path=require('path'),cp=require('child_process');
const PORT=+process.env.PORT||8787,HOST=process.env.HOST||'0.0.0.0',TMO=7000,CONC=30,EVERY=30*60*1000;
const SRC=[process.env.LIST_URL,'https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt','https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt'].filter(Boolean);
const now=()=>Number(process.hrtime.bigint())/1e6;
const sha=b=>crypto.createHash('sha256').update(b).digest();
const u16=n=>Buffer.from([n>>8,n&255]);

function parseSecret(s){
  let b=/^[0-9a-f]+$/i.test(s)&&s.length%2===0?Buffer.from(s,'hex'):Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64');
  if(b.length===16)return{mode:'plain',key:b};
  if(b[0]===0xdd&&b.length>=17)return{mode:'dd',key:b.subarray(1,17)};
  if(b[0]===0xee&&b.length>17)return{mode:'tls',key:b.subarray(1,17),domain:b.subarray(17).toString()||'www.google.com'};
  return null;
}
function makeInit(tag,dc){
  for(;;){
    const r=crypto.randomBytes(64),w=r.readUInt32LE(0);
    if(r[0]===0xef||[0x44414548,0x54534f50,0x20544547,0x4954504f,0x02010316,0xdddddddd,0xeeeeeeee].includes(w)||r.readUInt32LE(4)===0)continue;
    tag.copy(r,56);r.writeInt16LE(dc,60);return r;
  }
}
function ciphers(init,secret){
  const rev=Buffer.from(init.subarray(8,56)).reverse();
  let ek=init.subarray(8,40),dk=rev.subarray(0,32);
  ek=sha(Buffer.concat([ek,secret]));dk=sha(Buffer.concat([dk,secret]));
  return{enc:crypto.createCipheriv('aes-256-ctr',ek,init.subarray(40,56)),dec:crypto.createDecipheriv('aes-256-ctr',dk,rev.subarray(32,48))};
}
function reqPQ(pad){ // req_pq_multi بدون رمز، قالب padded-intermediate
  const nonce=crypto.randomBytes(16),body=Buffer.concat([Buffer.from('f18e7ebe','hex'),nonce]);
  const msg=Buffer.alloc(20+body.length-0);msg.writeBigUInt64LE(BigInt(Math.floor(Date.now()/1000))<<32n,8);msg.writeUInt32LE(body.length,16);body.copy(msg,20);
  const p=pad?crypto.randomBytes(crypto.randomInt(0,16)):Buffer.alloc(0),h=Buffer.alloc(4);h.writeUInt32LE(msg.length+p.length);
  return{pkt:Buffer.concat([h,msg,p]),nonce};
}
function clientHello(sec){ // ClientHello شبیه Chrome با HMAC سکرت (FakeTLS)
  const g=()=>{const x=(crypto.randomBytes(1)[0]&0xf0)|0x0a;return Buffer.from([x,x])};
  const ext=(t,d)=>Buffer.concat([u16(t),u16(d.length),d]);
  const name=Buffer.from(sec.domain),gs=[g(),g(),g(),g()];
  const pub=crypto.generateKeyPairSync('x25519').publicKey.export({type:'spki',format:'der'}).subarray(-32);
  const exts=[
    ext(gs[0].readUInt16BE(0),Buffer.alloc(0)),
    ext(0,Buffer.concat([u16(name.length+3),Buffer.from([0]),u16(name.length),name])),
    ext(0x17,Buffer.alloc(0)),ext(0xff01,Buffer.from([0])),
    ext(0x0a,Buffer.concat([u16(8),gs[1],u16(0x1d),u16(0x17),u16(0x18)])),
    ext(0x0b,Buffer.from([1,0])),ext(0x23,Buffer.alloc(0)),
    ext(0x10,Buffer.concat([u16(12),Buffer.from([2]),Buffer.from('h2'),Buffer.from([8]),Buffer.from('http/1.1')])),
    ext(5,Buffer.from([1,0,0,0,0])),
    ext(0x0d,Buffer.concat([u16(16),...[0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601].map(u16)])),
    ext(0x12,Buffer.alloc(0)),
    ext(0x33,Buffer.concat([u16(41),gs[2],u16(1),Buffer.from([0]),u16(0x1d),u16(32),pub])),
    ext(0x2d,Buffer.from([1,1])),
    ext(0x2b,Buffer.concat([Buffer.from([6]),gs[3],Buffer.from([3,4,3,3])])),
    ext(0x1b,Buffer.from([2,0,2])),
    ext(g().readUInt16BE(0),Buffer.from([0]))
  ];
  const suites=Buffer.concat([g(),...[0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35].map(u16)]);
  const head=Buffer.concat([Buffer.from([3,3]),Buffer.alloc(32),Buffer.from([32]),crypto.randomBytes(32),u16(suites.length),suites,Buffer.from([1,0])]);
  let ex=Buffer.concat(exts);const pad=517-(5+4+head.length+2+ex.length)-4;
  if(pad>0)ex=Buffer.concat([ex,ext(0x15,Buffer.alloc(pad))]);
  const hs=Buffer.concat([head,u16(ex.length),ex]),l=hs.length;
  const rec=Buffer.concat([Buffer.from([0x16,3,1]),u16(l+4),Buffer.from([1,0,l>>8,l&255]),hs]);
  const d=crypto.createHmac('sha256',sec.key).update(rec).digest(),ts=Buffer.alloc(4);ts.writeUInt32LE(Math.floor(Date.now()/1000));
  for(let i=0;i<4;i++)d[28+i]^=ts[i];d.copy(rec,11);return rec;
}

function check({host,port,secret}){return new Promise(resolve=>{
  const sec=/^[a-z0-9._-]+$/i.test(host||'')&&port>0&&port<65536&&parseSecret(String(secret||''));
  if(!sec)return resolve({ok:false,error:'bad-input',stage:'init'});
  const t0=now();let t1=0,tcp=null,stage='connect',done=false,tReq=0,enc,dec,nonce,rx=Buffer.alloc(0),tb=Buffer.alloc(0),seen=0,ready=sec.mode!=='tls';
  const s=net.connect({host,port:+port});s.setNoDelay(true);
  const fin=o=>{if(done)return;done=true;clearTimeout(tm);s.destroy();resolve({tcp,stage,...o})};
  const tm=setTimeout(()=>fin({ok:false,error:'timeout'}),TMO);
  const wrap=d=>sec.mode==='tls'?Buffer.concat([Buffer.from([0x17,3,3]),u16(d.length),d]):d;
  const start=()=>{
    const init=makeInit(Buffer.from(sec.mode==='plain'?'eeeeeeee':'dddddddd','hex'),2),c=ciphers(init,sec.key);enc=c.enc;dec=c.dec;
    const e=enc.update(init),first=Buffer.concat([init.subarray(0,56),e.subarray(56)]);
    const r=reqPQ(sec.mode!=='plain');nonce=r.nonce;const ct=enc.update(r.pkt);
    if(sec.mode==='tls')s.write(Buffer.from('140303000101','hex'));
    stage='mtproto';s.write(wrap(first));tReq=now();s.write(wrap(ct));
  };
  const onData=d=>{
    rx=Buffer.concat([rx,dec.update(d)]);if(rx.length<4)return;
    const l=rx.readUInt32LE(0)&0x7fffffff;if(rx.length<4+l)return;const p=rx.subarray(4,4+l),ms=now()-tReq;
    if(l===4)return fin({ok:false,error:'dc-error '+p.readInt32LE(0)});
    if(l>=40&&p.readUInt32LE(20)===0x05162463&&p.subarray(24,40).equals(nonce))return fin({ok:true,ping:Math.max(1,Math.round(ms))});
    fin({ok:false,error:'bad-reply'});
  };
  s.on('lookup',()=>{t1=now()});
  s.on('connect',()=>{tcp=Math.max(1,Math.round(now()-(t1||t0)));if(sec.mode==='tls'){stage='faketls';s.write(clientHello(sec))}else start()});
  s.on('error',e=>fin({ok:false,error:e.code||e.message}));
  s.on('close',()=>fin({ok:false,error:'closed'}));
  s.on('data',d=>{
    if(sec.mode!=='tls')return onData(d);
    tb=Buffer.concat([tb,d]);
    while(tb.length>=5){
      const l=tb.readUInt16BE(3);if(tb.length<5+l)break;const t=tb[0],p=tb.subarray(5,5+l);tb=tb.subarray(5+l);
      if(!ready){if(seen++===0&&t!==0x16)return fin({ok:false,error:'not-faketls'});if(t===0x17){ready=true;start()}}
      else if(t===0x17)onData(p);
    }
  });
})}


/* ---- سرویس: خودش لیست را می‌گیرد و هر ۳۰ دقیقه تست می‌کند؛ کاربر هدفی نمی‌فرستد (جلوگیری از سوءاستفاده) ---- */
let S={items:[],testedAt:0,testing:false,done:0,total:0,nextAt:0};
function parseList(t){const seen=new Set(),out=[];for(let l of t.split(/\r?\n/)){l=l.trim();if(!l)continue;try{const u=new URL(l.replace(/^tg:\/\//,'https://t.me/')),sv=u.searchParams.get('server'),p=u.searchParams.get('port'),k=u.searchParams.get('secret');if(!sv||!p||!k)continue;const id=sv.toLowerCase()+':'+p+':'+k;if(seen.has(id))continue;seen.add(id);out.push({server:sv.replace(/\.$/,''),port:+p,secret:k})}catch(e){}}return out}
async function fetchList(){
  for(const u of SRC){try{const r=await fetch(u,{signal:AbortSignal.timeout(15000)});if(r.ok){const a=parseList(await r.text());if(a.length)return a}}catch(e){}}
  try{return parseList(fs.readFileSync(path.join(__dirname,'proxies.txt'),'utf8'))}catch(e){return []}
}
async function cycle(){
  if(S.testing)return;S.testing=true;
  const list=await fetchList();
  if(!list.length){S.testing=false;S.nextAt=Date.now()+5*60*1000;return}
  const old=new Map(S.items.map(i=>[i.server+':'+i.port+':'+i.secret,i.r]));
  S.items=list.map((p,id)=>({id,...p,r:old.get(p.server+':'+p.port+':'+p.secret)}));
  S.done=0;S.total=S.items.length;let i=0;
  const w=async()=>{while(i<S.items.length){const it=S.items[i++];it.r=await check({host:it.server,port:it.port,secret:it.secret});S.done++}};
  await Promise.all(Array.from({length:CONC},w));
  S.testedAt=Date.now();S.testing=false;S.nextAt=Date.now()+EVERY;
}
http.createServer((req,res)=>{
  const u=new URL(req.url,'http://l'),j=(o)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(o))};
  if(u.pathname==='/api/ping'){res.writeHead(200);return res.end('ok')}
  if(u.pathname==='/api/list')return j({...S,now:Date.now()});
  if(req.method==='POST'&&u.pathname==='/api/retest'){const ok=!S.testing&&Date.now()-S.testedAt>120000;if(ok)cycle();return j({started:ok})}
  const ST={'/logo.jpg':'image/jpeg','/icon-192.png':'image/png','/icon-512.png':'image/png','/manifest.webmanifest':'application/manifest+json','/sw.js':'text/javascript'};
  if(ST[u.pathname])return fs.readFile(path.join(__dirname,u.pathname),(e,d)=>{res.writeHead(e?404:200,{'Content-Type':ST[u.pathname],'Cache-Control':'public, max-age=3600'});res.end(d||'')});
  fs.readFile(path.join(__dirname,'telegram-proxy.html'),(e,d)=>{res.writeHead(e?404:200,{'Content-Type':'text/html; charset=utf-8'});res.end(d||'not found')});
}).listen(PORT,HOST,()=>{
  console.log('\n  پروکسی تلگرام (nexoraict)  →  http://localhost:'+PORT+'\n');
  if(process.stdout.isTTY&&!process.env.NO_OPEN)try{cp.exec((process.platform==='win32'?'start ""':process.platform==='darwin'?'open':'xdg-open')+' http://localhost:'+PORT)}catch(e){}
  cycle();setInterval(cycle,EVERY);
});
