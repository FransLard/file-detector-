const $=id=>document.getElementById(id);
const drop=$('drop'),file=$('file'),rep=$('rep');
const COLORS={CLEAN:'#22c55e',LOW:'#38bdf8',MEDIUM:'#eab308',HIGH:'#f97316',MALICIOUS:'#ef4444'};

fetch('/api/health').then(r=>r.json()).then(h=>{
  const mb=(h.max_bytes/1048576)|0;
  $('health').textContent=`engine ok • pefile:${h.pefile?'✓':'—'} yara:${h.yara?'✓':'fallback'} • maks ${mb}MB`;
}).catch(()=>{$('health').textContent='⚠️ server tidak terjangkau — restart python app.py';});

function fmtMB(n){return n>1048576?(n/1048576).toFixed(1)+' MB':(n/1024).toFixed(0)+' KB';}
async function scanFile(f){
  const fd=new FormData();fd.append('file',f);
  $('result').classList.remove('hidden');
  $('rFile').textContent='⏳ Memindai '+f.name+' ('+fmtMB(f.size)+') ...';
  $('rMeta').textContent='Mengupload & menganalisis, mohon tunggu...';
  try{
    const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),120000);
    const r=await fetch('/api/scan?reputation='+(rep.checked?'1':'0'),{method:'POST',body:fd,signal:ctrl.signal});
    clearTimeout(to);
    const txt=await r.text();
    let j;try{j=JSON.parse(txt);}catch{throw new Error('Server menolak file ('+r.status+'). '+(txt.slice(0,120)||'Coba file < 100MB'));}
    if(!r.ok||j.error){$('rFile').textContent='❌ '+(j.error||('HTTP '+r.status));return;}
    render(j);
  }catch(err){
    if(err.name==='AbortError')$('rFile').textContent='❌ Timeout 120 detik — file terlalu besar / server sibuk. Matikan "cek reputasi online" lalu coba lagi.';
    else $('rFile').textContent='❌ '+err.message+' — pastikan server jalan (python app.py).';
  }
}
function render(j){
  $('rFile').textContent=(j.blocked?'⛔ ':'✅ ')+j.filename+` • ${j.family}`;
  $('rMeta').textContent=`${j.size_human} • entropi ${j.entropy} • ${j.magic} • ${j.mime} • SHA256 ${j.hashes.sha256.slice(0,16)}…`;
  $('rScore').textContent=j.score;
  const lv=$('rLevel');lv.textContent=j.verdict.level;
  lv.style.background=COLORS[j.verdict.level]+'22';lv.style.color=COLORS[j.verdict.level];
  lv.style.border=`1px solid ${COLORS[j.verdict.level]}`;
  $('rBar').style.width=j.score+'%';$('rBar').style.background=COLORS[j.verdict.level];
  $('rAction').textContent=j.verdict.action+(j.blocked?' (file DITOLAK upload)':'');
  $('rHash').textContent=`MD5    : ${j.hashes.md5}\nSHA1   : ${j.hashes.sha1}\nSHA256 : ${j.hashes.sha256}`;
  $('rIdent').textContent=`Magic  : ${j.magic}\nMIME   : ${j.mime}\nEkst   : ${j.ext.ext}  semua:${JSON.stringify(j.ext.all_exts)}\nGanda? : ${j.ext.double_ext}  spoof? ${j.ext.spoofed_double_ext}`;
  $('rCount').textContent=j.reasons.length;
  $('rRows').innerHTML=j.reasons.map(x=>`<tr><td><b>+${x.weight}</b></td><td>${x.label}</td><td>${x.family}</td><td>${x.description}</td></tr>`).join('')||'<tr><td colspan=4>Tidak ada temuan — bersih.</td></tr>';
  $('rRep').textContent=JSON.stringify(j.reputation,null,2);
  $('result').scrollIntoView({behavior:'smooth'});
}
drop.onclick=e=>{if(e.target.tagName!=='BUTTON'&&e.target.tagName!=='INPUT'&&e.target.tagName!=='LABEL')file.click();};
file.onchange=()=>file.files[0]&&scanFile(file.files[0]);
['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];f&&scanFile(f);});
$('eicarBtn').onclick=e=>{e.stopPropagation();location.href='/api/eicar';};
$('eicarScan').onclick=async e=>{
  e.stopPropagation();
  const s='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-' + 'STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  scanFile(new File([s],'eicar-test.txt',{type:'text/plain'}));
};
