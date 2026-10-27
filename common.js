const BASE='https://asardari8633-code.github.io/proxy/',REPO='https://github.com/asardari8633-code/proxy';
const $=id=>document.getElementById(id);
const fa=n=>String(n).replace(/\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d]);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const I=n=>`<svg class="i"><use href="#ic-${n}"/></svg>`;
let _t;function toast(m){const e=$('toast');e.textContent=m;e.classList.add('show');clearTimeout(_t);_t=setTimeout(()=>e.classList.remove('show'),2200)}
async function copy(t){try{await navigator.clipboard.writeText(t);return true}catch(e){try{const a=document.createElement('textarea');a.value=t;a.style.cssText='position:fixed;opacity:0';document.body.appendChild(a);a.select();const ok=document.execCommand('copy');a.remove();return ok}catch(e2){return false}}}
function setupShare(path,text){$('shr').onclick=async()=>{const full=text+'\n\n👇 لینک سایت:\n'+BASE+path+'\n\n🔓 شفاف و بدون پنهان‌کاری: کد کامل این سایت روی گیت‌هاب بازه و هر کسی می‌تونه ببینه داخلش چیه:\n'+REPO;
  if(navigator.share){try{await navigator.share({title:document.title,text:full});return}catch(e){if(e&&e.name==='AbortError')return}}
  toast(await copy(full)?'متن و لینک کپی شد ✓':'کپی نشد')}}
function showQR(title,text){const d=$('dlg');if(!d)return;$('qrT').textContent=title;$('qr').innerHTML='';
  if(window.QRCode){try{new QRCode($('qr'),{text,width:220,height:220,correctLevel:QRCode.CorrectLevel.L})}catch(e){toast('این متن برای QR زیادی بلند است');return}}else{toast('کتابخانه‌ی QR بارگذاری نشد');return}
  try{d.showModal()}catch(e){}}
if($('close'))$('close').onclick=()=>$('dlg').close();
