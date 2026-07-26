const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 const errs=[];const pg=await b.newPage({viewport:{width:1180,height:1200},colorScheme:'dark'});
 pg.on('pageerror',e=>errs.push(e.message)); pg.on('console',m=>{if(m.type()==='error')errs.push(m.text());});
 await pg.goto(URL); await pg.waitForTimeout(2500);
 const r=await pg.evaluate(()=>{
   const rows=[...document.querySelectorAll('#dtab tr')].slice(2);
   return rows.map(tr=>{
     const td=[...tr.querySelectorAll('td')];
     const act=/active/i.test(td[1].innerText)&&!/inactive/i.test(td[1].innerText);
     const a=td[2].innerText.trim(), bb=td[3].innerText.trim(), x=td[4].innerText.trim();
     // state difference bytes are td[6..13]; byte 3 is td[9]
     const bytes=td.slice(6,14).map(c=>c.innerText.trim());
     const sbcolIsByte3 = td[9].classList.contains('sbcol');
     return {r:+td[0].innerText, act, a, bb, x, byte3:bytes[3], sbcolIsByte3,
             nonzeroElsewhere: bytes.filter((v,i)=>i!==3 && v!=='00').length};
   });
 });
 console.log('rnd act  A  B  A^B  byte3  others-nonzero');
 r.slice(0,12).forEach(x=>console.log(`  ${String(x.r).padStart(2)}  ${x.act?'ACT':'ina'}  ${x.a} ${x.bb}  ${x.x}    ${x.byte3}      ${x.nonzeroElsewhere}`));
 // invariants
 const i1 = r.every(x=>x.x===x.byte3);                       // A^B must equal state byte 3
 const i2 = r.every(x=>x.act === (x.x!=='00'));              // active iff that byte differs
 const i3 = r.every(x=>x.act === (x.a!==x.bb));              // active iff the two values differ
 const i4 = r.every(x=>x.sbcolIsByte3);                      // the boxed column is byte 3
 const i5 = r.slice(0,7).every(x=>!x.act && x.nonzeroElsewhere>0); // early rows: quiet BUT row is changing
 console.log('\nA^B == state byte 3        :',i1);
 console.log('active <=> byte3 nonzero   :',i2);
 console.log('active <=> A != B          :',i3);
 console.log('boxed column is byte 3     :',i4);
 console.log('rounds 0-6 inactive while other bytes are nonzero (the confusing case, now explained):',i5);
 console.log('errors:',errs.length?errs:'none');
 await b.close(); process.exit((i1&&i2&&i3&&i4&&i5)?0:1);
})();
