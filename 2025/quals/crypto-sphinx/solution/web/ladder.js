const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 const errs=[];const pg=await b.newPage({viewport:{width:1180,height:1000}});
 pg.on('pageerror',e=>errs.push(e.message)); pg.on('console',m=>{if(m.type()==='error')errs.push(m.text());});
 await pg.goto(URL); await pg.waitForTimeout(2600);
 console.log('options:',await pg.evaluate(()=>[...document.querySelectorAll('#rr option')].map(o=>o.textContent)));
 for(const v of ['4','5','6']){
   await pg.selectOption('#rr',v); await pg.waitForTimeout(200);
   const t0=Date.now(); await pg.click('#runr');
   await pg.waitForFunction(()=>/RECOVERED|not found|failed/.test(document.querySelector('#rout').innerText),null,{timeout:180000});
   const txt=await pg.evaluate(()=>document.querySelector('#rout').innerText);
   console.log('\n--- r1='+v+' ('+((Date.now()-t0)/1000).toFixed(1)+'s) ---');
   console.log(txt.split('\n').filter(l=>l.trim()).join('\n'));
 }
 await pg.selectOption('#rr','7'); await pg.waitForTimeout(300);
 console.log('\n--- 15 rounds (the wall) ---');
 console.log(await pg.evaluate(()=>document.querySelector('#rout').innerText));
 console.log('\nerrors:',errs.length?errs:'none');
 await b.close();
})();
