const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 const errs=[];const pg=await b.newPage({viewport:{width:1180,height:1000}});
 pg.on('pageerror',e=>errs.push('PAGEERROR: '+e.message));
 pg.on('console',m=>{if(m.type()==='error')errs.push(m.text());});
 await pg.goto(URL); await pg.waitForTimeout(2600);
 const t0=Date.now();
 await pg.click('#runr');
 const poll=setInterval(async()=>{try{
   console.log('  ['+((Date.now()-t0)/1000).toFixed(0)+'s] '+
     await pg.evaluate(()=>document.querySelector('#rstat').innerText));}catch(_){}} ,15000);
 await pg.waitForFunction(()=>{const t=document.querySelector('#rout').innerText;
   return /KEY RECOVERED|MISMATCH|failed|nothing|will not let/.test(t);},null,{timeout:600000});
 clearInterval(poll);
 console.log('elapsed: '+((Date.now()-t0)/1000).toFixed(0)+'s');
 console.log('----- panel -----');
 console.log(await pg.evaluate(()=>document.querySelector('#rout').innerText));
 console.log('----- status: '+await pg.evaluate(()=>document.querySelector('#rstat').innerText));
 console.log('errors:',errs.length?errs:'none');
 await b.close();
})();
