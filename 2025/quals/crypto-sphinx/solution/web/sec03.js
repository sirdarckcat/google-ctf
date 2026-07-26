const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 const errs=[];const pg=await b.newPage({viewport:{width:1180,height:1200},colorScheme:'dark'});
 pg.on('pageerror',e=>errs.push(e.message)); pg.on('console',m=>{if(m.type()==='error')errs.push(m.text());});
 await pg.goto(URL); await pg.waitForTimeout(2600);
 // A/B table correctness
 const ab=await pg.evaluate(()=>[...document.querySelectorAll('#abtab tr')].slice(1).map(r=>
   [...r.querySelectorAll('td')].map(c=>c.innerText.trim()).slice(0,4).join(' ')));
 console.log('A/B table (round A B input):'); ab.forEach(r=>console.log('   '+r));
 // check A^B==input for every row
 const ok=await pg.evaluate(()=>[...document.querySelectorAll('#abtab tr')].slice(1).every(r=>{
   const c=[...r.querySelectorAll('td')].map(x=>x.innerText.trim());
   return (parseInt(c[1],16)^parseInt(c[2],16))===parseInt(c[3],16);}));
 console.log('A xor B == input for all rows:',ok);
 // sweep
 await pg.click('#runsw'); await pg.waitForTimeout(800);
 const sw=await pg.evaluate(()=>({stat:document.querySelector('#swstat').innerText,
   cells:document.querySelectorAll('#swgrid .swc').length,
   hits:document.querySelectorAll('#swgrid .swc.hit').length,
   out:document.querySelector('#swout').innerText.split('\n').filter(x=>x.trim()).slice(0,4).join(' / ')}));
 console.log('sweep:',JSON.stringify(sw));
 // click a hit -> trail should adopt that delta and show a quiet round
 if(sw.hits){
   await pg.click('#swgrid .swc.hit'); await pg.waitForTimeout(600);
   const after=await pg.evaluate(()=>({dv:document.querySelector('#dv').value,
     quiet:[...document.querySelectorAll('#dtab tr')].slice(1).map((r,i)=>
       /inactive/i.test(r.innerText)?i:null).filter(x=>x!==null&&x>=10)}));
   console.log('after clicking a hit: delta =',after.dv,' quiet rounds >=10:',after.quiet);
 }
 const hs=await pg.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1);
 console.log('hscroll:',hs,'errors:',errs.length?errs:'none');
 await b.close();
})();
