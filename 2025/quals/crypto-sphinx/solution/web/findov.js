const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 const pg=await b.newPage({viewport:{width:390,height:900}});
 await pg.goto(URL); await pg.waitForTimeout(2600);
 const out=await pg.evaluate(()=>{
   const W=document.documentElement.clientWidth, bad=[];
   document.querySelectorAll('*').forEach(el=>{
     const r=el.getBoundingClientRect();
     if(r.right>W+1 && r.width>0){
       // only report the outermost offenders
       const p=el.parentElement;
       const pr=p?p.getBoundingClientRect():null;
       if(!pr||pr.right<=W+1)
         bad.push({tag:el.tagName.toLowerCase(),cls:el.className||'',id:el.id||'',
           w:Math.round(r.width),right:Math.round(r.right),
           txt:(el.textContent||'').trim().slice(0,60)});
     }
   });
   return {W,bad:bad.slice(0,8),sw:document.documentElement.scrollWidth};
 });
 console.log('viewport',out.W,'scrollWidth',out.sw);
 out.bad.forEach(x=>console.log(' ',x.tag,'.'+x.cls,'#'+x.id,'w='+x.w,'right='+x.right,'|',x.txt));
 await b.close();
})();
