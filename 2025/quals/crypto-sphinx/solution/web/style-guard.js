const {chromium}=require('/opt/node22/lib/node_modules/playwright');
const URL='file:///home/user/google-ctf/2025/quals/crypto-sphinx/solution/web/index.html';
let FAIL=0;
const ck=(name,cond,got)=>{ if(!cond){FAIL++;console.log('  FAIL '+name+'  got: '+got);} else console.log('  ok   '+name); };
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'});
 for(const [theme,w] of [['dark',1180],['light',1180],['dark',390]]){
  console.log('--- '+theme+' @ '+w+' ---');
  const pg=await b.newPage({viewport:{width:w,height:1100},colorScheme:theme});
  await pg.goto(URL); await pg.waitForTimeout(2400);
  await pg.click('#bnext'); await pg.waitForTimeout(420);   // step1 whitening
  await pg.click('#bnext'); await pg.waitForTimeout(620);   // step2 sbox: rolodex built + live
  const r=await pg.evaluate(()=>{
    const g=s=>getComputedStyle(document.querySelector(s));
    const win=document.querySelector('.rolo-win'), list=document.querySelector('.rolo-list');
    const row=document.querySelector('.rolo-row'), panel=win.closest('.panel');
    const wb=win.getBoundingClientRect(), pb=panel.getBoundingClientRect();
    const rows=[...document.querySelectorAll('.rolo-row')];
    // how many rows actually render inside the window box
    const inside=rows.filter(x=>{const b=x.getBoundingClientRect();
      return b.bottom>wb.top-1 && b.top<wb.bottom+1;}).length;
    return {
      overflow:g('.rolo-win').overflow, winH:Math.round(wb.height), winW:Math.round(wb.width),
      listPos:g('.rolo-list').position, rowH:Math.round(row.getBoundingClientRect().height),
      rowFont:g('.rolo-row').fontSize,
      escapes: wb.bottom>pb.bottom+2 || wb.right>pb.right+2 || wb.top<pb.top-2,
      visibleRows:inside, nrows:rows.length,
      obyteBg:g('.obyte').backgroundColor, obyteW:Math.round(document.querySelector('.obyte').getBoundingClientRect().width),
      bodyOverflow:document.documentElement.scrollWidth>document.documentElement.clientWidth+1};
  });
  ck('rolo-win clips',           r.overflow==='hidden', r.overflow);
  ck('rolo-win height bounded',  r.winH>90&&r.winH<130, r.winH);
  ck('rolo-list absolute',       r.listPos==='absolute', r.listPos);
  ck('rolo-row height 18px',     r.rowH===18, r.rowH);
  ck('rolo-row font small',      parseFloat(r.rowFont)<14, r.rowFont);
  ck('all 256 rows present',     r.nrows===256, r.nrows);
  ck('only a window of rows visible', r.visibleRows<=8, r.visibleRows);
  ck('window inside its panel',  !r.escapes, 'escaped='+r.escapes);
  ck('obyte chip styled',        r.obyteBg!=='rgba(0, 0, 0, 0)'&&r.obyteW>18, r.obyteBg+' w='+r.obyteW);
  ck('no page h-overflow',       !r.bodyOverflow, r.bodyOverflow);
  // ghost styling, mid-flight
  await pg.click('#bnext'); await pg.waitForTimeout(180);   // step3 xor: ghosts in flight
  const gh=await pg.evaluate(()=>{const g=document.querySelector('.sbghost');
    return g?{pos:getComputedStyle(g).position,z:getComputedStyle(g).zIndex,
      bg:getComputedStyle(g).backgroundColor}:null;});
  ck('sbghost fixed+styled', gh&&gh.pos==='fixed'&&gh.bg!=='rgba(0, 0, 0, 0)', JSON.stringify(gh));
  await pg.close();
 }
 console.log(FAIL? '\nSTYLE GUARD: '+FAIL+' FAILURE(S)':'\nSTYLE GUARD: all checks passed');
 await b.close(); process.exit(FAIL?1:0);
})();
