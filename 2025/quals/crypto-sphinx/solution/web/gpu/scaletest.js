const {Worker,isMainThread,parentPort,workerData}=require('worker_threads');
const fs=require('fs');
const WASM=fs.readFileSync('/tmp/sphinx/gpu/fwbench.wasm');
if(!isMainThread){
  (async()=>{
    const e=(await WebAssembly.instantiate(WASM,{})).instance.exports;
    e.seed(12345+workerData.id);
    // warm up once so instantiation and first-touch are not in the timed window
    e.run(24);
    parentPort.postMessage({t:'ready'});
    parentPort.on('message',m=>{
      if(m.t!=='go') return;
      const t0=Date.now(); for(let i=0;i<m.n;i++) e.run(24);
      parentPort.postMessage({t:'done',ms:Date.now()-t0,n:m.n});
    });
  })();
} else {
  (async()=>{
    console.log('independent 2^24 uint32 FWHTs, private 64 MB buffer each');
    console.log('cores available:',require('os').cpus().length);
    const base=[];
    for(const W of [1,2,4]){
      const ws=[...Array(W)].map((_,i)=>new Worker(__filename,{workerData:{id:i}}));
      await Promise.all(ws.map(w=>new Promise(r=>w.once('message',m=>m.t==='ready'&&r()))));
      const N=6;
      const t0=Date.now();
      const res=await Promise.all(ws.map(w=>new Promise(r=>{
        w.on('message',m=>{ if(m.t==='done') r(m); });
        w.postMessage({t:'go',n:N});
      })));
      const wall=(Date.now()-t0)/1000;
      const total=W*N;
      const perT=wall/total;
      ws.forEach(w=>w.terminate());
      if(W===1) base.push(perT);
      console.log('  '+W+' worker(s): '+total+' transforms in '+wall.toFixed(1)+'s  -> '+
        (perT*1000).toFixed(0)+' ms/transform aggregate   scaling '+(base[0]/perT).toFixed(2)+'x');
    }
  })();
}
