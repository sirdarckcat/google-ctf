// Deliberately sets NO COOP/COEP, to stand in for GitHub Pages.
const http=require('http'),fs=require('fs'),p=require('path');
const types={'.html':'text/html','.js':'application/javascript'};
http.createServer((req,res)=>{
  const f=p.join('/tmp/sphinx/sw',req.url==='/'?'index.html':req.url.split('?')[0]);
  fs.readFile(f,(e,d)=>{
    if(e){res.writeHead(404);res.end('no');return;}
    res.writeHead(200,{'Content-Type':types[p.extname(f)]||'text/plain',
      'Service-Worker-Allowed':'/'});
    res.end(d);
  });
}).listen(8099,()=>console.log('serving on 8099 with no isolation headers'));
