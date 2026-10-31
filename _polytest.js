const {JSDOM}=require('jsdom');const fs=require('fs');
let html=fs.readFileSync('/sessions/festive-gallant-turing/mnt/DueDiligence/terminal.html','utf8');
html=html.replace(/<script src="[^"]*"><\/script>/g,'<script>window.Chart=class{constructor(){}destroy(){}};</script>');
let polyQ=null;
const dom=new JSDOM(html,{runScripts:'dangerously',url:'http://localhost/i.html',beforeParse(w){
  w.fetch=(u)=>{const s=String(u);const ok=d=>Promise.resolve({ok:true,status:200,json:()=>Promise.resolve(d)});
    if(s.includes('profile2'))return ok({name:'Apple Inc',finnhubIndustry:'Technology'});
    if(s.includes('/quote'))return ok({c:230,dp:1.2});
    if(s.includes('/api/poly')){polyQ=s;return ok([
      {q:'Will Apple release a foldable iPhone in 2026?',yes:0.28,o0:'Yes',o1:'No',vol:420000,end:'2026-12-31',url:'https://polymarket.com/event/apple-foldable-2026'},
      {q:'Apple $4T market cap by end of 2026?',yes:0.61,o0:'Yes',o1:'No',vol:150000,end:'2026-12-31',url:'https://polymarket.com/event/apple-4t'}]);}
    return ok(null);};
  w.matchMedia=()=>({matches:false});
}});
const w=dom.window;const t=(n,ok,x)=>console.log(ok?'PASS':'FAIL',n,x||'');
setTimeout(async()=>{
  const $=id=>w.document.getElementById(id);
  await w.loadStock('AAPL');await new Promise(r=>setTimeout(r,200));
  t('PREDICTIONS tab present',$('centerTabs').textContent.includes('PREDICTIONS'));
  await w.loadPredictions('AAPL',false);await new Promise(r=>setTimeout(r,150));
  t('searched by company name',polyQ&&polyQ.includes('Apple%20Inc'),polyQ);
  const h=$('predictionsContent').innerHTML;
  t('markets rendered',h.includes('foldable iPhone')&&h.includes('4T market cap'));
  t('yes odds shown',h.includes('28%')&&h.includes('61%'));
  t('volume shown',h.includes('420k'));
  t('trade link',h.includes('polymarket.com/event/apple-foldable-2026'));
  t('not-advice note',h.toLowerCase().includes('not investment advice'));
  t('tab highlight aligns',(()=>{w.showTab('predictions');const on=[...w.document.querySelectorAll('.ctab')].find(x=>x.classList.contains('on'));return on&&on.textContent==='PREDICTIONS';})());
  console.log('DONE');
  w.close();process.exit(0);
},700);
