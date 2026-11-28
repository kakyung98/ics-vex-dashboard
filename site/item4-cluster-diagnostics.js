/* Full-corpus clustering diagnostics. The 2D plot never supplies VEX facts. */
(function(){
 const cache=new Map(),palette=['#1764a1','#b64331','#27815e','#824bab','#b06b12','#147b87','#b23c75','#596d21','#594eb5','#9b583e','#36748e','#985a91','#477641','#95650f','#626a91','#a24555','#408878','#725c3d'];
 const node=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
 const svgNode=(tag,attrs,text)=>{const n=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [k,v]of Object.entries(attrs||{}))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;};
 const number=v=>Number.isFinite(v)?v.toFixed(4):'Unavailable';
 function render(host,data,preferred){
  host.replaceChildren();host.className='cluster-diagnostics';
  host.append(node('h3','Cluster quality and projection'));
  const metrics=data.metrics,stats=node('div');stats.className='cluster-metrics';
  for(const [label,value]of [['Corpus advisories',metrics.population.toLocaleString()],['Clusters',metrics.clusters],['Silhouette · normalized SVD / cosine',number(metrics.svd_cosine_silhouette)]]){
   const card=node('div');card.append(node('span',label),node('strong',value));stats.append(card);
  }
  host.append(stats,node('p','These scores measure corpus cohesion and separation, not asset-type classification accuracy. All '+metrics.population.toLocaleString()+' advisories are included, including '+metrics.zero_feature_records+' zero-feature records.'));
  const label=node('label','Highlight a cluster '),select=node('select');select.setAttribute('aria-label','Highlight an ICSA cluster');
  data.groups.forEach((g,i)=>{const option=node('option',g.id+' · '+g.count+' advisories');option.value=g.id;select.append(option);});
  select.value=data.groups.some(g=>g.id===preferred)?preferred:data.groups[0].id;label.append(select);host.append(label);
  const summary=node('p');summary.className='cluster-selected-summary';host.append(summary);
  const chart=svgNode('svg',{viewBox:'0 0 900 450',role:'img','aria-label':'PCA scatter of all ICSA advisories, colored by K-means cluster. Black diamonds are projected BOM components.'});chart.classList.add('cluster-scatter');host.append(chart);
  chart.append(svgNode('title',{},'ICSA clusters and projected BOM component; two-dimensional display only'));
  const all=[...data.points,...data.bom_points,...data.groups.map(g=>({x:g.center[0],y:g.center[1]}))];
  const xs=all.map(p=>p.x),ys=all.map(p=>p.y),minX=Math.min(...xs),maxX=Math.max(...xs),minY=Math.min(...ys),maxY=Math.max(...ys);
  const x=v=>60+(v-minX)/(maxX-minX||1)*800,y=v=>395-(v-minY)/(maxY-minY||1)*355;
  chart.append(svgNode('rect',{x:60,y:40,width:800,height:355,fill:'#fafbfc',stroke:'#cdd3df'}));
  chart.append(svgNode('text',{x:460,y:435,'text-anchor':'middle'},'PC1 · '+(metrics.projection_explained_variance[0]*100).toFixed(1)+'% of SVD-space variance'));
  chart.append(svgNode('text',{x:18,y:220,transform:'rotate(-90 18 220)','text-anchor':'middle'},'PC2 · '+(metrics.projection_explained_variance[1]*100).toFixed(1)+'%'));
  const colors=new Map(data.groups.map((g,i)=>[g.id,palette[i%palette.length]])),dots=[];
  for(const p of data.points){
   const circle=svgNode('circle',{cx:x(p.x),cy:y(p.y),r:p.zero_features?3:2.5,fill:colors.get(p.cluster_id)});
   circle.append(svgNode('title',{},p.id+' · '+p.cluster_id+' · silhouette '+number(p.silhouette)+(p.zero_features?' · zero features':'')));chart.append(circle);dots.push({circle,id:p.cluster_id});
  }
  const center=svgNode('path',{stroke:'#172b43','stroke-width':2.5,fill:'none'});chart.append(center);
  for(const p of data.bom_points){
   const px=x(p.x),py=y(p.y),mark=svgNode('path',{d:`M ${px} ${py-8} L ${px+8} ${py} L ${px} ${py+8} L ${px-8} ${py} Z`,fill:'#111827',stroke:'#fff','stroke-width':2,tabindex:0});
   mark.append(svgNode('title',{},'BOM · '+p.name+' · '+p.cluster_id+' · centroid distance '+number(p.distance_to_centroid)+' · no corpus silhouette'));chart.append(mark);
  }
  const legend=node('div');legend.className='cluster-legend';
  data.groups.forEach(g=>{const button=node('button',g.id);button.type='button';button.style.borderColor=colors.get(g.id);button.style.color=colors.get(g.id);button.onclick=()=>{select.value=g.id;update();};legend.append(button);});host.append(legend);
  host.append(node('p','● ICSA advisory (hover for ID and silhouette) · + selected cluster centroid · ◆ current BOM component (out of sample). Overlapping points remain in the dataset.'));
  if(data.bom_projection_note)host.append(node('p',data.bom_projection_note));
  for(const p of data.bom_points)host.append(node('p','BOM: '+p.name+' · '+p.cluster_id+' · out-of-sample projection; no corpus silhouette is assigned to this point.'));
  host.append(node('p','Projection only: PCA retains '+(metrics.projection_explained_variance.reduce((a,b)=>a+b,0)*100).toFixed(1)+'% of the normalized SVD-space variance. The '+metrics.svd_dimensions+'-dimensional SVD retains '+(metrics.svd_explained_variance*100).toFixed(2)+'% of original TF-IDF variance. Quality metrics above are not computed from this 2D plot.'));
  const detail=node('details');detail.append(node('summary','Metric definitions and limitations'));
  detail.append(node('p','Silhouette: −1 to 1; higher indicates better separation in the normalized SVD space. It does not measure semantic asset-type accuracy.'),
   node('p','Negative-silhouette advisories: '+metrics.negative_silhouette_records+'. This partition was selected among '+metrics.selection_candidates+' candidates on the same corpus; independent asset-type accuracy has not been validated.'));
  host.append(detail);
  function update(){
   const g=data.groups.find(g=>g.id===select.value),px=x(g.center[0]),py=y(g.center[1]);
   for(const dot of dots)dot.circle.setAttribute('opacity',dot.id===g.id?'0.9':'0.14');
   center.setAttribute('d',`M ${px-9} ${py} H ${px+9} M ${px} ${py-9} V ${py+9}`);
   summary.textContent=g.id+' · '+g.count+' advisories · mean SVD silhouette '+number(g.silhouette);
   for(const button of legend.children)button.setAttribute('aria-pressed',String(button.textContent===g.id));
  }
  select.onchange=update;update();
 }
 window.ICSClusterDiagnostics={async mount(host,jobId,preferred){
  host.textContent='Loading frozen-model cluster diagnostics…';
  try{
   if(!cache.has(jobId))cache.set(jobId,fetch('/api/item4/analyses/jobs/'+encodeURIComponent(jobId)+'/cluster-diagnostics').then(async r=>{if(!r.ok)throw Error('HTTP '+r.status);return r.json();}).catch(e=>{cache.delete(jobId);throw e;}));
   const data=await cache.get(jobId);if(host.isConnected===false)return;render(host,data,preferred);
  }catch(e){host.textContent='Cluster diagnostics unavailable. Classification remains provisional; no quality score was assumed.';}
 }};
})();
