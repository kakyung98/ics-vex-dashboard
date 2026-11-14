"""Compare exact full-population leaf metrics and repeated-run stability."""
import json
from pathlib import Path
import shutil

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[1]


def main():
    roots=[ROOT/'results/item4_prototype_hierarchy_v1',ROOT/'results/item4_cisa_lowrank_v1']
    entries=[]
    for root in roots:
        results=json.loads((root/'results.json').read_text(encoding='utf-8'))
        stability=json.loads((root/'stability_summary.json').read_text(encoding='utf-8'))
        for row in results:
            candidate=row['candidate'];rep=row['representation']
            if root.name=='item4_prototype_hierarchy_v1' and candidate=='best_cisa_reference':continue
            relevant=[s for s in stability if s['candidate']==candidate and s['resolution_level']==6]
            stat={s['family']:s['ari'] for s in relevant}
            if rep.startswith('current_mix'):name='Mixed'
            elif rep.startswith('cisa_context'):name='CISA context'
            elif rep.startswith('cisa_advisory'):name='CISA advisory'
            else:name='CISA scoped'
            model=rep.rsplit('_',2)[-2].replace('raw','SVD').replace('dae','DAE').replace('neighbor','Contrastive')
            entries.append(dict(label=f"{name}\n{model}\n{row['clusters']} clusters",native=row['full_native_silhouette'],
                                reference=row['full_reference_silhouette'],stats=stat,source=str(root),candidate=candidate))
    x=np.arange(len(entries));width=.36
    fig,axes=plt.subplots(2,1,figsize=(15,9),sharex=True)
    fig.subplots_adjust(top=.89,bottom=.19,hspace=.23,left=.065,right=.985)
    a=axes[0]
    for offset,key,label,color in [(-width/2,'native','Native (own representation)','#dd8c27'),
                                   (width/2,'reference','Fixed common reference','#3d6db5')]:
        bars=a.bar(x+offset,[e[key] for e in entries],width,label=label,color=color)
        a.bar_label(bars,fmt='%.3f',padding=3,fontsize=9)
    a.set_title('A. Exact full-population leaf separation',loc='left',fontweight='bold')
    a.set_ylabel('Cosine silhouette');a.set_ylim(0,max(.75,max(e['native'] for e in entries)+.1));a.legend(frameon=False,ncol=2,loc='upper left')
    a=axes[1]
    for offset,key,label,color in [(-width/2,'seed','5 full-population seeds','#277f70'),
                                   (width/2,'frozen_resample','10 frozen-view subsamples','#9370b2')]:
        means=[e['stats'][key]['mean'] for e in entries];std=[e['stats'][key]['std'] for e in entries]
        bars=a.bar(x+offset,means,width,yerr=std,capsize=2,label=label,color=color,error_kw={'lw':.8})
        a.bar_label(bars,fmt='%.3f',padding=3,fontsize=9)
    a.set_title('B. Leaf partition stability (mean ARI; error bars = pair SD)',loc='left',fontweight='bold')
    a.set_ylabel('Adjusted Rand index');a.set_ylim(0,1.12);a.legend(frameon=False,ncol=2,loc='upper left')
    a.set_xticks(x,[e['label'] for e in entries],fontsize=10)
    for a in axes:
        a.set_axisbelow(True);a.grid(axis='y',alpha=.2);a.spines[['top','right']].set_visible(False)
    fig.suptitle('Selected CVE cluster configurations: all 12,418 targets retained',fontsize=15,y=.975)
    fig.text(.5,.035,'Native spaces differ. ARI pairs are correlated; SD is not a confidence interval. No semantic ground truth.',ha='center',fontsize=10)
    out=roots[1]
    fig.savefig(out/'overview.png',dpi=170);fig.savefig(out/'overview.svg');plt.close(fig)
    (out/'overview_data.json').write_text(json.dumps(entries,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    snap=out/'code_snapshot';snap.mkdir(exist_ok=True);shutil.copyfile(Path(__file__),snap/Path(__file__).name)
    page=out/'report.html';text=page.read_text(encoding='utf-8')
    if 'overview.png' not in text:
        text=text.replace('<table>','<figure><img src="overview.png" style="width:100%;height:auto" alt="Exact silhouette and stability of selected models"><figcaption>모든 CVE를 포함한 전수 점수와 반복 안정성. Native 공간은 서로 다릅니다.</figcaption></figure><table>',1)
        page.write_text(text,encoding='utf-8')
    print(out/'overview.png')


if __name__=='__main__':main()
