"""Render fixed-study depth curves; dispersion bands are not confidence intervals."""
import argparse
import json
from pathlib import Path
import shutil

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
LABELS={'svd_kmeans':'TF-IDF/SVD + K-means','ssl_kmeans':'DAE + K-means','ssl_ward':'DAE + Ward'}
COLORS={'svd_kmeans':'#4866b0','ssl_kmeans':'#d78a21','ssl_ward':'#168b79'}


def render(out):
    comparison=json.loads((out/'comparison_summary.json').read_text(encoding='utf-8'))
    stability=json.loads((out/'stability_summary.json').read_text(encoding='utf-8'))
    fig,axes=plt.subplots(2,3,figsize=(15,8.5))
    fig.subplots_adjust(top=.84,bottom=.12,hspace=.45,wspace=.3)
    configs=[('A. Native-space separation','seed','native_silhouette',comparison,'Cosine silhouette'),
             ('B. Common-reference separation','seed','reference_silhouette',comparison,'Cosine silhouette'),
             ('C. Seed stability','seed','ari_nondegenerate_pairs',stability,'ARI'),
             ('D. Frozen-representation subsampling','frozen_resample','ari_nondegenerate_pairs',stability,'ARI'),
             ('E. Full-pipeline subsampling','pipeline_resample','ari_nondegenerate_pairs',stability,'ARI'),
             ('F. Partition size','seed','clusters',comparison,'Number of clusters')]
    for ax,(title,family,metric,rows,ylabel) in zip(axes.flat,configs):
        for method,label in LABELS.items():
            selected=sorted((r for r in rows if r['family']==family and r['method']==method),key=lambda r:r['depth'])
            if not selected:continue
            depth=np.array([r['depth'] for r in selected])
            mean=np.array([r[metric]['mean'] if r[metric]['mean'] is not None else np.nan for r in selected])
            sd=np.array([r[metric]['std'] if r[metric]['std'] is not None else np.nan for r in selected])
            ax.plot(depth,mean,marker='o',markersize=4,lw=1.8,color=COLORS[method],label=label)
            ax.fill_between(depth,mean-sd,mean+sd,color=COLORS[method],alpha=.13,linewidth=0)
        ax.set_title(title,loc='left',fontsize=11,fontweight='bold')
        ax.set_xlabel('Hierarchy depth (synthetic root = 0)');ax.set_ylabel(ylabel)
        ax.set_xticks(range(1,7));ax.grid(alpha=.2)
        ax.spines[['top','right']].set_visible(False)
    handles,labels=axes[0,0].get_legend_handles_labels()
    fig.legend(handles,labels,loc='upper center',bbox_to_anchor=(.5,.94),ncol=3,frameon=False)
    fig.suptitle('Item #4: self-supervised representation learning followed by hierarchical clustering',fontsize=14,y=.985)
    fig.supxlabel('Bands: mean ± SD. ARI bands summarize correlated run pairs, not confidence intervals. No semantic ground truth.',fontsize=9,y=.025)
    fig.savefig(out/'comparison.png',dpi=170)
    fig.savefig(out/'comparison.svg')
    plt.close(fig)
    report=out/'report.html'
    page=report.read_text(encoding='utf-8')
    if 'comparison.png' not in page:
        page=page.replace('<table>','<figure><img src="comparison.png" alt="Depth-wise separation and stability comparisons" style="width:100%;height:auto"><figcaption>음영은 표준편차이며 신뢰구간이 아닙니다.</figcaption></figure><table>',1)
        report.write_text(page,encoding='utf-8')
    snapshot=out/'code_snapshot'/Path(__file__).name
    shutil.copyfile(Path(__file__),snapshot)
    print(str(out/'comparison.png'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='results/item4_ssl_hierarchy_v1')
    render(ROOT/parser.parse_args().output)
