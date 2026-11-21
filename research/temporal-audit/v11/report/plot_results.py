"""Render the two study figures from scored decisions. Optional dependency: matplotlib."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

ROOT=Path(__file__).resolve().parents[1]
models=json.loads((ROOT/'results/metrics.json').read_text())['groups']['new_challenge']
reader=json.loads((ROOT/'results/reader_metrics.json').read_text())['all']
for lang in ('es','en'):
    es=lang=='es'
    fig,axes=plt.subplots(1,2,figsize=(10,3.2),layout='constrained')
    titles=['18 afirmaciones posteriores al corte','6 referencias indeterminadas'] if es else ['18 post-cutoff assertions','6 indeterminate references']
    methods=['Regla anual','Proposiciones','Lectura con IA*'] if es else ['Year rule','Proposition rule','AI reading*']
    colors=['#2249a2','#323e49','#dfE3e8']
    for ax,group,title in zip(axes,['POST_ASSERTION','INDETERMINATE'],titles):
        for y,md in enumerate([models['year_rule'],models['proposition'],reader]):
            row=md['confusion'][group]
            left=0
            for i,k in enumerate(['POST_ASSERTION','OTHER','REVIEW']):
                v=row[k]
                if v:
                    ax.barh(y,v,left=left,height=.53,color=colors[i],edgecolor='white',linewidth=.7)
                    ax.text(left+v/2,y,str(v),ha='center',va='center',color='white' if i<2 else '#19232b',fontsize=10,weight='bold')
                left+=v
        ax.set_yticks([0,1,2],methods)
        ax.invert_yaxis()
        ax.set_xlim(0,18 if group=='POST_ASSERTION' else 6)
        ax.tick_params(axis='both',length=0,pad=5)
        ax.set_xticks([])
        ax.set_title(title,loc='left',weight='bold',fontsize=12,pad=12)
        for edge in ax.spines.values(): edge.set_visible(False)
    legend=['Alerta','Otro','Revisión'] if es else ['Alert','Other','Review']
    axes[0].legend(handles=[Patch(facecolor=c,label=l) for c,l in zip(colors,legend)],
                   loc='upper left',bbox_to_anchor=(0,-.10),ncol=3,frameon=False,fontsize=9,handlelength=1.2)
    fig.savefig(ROOT/'report'/('outcomes_'+lang+'.png'),dpi=176,facecolor='white',bbox_inches='tight')
    plt.close(fig)

