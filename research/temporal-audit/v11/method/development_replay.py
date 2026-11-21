"""Optional replay on the 96 + 16 previously published English cases."""
import argparse
from pathlib import Path
import json
from calibrate import HERE,metrics
from proposition import predict


def replay(source):
    events={e['id']:e for e in json.loads((HERE/'development_events.json').read_text())}
    report={}
    old_text=set()
    for split,case_file,label_file in [('original96','cases.json','labels.json'),
                                       ('public16','challenge.json','challenge_labels.json')]:
        cases=json.loads((source/case_file).read_text())
        labels=json.loads((source/label_file).read_text())
        rows=[]
        for case in cases:
            row={'id':case['id'],'event_id':case['event'],'cutoff':case['cutoff'],'language':'en',
                 'prompt':case['prompt'],'text':case['output']}
            pred=predict(row,events[row['event_id']])
            old_text.add(row['text'].strip().casefold())
            rows.append({'id':row['id'],'gold':labels[row['id']]['label'],'decision':pred['decision']})
        report[split]=metrics(rows)
    cal=json.loads((HERE/'calibration.json').read_text())
    cal_text={r['text'].strip().casefold() for r in cal}
    report['calibration_overlap']={'exact_output_overlap_with_old':len(old_text & cal_text),
                                   'distinct_calibration_texts':len(cal_text),
                                   'shared_registered_events':len({r['event_id'] for r in cal} & set(events))}
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--data',type=Path,default=HERE.parent.parent/'study'/'data')
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    report=replay(args.data)
    text=json.dumps(report,indent=2)+'\n'
    if args.write:
        (HERE/'development_report.json').write_text(text)
    elif text!=(HERE/'development_report.json').read_text():
        raise SystemExit('Development report does not match replay.')
    print(text,end='')
