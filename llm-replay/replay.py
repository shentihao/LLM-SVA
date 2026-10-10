"""Offline scoring and display of archived responses. No network dependencies."""
import argparse,csv,json
from pathlib import Path
D=Path(__file__).resolve().parent

def counts(rows,key):
 c=dict(TP=0,FP=0,TN=0,FN=0)
 for r in rows:
  true=r['expected_unsafe']=='True'; pred=r[key]=='True' if key!='llm' else r[key]=='unsafe'
  c[('T' if pred==true else 'F')+('P' if pred else 'N')]+=1
 return c

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case');a=p.parse_args()
 rows=list(csv.DictReader((D/'case-results.csv').open()))
 results=json.loads((D/'responses.json').read_text())
 assert len(rows)==504 and len(results)==617
 byid={r['id']:r for r in results};assert len(byid)==617
 for r in rows:
  cid=r['case_id'];llm=byid[cid+'-llm']; decision=llm.get('parsed',{}).get('decision') if llm['status']=='ok' else 'unavailable'
  assert decision==r['llm']
  static=r['static']=='True'
  if static:
   h=byid[cid+'-hybrid'];hd=h.get('parsed',{}).get('decision') if h['status']=='ok' else 'unavailable'
   assert hd==r['hybrid_decision']
  else:hd='not_requested'
  assert (static and hd!='safe')==(r['hybrid_keep_uncertain']=='True')
  assert (static and hd=='unsafe')==(r['hybrid_unsafe_only']=='True')
 decided=[r for r in rows if r['llm'] in ('unsafe','safe')]
 output={'mode':'archived replay; no model requests','cases':len(rows),'responses':len(results),'static':counts(rows,'static'),'hybrid_keep_uncertain':counts(rows,'hybrid_keep_uncertain'),'llm_decided_n':len(decided),'llm_decided':counts(decided,'llm')}
 assert output['static']==dict(TP=78,FP=35,TN=197,FN=194)
 assert output['hybrid_keep_uncertain']==dict(TP=75,FP=12,TN=220,FN=197)
 print(json.dumps(output,indent=2))
 if a.case:
  matched=[r for r in rows if a.case in (r['original_case'],r['case_id'])]
  if not matched:p.error('Case not found')
  for r in matched:
   print(json.dumps(r,indent=2))
   for arm in ['llm','hybrid']:
    response=byid.get(r['case_id']+'-'+arm)
    if response:print(json.dumps(response,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
