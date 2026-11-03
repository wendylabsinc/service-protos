"""Exercise the actual isolated publisher with an in-memory GitHub API."""
import json
from pathlib import Path
import subprocess
import textwrap
import unittest


class PublisherTests(unittest.TestCase):
    def test_exact_revisions_drafts_forks_and_single_report(self):
        workflow = (Path(__file__).parents[1] / 'workflows/compatibility-review.yml').read_text()
        script = textwrap.dedent(workflow.split('          script: |\n', 1)[1])
        harness = r'''
const assert = require('node:assert/strict');
const script = SCRIPT;
async function run(change, existing=false, race=false) {
  const pr = {state:'open', draft:false, head:{sha:'head',repo:{full_name:'owner/repo'}},base:{sha:'base'}};
  change(pr);
  let gets=0, writes=[];
  const marker='<!-- automated-compatibility-review -->';
  let comments=existing ? [{id:1,user:{login:'github-actions[bot]'},body:marker+' old'}] : [];
  const github={rest:{pulls:{get:async()=> {
    gets++;
    if(race && gets===3) pr.head.sha='superseded';
    return {data:pr};
  }},issues:{
    listComments:()=>{},
    updateComment:async x=>{writes.push(x);comments[0].body=x.body;},
    createComment:async x=>{writes.push(x);comments=[{id:2,user:{login:'github-actions[bot]'},body:x.body}];}
  }},paginate:async()=>comments};
  const errors=[];
  process.env.REPORT_JSON=JSON.stringify(marker+' @untrusted');
  process.env.HEAD_SHA='head';process.env.BASE_SHA='base';
  const context={repo:{owner:'owner',repo:'repo'},payload:{pull_request:{number:1}}};
  await new Function('github','context','core','return (async()=>{'+script+'})()')(github,context,{setFailed:s=>errors.push(s)});
  return {writes,errors};
}
(async()=>{
  for(const change of [p=>p.head.sha='old',p=>p.base.sha='old',p=>p.draft=true,
      p=>p.state='closed',p=>p.head.repo.full_name='fork/repo']) {
    const r=await run(change);assert.equal(r.writes.length,0);assert.equal(r.errors.length,1);
  }
  for(const existing of [false,true]) {
    const r=await run(()=>{},existing);assert.equal(r.writes.length,1);assert.equal(r.errors.length,0);
    assert.equal(Boolean(r.writes[0].comment_id),existing);
  }
  const r=await run(()=>{},true,true);
  assert.equal(r.writes.length,2);assert.match(r.writes[1].body,/superseded/);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        subprocess.run(['node', '-e', harness.replace('SCRIPT', json.dumps(script), 1)], check=True)


if __name__ == '__main__':
    unittest.main()
