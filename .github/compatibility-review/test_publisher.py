"""Exercise the actual isolated publisher with an in-memory GitHub API."""
import json
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


class PublisherTests(unittest.TestCase):
    def test_base_retarget_event_without_head_push(self):
        workflow = (Path(__file__).parents[1] / 'workflows/compatibility-review.yml').read_text()
        events = re.search(r'types: \[(.*?)\]', workflow)[1].split(', ')
        self.assertIn('edited', events)
        condition = re.search(r'    if: >-\n(.*?)    runs-on:', workflow, re.S)[1].strip()
        group = re.search(r'group: .*\$\{\{ (github.event.action.*?) \}\}', workflow)[1]
        # GitHub's missing properties evaluate as null. Optional chaining gives
        # the fixture the same behavior for absent changes.base in JavaScript.
        def javascript(expression):
            return expression.replace('github.event.changes.base', 'event.changes?.base').replace('github.event.', 'event.').replace('github.repository', 'repository')
        harness = r'''
const assert = require('node:assert/strict');
const repository = 'owner/repo';
const eligible = new Function('event', 'repository', 'return (' + CONDITION + ')');
const group = new Function('event', 'return (' + GROUP + ')');
const event = {action:'edited', changes:{base:{ref:{from:'parent'}}},
  pull_request:{draft:false, head:{sha:'unchanged-head',repo:{full_name:repository}},
    base:{ref:'master',sha:'new-base'}}};
assert.equal(eligible(event, repository), true);
assert.equal(group(event), 'comparison');
for (const changes of [{body:{from:'old'}}, {title:{from:'old'}}, {}]) {
  event.changes=changes;
  assert.equal(eligible(event, repository), false);
  assert.equal(group(event), 'metadata'); // Chatter cannot displace any comparison.
}
for (const action of ['opened','ready_for_review','reopened','synchronize']) {
  event.action=action; delete event.changes;
  assert.equal(eligible(event, repository), true);
  assert.equal(group(event), 'comparison');
}
event.action='edited'; event.changes={base:{ref:{from:'parent'}}};
event.pull_request.draft=true;
assert.equal(eligible(event, repository), false);
event.pull_request.draft=false; event.pull_request.head.repo.full_name='fork/repo';
assert.equal(eligible(event, repository), false);
'''
        harness = harness.replace('CONDITION', json.dumps(javascript(condition)), 1)
        harness = harness.replace('GROUP', json.dumps(javascript(group)), 1)
        subprocess.run(['node', '-e', harness], check=True)

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
