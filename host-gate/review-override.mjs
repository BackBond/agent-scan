// Operator-owned local decision record, not an agent-supplied bypass flag.
import {openSync,readSync,fstatSync,closeSync,constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {GateError,SCANNER_SHA256} from './host-gate.mjs';

const fields=['protocol','approval_id','operator','approved_at','expires_at',
  'manifest_sha256','scanner_sha256','ruleset_sha256','profile_sha256','accepted_review_codes','reason'];
const digest=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const label=s=>typeof s==='string'&&s.trim()===s&&s.length>0&&s.length<=200&&!/[\x00-\x1f\x7f]/.test(s);
const time=s=>typeof s==='string'&&/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(s)&&Number.isFinite(Date.parse(s));
const fail=code=>{throw new GateError(code);};

function readRecord(path,limit,kind) {
  let fd,bytes;
  try {
    fd=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW||0)|(constants.O_NONBLOCK||0));
    const stat=fstatSync(fd);
    if(!stat.isFile()||stat.size>limit)fail(kind+'_invalid');
    const buffer=Buffer.alloc(limit+1);let length=0;
    while(length<buffer.length){const n=readSync(fd,buffer,length,buffer.length-length,null);if(!n)break;length+=n;}
    if(length>limit)fail(kind+'_invalid');
    bytes=buffer.subarray(0,length);
  } catch(e) {if(e instanceof GateError)throw e;fail(kind+'_unavailable');}
  finally {if(fd!==undefined)closeSync(fd);}
  try{return {data:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),sha256:createHash('sha256').update(bytes).digest('hex')};}
  catch{fail(kind+'_invalid');}
}

export function createReviewPolicy({path,revocationsPath,now=()=>Date.now()}) {
  function check({snapshot,report}) {
    // No file, flag, or operator record can permit BLOCK or scanner failures.
    if(report.decision!=='review')return null;
    if(!path)fail('review');
    const {data:r,sha256:recordHash}=readRecord(path,16384,'review_override');
    const reject=fail;
    if(!r||Array.isArray(r)||Object.keys(r).some(k=>!fields.includes(k))
      ||r.protocol!=='backbond-review-override/v1'||!label(r.approval_id)||!label(r.operator)
      ||!label(r.reason)||!time(r.approved_at)||Date.parse(r.approved_at)>now()
      ||(r.expires_at!==undefined&&(!time(r.expires_at)||Date.parse(r.expires_at)<=now()||Date.parse(r.expires_at)<=Date.parse(r.approved_at)))
      ||!digest(r.manifest_sha256)||!Array.isArray(r.accepted_review_codes))reject('review_override_invalid');
    const {data:revocations,sha256:revocationsHash}=readRecord(revocationsPath,65536,'review_override_revocations');
    if(!revocations||Array.isArray(revocations)||revocations.protocol!=='backbond-review-revocations/v1'
      ||Object.keys(revocations).some(k=>!['protocol','revoked_approval_ids'].includes(k))
      ||!Array.isArray(revocations.revoked_approval_ids)||revocations.revoked_approval_ids.length>4096
      ||revocations.revoked_approval_ids.some(id=>!label(id)))reject('review_override_revocations_invalid');
    if(revocations.revoked_approval_ids.includes(r.approval_id))reject('review_override_revoked');
    if(r.manifest_sha256!==snapshot)reject('review_override_manifest_changed');
    if(r.scanner_sha256!==SCANNER_SHA256||r.ruleset_sha256!==report.ruleset.sha256||r.profile_sha256!==report.profile.sha256)reject('review_override_policy_mismatch');
    const codes=Object.keys(report.coverage?.gap_codes||{}).sort();
    if(!codes.length||r.accepted_review_codes.some(c=>typeof c!=='string')
      ||JSON.stringify([...r.accepted_review_codes].sort())!==JSON.stringify(codes))reject('review_override_review_scope_mismatch');
    return {approval_id:r.approval_id,operator:r.operator,approved_at:r.approved_at,
      manifest_sha256:snapshot,record_sha256:recordHash,revocations_sha256:revocationsHash,accepted_review_codes:codes};
  }
  return Object.freeze({check});
}
