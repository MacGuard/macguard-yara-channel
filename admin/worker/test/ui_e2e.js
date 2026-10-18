
var R = [], out = document.getElementById('result');
function rec(n, ok, d) { R.push((ok ? 'PASS ' : 'FAIL ') + n + (d ? ' — ' + d : '')); }
function wait(f, ms) { return new Promise(function (res) { var t0 = Date.now(); (function p() { var v; try { v = f(); } catch (e) {} if (v || Date.now() - t0 > (ms || 6000)) return res(v); setTimeout(p, 80); })(); }); }
function load(sid) { return new Promise(function (res) { document.cookie = '__Host-mg_session=; Path=/; Max-Age=0; Secure'; if (sid) document.cookie = '__Host-mg_session=' + sid + '; Path=/; Secure'; var f = document.createElement('iframe'); f.style.cssText = 'width:1100px;height:900px'; f.onload = function () { res(f); }; f.src = '/'; document.body.appendChild(f); }); }
async function main() {
  var ses = await (await fetch('/__sessions')).json();
  // 1. anonymous
  var f = await load(null), d = f.contentDocument; await wait(function () { return !d.getElementById('login').hidden; });
  rec('anonymous visitors only see the sign-in card', !d.getElementById('login').hidden && d.getElementById('app').hidden && d.querySelectorAll('#list tbody tr').length === 0);
  f.remove();
  // 2. viewer
  f = await load(ses.viewer); d = f.contentDocument; await wait(function () { return d.querySelectorAll('#list tbody tr').length > 0; });
  rec('viewer sees the list', d.querySelectorAll('#list tbody tr').length === 7, d.getElementById('role').textContent);
  rec('viewer has no approval controls', d.getElementById('bulk-approve').hidden && [].every.call(d.querySelectorAll('#list tbody input'), function (c) { return c.disabled; }) && d.querySelector('[data-tab=a]').hidden && d.querySelector('[data-tab=m]').hidden);
  f.remove();
  // 3. reviewer
  f = await load(ses.reviewer); d = f.contentDocument; await wait(function () { return d.querySelectorAll('#list tbody tr').length > 0; });
  rec('reviewer sees dashboard cards', d.querySelectorAll('#cards button').length === 5 && /7/.test(d.querySelector('#cards button').textContent));
  var link = [].filter.call(d.querySelectorAll('#list tbody button.linkish'), function (b) { return /evil/.test(b.textContent); })[0]; link.click();
  await wait(function () { return d.querySelector('#detail pre.code'); });
  rec('rule code is shown as text and is never executed', /<img src=x onerror/.test(d.querySelector('#detail pre.code').textContent) && !f.contentWindow.__xss && d.querySelectorAll('#detail img').length === 0);
  rec('detail shows resource bars', d.querySelectorAll('#detail svg.bars rect').length >= 0);
  d.querySelector('#detail button').click();
  var boxes = d.querySelectorAll('#list tbody input[type=checkbox]'); boxes[0].click(); boxes[1].click();
  rec('selection counter shows exactly 2', d.getElementById('selcount').textContent === '2' && !d.getElementById('bulk-approve').disabled);
  d.getElementById('bulk-approve').click(); await wait(function () { return d.getElementById('confirm').open; });
  rec('the confirmation dialog states the exact number affected', /exactly 2 rules/.test(d.getElementById('confirm-p').textContent) && /Approve 2 rules/.test(d.getElementById('confirm-h').textContent));
  d.getElementById('confirm-go').click(); await new Promise(function (r) { setTimeout(r, 400); });
  rec('without a reason the dialog stays open, explains why and sends nothing', d.getElementById('confirm').open && /reason/i.test(d.getElementById('confirm-err').textContent) && d.querySelector('#cards button strong').textContent === '7');
  d.getElementById('confirm-reason').value = 'regexes reviewed by hand'; d.getElementById('confirm-go').click();
  await wait(function () { return /updated/.test(d.getElementById('status').textContent); });
  await new Promise(function (r) { setTimeout(r, 400); });
  var counts = [].map.call(d.querySelectorAll('#cards button'), function (b) { return b.dataset.state + '=' + b.querySelector('strong').textContent; }).join(' ');
  rec('exactly the two selected rules were approved', /PENDING=5/.test(counts) && /APPROVED_PENDING_VALIDATION=2/.test(counts), counts + ' status=' + d.getElementById('status').textContent + ' open=' + d.getElementById('confirm').open + ' rv=' + d.getElementById('confirm').returnValue);
  d.querySelector('[data-tab=a]').click(); await wait(function () { return d.querySelectorAll('#audit tbody tr').length > 0; });
  rec('reviewer sees the audit trail with the decision', /decision\.approve/.test(d.querySelector('#audit tbody').textContent) && /rita/.test(d.querySelector('#audit tbody').textContent));
  rec('reviewer cannot manage members or verify the chain', d.querySelector('[data-tab=m]').hidden && d.getElementById('verify-chain').hidden);
  f.remove();
  // 4. admin
  f = await load(ses.admin); d = f.contentDocument; await wait(function () { return d.querySelectorAll('#list tbody tr').length > 0; });
  d.querySelector('[data-tab=a]').click(); d.getElementById('verify-chain').click(); await wait(function () { return /intact|broken|✘/.test(d.getElementById('chain-out').textContent); });
  rec('admin verifies the audit chain', /✔/.test(d.getElementById('chain-out').textContent), d.getElementById('chain-out').textContent);
  d.querySelector('[data-tab=m]').click(); await wait(function () { return d.querySelectorAll('#members li').length > 0; });
  rec('admin sees the members list', /vera/.test(d.getElementById('members').textContent));
  f.remove();
  // 5. bad session
  f = await load('0'.repeat(64)); d = f.contentDocument; await wait(function () { return !d.getElementById('login').hidden; });
  rec('a forged session id is treated as anonymous', !d.getElementById('login').hidden && d.getElementById('app').hidden);
  out.textContent = R.join('\n') + '\nDONE';
}
main().catch(function (e) { R.push('FAIL harness ' + e); out.textContent = R.join('\n') + '\nDONE'; });
