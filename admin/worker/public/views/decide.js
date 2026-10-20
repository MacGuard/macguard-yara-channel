// One safe path for every decision: states exactly how many rules change, what the action does, asks for a reason, and sends the versions the person saw.
import { t } from '../i18n.js';
import { h, modal, reasonField, rulesText, toast } from '../ui.js';
import { api, failure } from '../api.js';

const rid = () => `req_${(crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/[^A-Za-z0-9_-]/g, '')}`;
const VARIANT = { approve: 'ok', reject: 'bad', hold: 'primary' };

/** selection: Map(id -> version seen). Resolves true when the server applied the change. */
export function decide(action, selection, done) {
  const n = selection.size, count = rulesText(n), reason = reasonField();
  const body = h('div', { class: 'grid-12' }, h('p', { class: 'alert alert-info', text: t('act_affects', { n: count }) }), h('p', { class: 'note', text: t(`act_${action}_p`) }), reason.node);
  modal({
    title: t(`act_${action}_h`, { n: count }), body, confirmLabel: t(`act_${action}`), variant: VARIANT[action],
    validate: () => (reason.value.length < 5 ? t('reason_short') : null),
    async submit() {
      const ids = [...selection.keys()], expect = Object.fromEntries(selection);
      const r = await api('POST', '/api/decisions', { action, ids, reason: reason.value, request_id: rid(), expect, ...(n > 1 ? { confirm_count: n } : {}) });
      if (r.status === 200) { toast(n === 1 ? t('done_one') : t('done_n', { n: (r.data.applied || []).length })); if (done) done(); return null; }
      if (r.status === 409 && r.data.conflicts) { if (done) done(); return t('conflicts', { n: r.data.conflicts.length }); }
      return t('failed', { msg: failure(r, t('err_generic')) });
    },
  });
}
export async function retest(id) {
  const r = await api('POST', `/api/candidates/${id}/retest`);
  toast(r.status === 200 ? t('retest_ok') : t('failed', { msg: failure(r, t('err_generic')) }), r.status !== 200);
}
