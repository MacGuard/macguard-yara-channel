// Writes gateway/hardening/cloudflare-rulesets.<host>.json (a payload for the Rulesets API). It NEVER calls Cloudflare. Usage: node tools/gen_hardening.mjs [host=api.mac-guard.com]
import { writeFileSync } from 'node:fs';
import { payload } from '../hardening/rules.js';
const host = process.argv[2] ?? 'api.mac-guard.com', file = new URL(`../hardening/cloudflare-rulesets.${host}.json`, import.meta.url);
writeFileSync(file, JSON.stringify(payload(host), null, 2) + '\n'); console.log('written', file.pathname);
