// Writes contracts/v1/kpi-catalog.json from src/kpi_catalog.js so the neutral contract cannot drift from the code. `--check` compares with the committed file.
import { readFileSync, writeFileSync } from 'node:fs';
import { KPI_CATALOG, ACCURACY, STATES } from '../src/kpi_catalog.js';

const file = new URL('../../contracts/v1/kpi-catalog.json', import.meta.url);
const text = JSON.stringify({ schema: 'macguard.kpi-catalog/1', accuracy: ACCURACY, states: STATES, metrics: KPI_CATALOG }, null, 2) + '\n';
if (process.argv.includes('--check')) { if (readFileSync(file, 'utf8') !== text) { console.error('kpi-catalog.json is out of date: run tools/gen_kpi_catalog.mjs'); process.exit(1); } console.log('kpi-catalog.json is current'); }
else { writeFileSync(file, text); console.log('written'); }
