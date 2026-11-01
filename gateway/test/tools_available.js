// One place that decides which external tools a test may rely on. Detection is by PATH lookup, never by a fixed path or by operating system, so the same test runs on a developer Mac and on the Linux CI runner
// as soon as the tool is installed. Tests that need something only a Mac has (the login Keychain) say so with ON_MAC, with a reason, instead of hiding behind an unrelated tool check.
//
// Trust: the lookup is done here, not by spawning `which` (which would itself be resolved through PATH). A PATH entry is IGNORED when it is empty or relative (both mean "the current directory") or when it
// lies inside this repository, so a file committed in a pull request can never be what "age" or "sqlite3" resolves to during detection. tools_available.test.js fails if PATH contains such entries at all,
// because the tests then spawn the tools by bare name and the operating system would resolve them the same way.
import { accessSync, constants, realpathSync, statSync } from 'node:fs';
import { delimiter, isAbsolute, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = realpathSync(fileURLToPath(new URL('../../', import.meta.url)));
const inside = (dir, root) => dir === root || dir.startsWith(root + sep);

/** PATH entries that may be trusted, in order, with the reason an entry is refused. */
export function pathEntries(pathValue = process.env.PATH || '') {
  return pathValue.split(delimiter).map((raw) => {
    if (!raw || !isAbsolute(raw)) return { raw, ok: false, why: 'empty or relative entry (means the current directory)' };
    let real; try { real = realpathSync(raw); } catch { return { raw, ok: false, why: 'does not exist' }; }
    return inside(real, REPO_ROOT) ? { raw, ok: false, why: 'inside the repository' } : { raw, ok: true, dir: real };
  });
}

/** Absolute path of the first executable regular file called `name` in a trusted PATH entry, or null. */
export function resolveTool(name, pathValue = process.env.PATH || '') {
  if (!name || name.includes('/')) return null;
  for (const e of pathEntries(pathValue)) {
    if (!e.ok) continue;
    const f = join(e.dir, name);
    try { accessSync(f, constants.X_OK); if (statSync(f).isFile()) return f; } catch { /* not here */ }
  }
  return null;
}

export const have = (...tools) => tools.every((t) => resolveTool(t) !== null);
export const HAVE_AGE = have('age', 'age-keygen');
export const HAVE_SQLITE3 = have('sqlite3');
export const ON_MAC = process.platform === 'darwin';
export const IN_CI = process.env.GITHUB_ACTIONS === 'true';
