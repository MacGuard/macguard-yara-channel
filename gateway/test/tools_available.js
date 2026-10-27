// One place that decides which external tools a test may rely on. Detection is by PATH lookup, never by a fixed path or by operating system, so the same test runs on a developer Mac and on the Linux CI runner
// as soon as the tool is installed. Tests that need something only a Mac has (the login Keychain) say so with ON_MAC, with a reason, instead of hiding behind an unrelated tool check.
import { execFileSync } from 'node:child_process';

export const have = (...tools) => tools.every((t) => { try { execFileSync('which', [t], { stdio: 'pipe' }); return true; } catch { return false; } });
export const HAVE_AGE = have('age', 'age-keygen');
export const HAVE_SQLITE3 = have('sqlite3');
export const ON_MAC = process.platform === 'darwin';
export const IN_CI = process.env.GITHUB_ACTIONS === 'true';
