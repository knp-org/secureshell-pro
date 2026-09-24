import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const files = readdirSync('src/js', { recursive: true }).filter(file => file.endsWith('.js'));
for (const file of files) {
    const result = spawnSync(process.execPath, ['--check', `src/js/${file}`], { stdio: 'inherit' });
    if (result.status !== 0) process.exit(result.status ?? 1);
}
console.log(`Checked ${files.length} JavaScript files.`);
