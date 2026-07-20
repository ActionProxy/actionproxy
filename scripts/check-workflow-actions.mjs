import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function findMutableActionReferences(source, filename = 'workflow.yml') {
  const failures = [];
  for (const [index, line] of source.split('\n').entries()) {
    const match = line.match(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/);
    if (!match) continue;
    const reference = match[1];
    if (reference.startsWith('./') || reference.startsWith('docker://')) continue;
    const revision = reference.split('@').at(-1) ?? '';
    if (!/^[a-f0-9]{40}$/i.test(revision)) failures.push(`${filename}:${index + 1}: ${reference}`);
  }
  return failures;
}

function main() {
  const directory = process.argv[2] ?? '.github/workflows';
  const failures = readdirSync(directory)
    .filter((filename) => /\.ya?ml$/.test(filename))
    .sort()
    .flatMap((filename) =>
      findMutableActionReferences(readFileSync(path.join(directory, filename), 'utf8'), path.join(directory, filename)),
    );
  if (failures.length > 0) throw new Error(`Mutable GitHub Action references:\n${failures.join('\n')}`);
  console.log(`Verified immutable GitHub Action revisions in ${directory}.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
