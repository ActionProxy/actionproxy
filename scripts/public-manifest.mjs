import path from "node:path";

export const PUBLIC_MANIFEST_SCHEMA_VERSION = "actionproxy.public-manifest.v2";

export const REGULAR_GIT_MODES = Object.freeze(["100644", "100755"]);

export function isSafePublicPath(value) {
  if (
    typeof value !== "string" ||
    value === "" ||
    value.includes("\\") ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    return false;
  }
  const normalized = path.posix.normalize(value);
  const segments = normalized.split("/");
  return (
    normalized === value &&
    normalized !== "." &&
    !normalized.endsWith("/") &&
    !path.posix.isAbsolute(normalized) &&
    normalized !== ".." &&
    !normalized.startsWith("../") &&
    !segments.includes(".git")
  );
}

export function gitModeFromStat(stat) {
  if (!stat?.isFile?.() || stat.isSymbolicLink?.()) {
    throw new Error("Git file mode can only be derived from a regular file.");
  }
  return (stat.mode & 0o111) === 0 ? "100644" : "100755";
}

export function isRegularGitMode(value) {
  return REGULAR_GIT_MODES.includes(value);
}

export function parseGitStageRecords(body) {
  if (typeof body !== "string") {
    throw new TypeError("Git stage output must be a string.");
  }
  const records = [];
  for (const record of body.split("\0")) {
    if (record === "") continue;
    const tab = record.indexOf("\t");
    const metadata = tab === -1 ? "" : record.slice(0, tab);
    const relativePath = tab === -1 ? "" : record.slice(tab + 1);
    const match = /^(\d{6}) ((?:[a-f0-9]{40}|[a-f0-9]{64})) ([0-3])$/u.exec(
      metadata,
    );
    if (!match || !isSafePublicPath(relativePath)) {
      throw new Error(
        `Git reported a malformed or unsafe index entry: ${record}`,
      );
    }
    records.push({
      mode: match[1],
      objectId: match[2],
      path: relativePath,
      stage: Number(match[3]),
    });
  }
  return records;
}

export function comparePublicPaths(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
