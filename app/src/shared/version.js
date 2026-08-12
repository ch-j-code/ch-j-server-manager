"use strict";

const VERSION_PATTERN = /^v?(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseVersion(input) {
  const raw = String(input || "").trim();
  const match = VERSION_PATTERN.exec(raw);
  if (!match) {
    throw new Error(`Invalid version: ${raw || "<empty>"}`);
  }

  return {
    raw: raw.replace(/^v/i, ""),
    numbers: [match[1], match[2], match[3] || "0", match[4] || "0"].map(Number),
    prerelease: match[5] ? match[5].split(".") : []
  };
}

function comparePrerelease(left, right) {
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;

  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] === undefined) return -1;
    if (right[index] === undefined) return 1;
    if (left[index] === right[index]) continue;

    const leftNumeric = /^\d+$/.test(left[index]);
    const rightNumeric = /^\d+$/.test(right[index]);
    if (leftNumeric && rightNumeric) {
      return Number(left[index]) > Number(right[index]) ? 1 : -1;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return left[index] > right[index] ? 1 : -1;
  }
  return 0;
}

function compareVersions(leftInput, rightInput) {
  const left = parseVersion(leftInput);
  const right = parseVersion(rightInput);

  for (let index = 0; index < left.numbers.length; index += 1) {
    if (left.numbers[index] === right.numbers[index]) continue;
    return left.numbers[index] > right.numbers[index] ? 1 : -1;
  }
  return comparePrerelease(left.prerelease, right.prerelease);
}

module.exports = {
  VERSION_PATTERN,
  compareVersions,
  parseVersion
};
