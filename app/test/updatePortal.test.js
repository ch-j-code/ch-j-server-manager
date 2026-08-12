"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const portalRoot = path.join(__dirname, "..", "..", "php-update-server");
const read = (name) => fs.readFileSync(path.join(portalRoot, name), "utf8");

test("update portal defaults to application downloads and keeps release history separate", () => {
  const index = read("index.php");
  const releases = read("releases.php");
  const partials = read("partials.php");
  const functions = read("functions.php");
  assert.match(index, /web_t\('index\.heading'\)/);
  assert.match(index, /preferred_app_installer/);
  assert.match(index, /releases\.php/);
  assert.match(releases, /web_t\('releases\.heading'\)/);
  assert.match(releases, /web_t\('releases\.app'\)/);
  assert.match(releases, /web_t\('releases\.plugins'\)/);
  assert.match(partials, /web_t\('nav\.download'\)/);
  assert.match(partials, /web_t\('footer\.rights'\)/);
  assert.match(partials, /assets\/app-icon\.svg/);
  assert.match(functions, /\['stable', 'beta', 'alpha'\]/);
  assert.match(functions, /artifact_role.*installer/s);
  assert.match(functions, /artifact_role.*update/s);
});

test("update portal publishes only available localized screenshots", () => {
  const index = read("index.php");
  const styles = read("assets/downloads.css");
  assert.match(index, /assets\/screenshots/);
  assert.match(index, /is_file\(\$screenshotPath\)/);
  assert.match(index, /is_file\(\$thumbnailPath\)/);
  assert.match(index, /getimagesize\(\$thumbnailPath\)/);
  assert.match(index, /assets\/screenshots\/thumbs/);
  assert.match(index, /loading="lazy"/);
  assert.match(index, /index\.screenshots\.heading/);
  assert.match(styles, /\.screenshot-grid/);
  for (const file of ["vault-unlock.png", "overview.png", "terminal.png", "updates.png", "plugins.png", "settings.png"]) {
    assert.ok(fs.statSync(path.join(portalRoot, "assets", "screenshots", file)).size > 0, `${file} is missing`);
    assert.ok(fs.statSync(path.join(portalRoot, "assets", "screenshots", "thumbs", file)).size > 0, `${file} thumbnail is missing`);
  }
  assert.equal(fs.existsSync(path.join(portalRoot, "assets", "screenshots", "servers.png")), false);
});

test("update administration filters application releases by OS and plugins by identity", () => {
  const admin = read("admin.php");
  const script = read("assets/app.js");
  assert.match(admin, /id="adminReleaseTypeFilter"/);
  assert.match(admin, /id="adminReleaseOsFilter"/);
  assert.match(admin, /id="adminReleaseRoleFilter"/);
  assert.match(admin, /id="adminReleasePluginFilter"/);
  assert.match(admin, /data-release-platform/);
  assert.match(admin, /data-release-plugin/);
  assert.match(admin, /data-release-role/);
  assert.match(script, /syncAdminReleaseFilters/);
  assert.match(script, /row\.dataset\.releasePlatform/);
  assert.match(script, /row\.dataset\.releasePlugin/);
  assert.match(script, /row\.dataset\.releaseRole/);
});

test("macOS first-install and update artifacts stay separate", () => {
  const upload = read("upload.php");
  const admin = read("admin.php");
  const packager = fs.readFileSync(path.join(portalRoot, "..", "app", "scripts", "packageMacInstaller.js"), "utf8");
  assert.match(upload, /'mac' => match \(\$artifactRole\).*'installer' => \['zip'\].*'update' => \['dmg'\]/s);
  assert.match(upload, /\['update', 'installer', 'both'\]/);
  assert.match(admin, /name="artifact_role"/);
  assert.match(packager, /--keepParent/);
  assert.match(packager, /codesign/);
  assert.match(packager, /Developer ID/);
  assert.match(packager, /delete smokeEnvironment\.ELECTRON_RUN_AS_NODE/);
  assert.match(packager, /CHJ_BUILD_SMOKE_READY/);
});

test("build IDs may be shared by artifacts for different target platforms", () => {
  const upload = read("upload.php");
  assert.match(upload, /\$existingRelease\['platform'\].*\$record\['platform'\]/s);
  assert.match(upload, /\$existingRelease\['arch'\].*\$record\['arch'\]/s);
  assert.match(upload, /\$existingRelease\['plugin_id'\].*\$record\['plugin_id'\]/s);
});

test("administration reports upload progress and edits existing release notes", () => {
  const admin = read("admin.php");
  const script = read("assets/app.js");
  const action = read("action.php");
  const upload = read("upload.php");
  assert.match(admin, /data-upload-progress/);
  assert.match(admin, /data-upload-meter/);
  assert.match(script, /XMLHttpRequest/);
  assert.match(script, /request\.upload\.addEventListener\('progress'/);
  assert.match(script, /formatRemainingTime/);
  assert.match(upload, /HTTP_X_REQUESTED_WITH/);
  assert.match(upload, /json_response\(\['ok' => \$success/);
  assert.match(admin, /id="releaseNotesDialog"/);
  assert.match(admin, /data-edit-release/);
  assert.match(action, /update_notes/);
  assert.match(action, /mb_strlen\(\$notes/);
});
