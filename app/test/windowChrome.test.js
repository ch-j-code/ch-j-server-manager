"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { windowChromeOptions } = require("../src/main/bootstrap/windowChrome");

test("Windows main window uses a dark native controls overlay", () => {
  assert.deepEqual(windowChromeOptions("win32"), {
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#07111f",
      symbolColor: "#d9eaff",
      height: 40
    }
  });
});

test("Linux uses the same dark controls and custom title bar as Windows", () => {
  assert.deepEqual(windowChromeOptions("linux"), windowChromeOptions("win32"));
  assert.equal(windowChromeOptions("linux").titleBarStyle, "hidden");
});

test("macOS keeps its native title bar", () => {
  assert.deepEqual(windowChromeOptions("darwin"), {});
});
