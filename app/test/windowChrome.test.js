"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { windowChromeOptions } = require("../src/main/bootstrap/createMainWindow");

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

test("macOS keeps its native title bar", () => {
  assert.deepEqual(windowChromeOptions("darwin"), {});
});
