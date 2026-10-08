"use strict";

function windowChromeOptions(platform = process.platform) {
  if (!["win32", "linux"].includes(platform)) return {};
  return {
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#07111f",
      symbolColor: "#d9eaff",
      height: 40
    }
  };
}

module.exports = { windowChromeOptions };
