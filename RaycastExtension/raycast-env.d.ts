/// <reference types="@raycast/api">

/* 🚧 🚧 🚧
 * This file is auto-generated from the extension's manifest.
 * Do not modify manually. Instead, update the `package.json` file.
 * 🚧 🚧 🚧 */

/* eslint-disable @typescript-eslint/ban-types */

type ExtensionPreferences = {}

/** Preferences accessible in all the extension's commands */
declare type Preferences = ExtensionPreferences

declare namespace Preferences {
  /** Preferences accessible in the `scrub-clipboard` command */
  export type ScrubClipboard = ExtensionPreferences & {
  /** Sensitivity - low: named patterns only. medium: + entropy > 4.5, length >= 20. high: + entropy > 3.8, length >= 16. */
  "sensitivity": "high" | "medium" | "low"
}
}

declare namespace Arguments {
  /** Arguments passed to the `scrub-clipboard` command */
  export type ScrubClipboard = {}
}

