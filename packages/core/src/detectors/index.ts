import type { Detector } from "../types";
import { zeroWidth } from "./zero-width";
import { bidiOverride } from "./bidi-override";
import { unicodeTags } from "./unicode-tags";
import { homoglyph } from "./homoglyph";
import { hiddenHtml } from "./hidden-html";
import { encodedPayload } from "./encoded-payload";
import { instructionPatterns } from "./instruction-patterns";
import { exfilUrls } from "./exfil-urls";
import { authoritySpoof } from "./authority-spoof";
import { metadata } from "./metadata";
import { roleSpoofing } from "./role-spoofing";
import { fakeDelimiter } from "./fake-delimiter";

export const DETECTORS: Detector[] = [
  zeroWidth,
  bidiOverride,
  unicodeTags,
  homoglyph,
  hiddenHtml,
  encodedPayload,
  instructionPatterns,
  exfilUrls,
  authoritySpoof,
  metadata,
  roleSpoofing,
  fakeDelimiter,
];

export { zeroWidth, bidiOverride, unicodeTags, homoglyph, hiddenHtml, encodedPayload, instructionPatterns, exfilUrls, authoritySpoof, metadata, roleSpoofing, fakeDelimiter };
