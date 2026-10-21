export { scan, computeScore, verdictFor, detectContentType, resolveContentType, VERSION } from "./scan";
export { sanitize, findingsAtOrAbove } from "./sanitize";
export type { SanitizeOptions } from "./sanitize";
export { DETECTORS } from "./detectors";
export { INSTRUCTION_PATTERNS, matchInstructions } from "./patterns";
export { SEVERITY_WEIGHT, reveal } from "./util/text";
export type {
  Category,
  EmailField,
  EmailInput,
  ScanError,
  ContentType,
  Detector,
  DetectorContext,
  Finding,
  InstructionMatch,
  Provenance,
  ResolvedContentType,
  Result,
  ScanOptions,
  Severity,
  Verdict,
} from "./types";
