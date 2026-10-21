import type { Tag, TagScan } from "./detectors/hidden-html";

// The element tree the browser builds, for what changes what is hidden: open
// elements on a stack, implicit end tags, end tags that close open children, table foster parenting, markup dropped
// inside <select>, foreign content (svg / math). Every text run gets the outermost element that hides it.
// Linear: every "in scope" check reads the last stack position of a name, so each tag costs O(1), and each element
// is pushed and popped once. Adoption agency, head / body / frameset modes, the form pointer and quirks mode are not
// built (they do not change what is hidden; see the spec).

export interface TreeElement {
  name: string;
  /** source offsets: the open tag, and the end of the element (its close tag, or where it was closed implicitly) */
  start: number;
  openEnd: number;
  end: number;
  parent: number;
  /** the outermost element that hides this one (itself included), or -1 */
  hider: number;
  /** why this element hides its subtree, when it does */
  reason?: string;
  foreign: boolean;
}

export interface TextRun {
  start: number;
  end: number;
  /** the element the text belongs to (-1: the document) */
  el: number;
  /** the outermost element that hides the text, or -1 */
  hider: number;
  /** a line starts here: an element started, or a block element or <br> ended, since the previous text run */
  breakBefore: boolean;
}

export interface HtmlTree {
  elements: TreeElement[];
  runs: TextRun[];
}

const VOID = new Set("area base basefont bgsound br col embed frame hr img input keygen link meta param source track wbr".split(" "));
// content a reader never sees; inside svg / math, style and script are ordinary elements whose text is not rendered
const UNRENDERED = new Set(["script", "style", "template", "noscript", "noembed", "noframes", "iframe", "title"]);
const SCOPE_BOUNDARY = new Set(["applet", "caption", "html", "table", "td", "th", "marquee", "object", "template"]);
const CLOSES_P = new Set("address article aside blockquote center details dialog dir div dl fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr main menu nav ol p pre search section summary table ul li dd dt listing plaintext xmp".split(" "));
const HEADINGS = new Set(["h1", "h2", "h3", "h4", "h5", "h6"]);
const TABLE_CONTEXT = new Set(["table", "tbody", "thead", "tfoot", "tr"]);
const TABLE_CONTENT = new Set(["caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td", "th", "script", "style", "template", "table", "form", "input"]);
const SELECT_CONTENT = new Set(["option", "optgroup", "hr", "script", "template"]);
const HEAD_CONTENT = new Set(["base", "basefont", "bgsound", "link", "meta", "title", "style", "script", "noscript", "template", "noframes"]);
// an HTML element that ends foreign content when it starts inside svg / math
const BREAKOUT = new Set("b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr i img li listing menu meta nobr ol p pre ruby s small span strong strike sub sup table tt u ul var".split(" "));
// the "special" category: an end tag for any other element is ignored when one of these is open above that element
const SPECIAL = new Set("address applet area article aside base basefont bgsound blockquote body br button caption center col colgroup dd details dir div dl dt embed fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html iframe img input keygen li link listing main marquee menu meta nav noembed noframes noscript object ol p param plaintext pre script search section select source style summary table tbody td template textarea tfoot th thead title tr track ul wbr xmp".split(" "));
// elements whose end starts a new line in rendered text (a <span> end does not: no false "System:" line after it)
const BLOCK = new Set("address article aside blockquote br dd details dialog div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr li main nav ol p pre section summary table tbody td tfoot th thead tr ul".split(" "));
const WS_ONLY = /^[\t\n\f\r ]*$/;

/**
 * Builds the tree from the tokenizer's tags and comments. `hides` decides whether an element hides its subtree by its
 * own attributes (the caller's rules); not-rendered elements always do.
 */
export function buildTree(html: string, scan: TagScan, hides: (tag: Tag) => string | undefined): HtmlTree {
  const elements: TreeElement[] = [];
  const runs: TextRun[] = [];
  const stack: number[] = [];
  const posOf = new Map<string, number[]>(); // stack positions of the open elements of each name, ascending
  const boundaries: number[] = []; // stack positions of open scope boundaries, ascending
  const specials: number[] = []; // stack positions of open special elements, ascending
  const last = (name: string) => {
    const p = posOf.get(name);
    return p && p.length ? p[p.length - 1] : -1;
  };
  const top = () => (stack.length ? stack[stack.length - 1] : -1);
  const topName = () => (stack.length ? elements[top()].name : "");
  const push = (el: number) => {
    const name = elements[el].name;
    stack.push(el);
    let p = posOf.get(name);
    if (!p) posOf.set(name, (p = []));
    p.push(stack.length - 1);
    if (SCOPE_BOUNDARY.has(name) && !elements[el].foreign) boundaries.push(stack.length - 1);
    if (SPECIAL.has(name) && !elements[el].foreign) specials.push(stack.length - 1);
  };
  const pop = (endAt: number) => {
    const el = stack.pop()!;
    const e = elements[el];
    posOf.get(e.name)!.pop();
    if (boundaries.length && boundaries[boundaries.length - 1] === stack.length) boundaries.pop();
    if (specials.length && specials[specials.length - 1] === stack.length) specials.pop();
    e.end = endAt;
  };
  /** Pops up to and including the last open element of that name (the caller checked that it is open). */
  const popUntil = (name: string, endAt: number) => {
    const at = last(name);
    while (stack.length > at) pop(endAt);
  };
  const boundaryTop = () => (boundaries.length ? boundaries[boundaries.length - 1] : -1);
  /** Open and not cut off by a scope boundary opened after it (or `also`, e.g. button for p, ul / ol for li). */
  const inScope = (name: string, also: string[] = []) => {
    const at = last(name);
    if (at < 0) return false;
    let lim = boundaryTop();
    for (const a of also) lim = Math.max(lim, last(a));
    return at >= lim;
  };
  const tablePos = () => last("table");
  // the insertion mode of a table comes from the nearest table-structure element, not from the current node: an
  // element foster-parented out of the table stays open on top of it without leaving table mode
  // (a <template> starts a context of its own)
  const tableMode = () => Math.max(last("table"), last("tbody"), last("thead"), last("tfoot"), last("tr")) > Math.max(last("td"), last("th"), last("caption"), last("template"));
  // without a doctype the document is in quirks mode, where a <table> does not close an open <p>
  const quirks = !/^\s*<!doctype\s+html\b/i.test(html.slice(0, 1024));
  const inSelect = () => {
    const s = last("select");
    return s >= 0 && s > Math.max(tablePos(), last("template"));
  };
  // foster parenting applies when the current node itself is table structure
  const foster = () => {
    const t = top();
    return t >= 0 && !elements[t].foreign && TABLE_CONTEXT.has(elements[t].name);
  };
  /** Pops foster-parented elements until the current node is table structure again. */
  const backToTable = (at: number) => {
    while (stack.length && !TABLE_CONTEXT.has(topName()) && topName() !== "html" && topName() !== "template") pop(at);
  };
  const fosterParent = () => {
    const at = tablePos();
    return at > 0 ? stack[at - 1] : -1;
  };

  let lineBreak = false;
  const create = (name: string, start: number, openEnd: number, parent: number, tag: Tag, foreign: boolean) => {
    const parentHider = parent >= 0 ? elements[parent].hider : -1;
    const reason = UNRENDERED.has(name) ? `<${name}>` : foreign ? undefined : hides(tag);
    const el = elements.length;
    elements.push({ name, start, openEnd, end: openEnd, parent, hider: parentHider >= 0 ? parentHider : reason ? el : -1, reason, foreign });
    return el;
  };
  const text = (start: number, end: number) => {
    if (end <= start) return;
    const blank = WS_ONLY.test(html.slice(start, end));
    // text in <head> closes it; the text goes to the body
    if (!blank && topName() === "head") pop(start);
    const el = !blank && foster() ? fosterParent() : top();
    runs.push({ start, end, el, hider: el >= 0 ? elements[el].hider : -1, breakBefore: lineBreak });
    if (!blank) lineBreak = false;
  };

  const startTag = (name: string, start: number, end: number, tag: Tag) => {
    const tagText = tag.text;
    lineBreak = true;
    let cur = top();
    const inForeign = cur >= 0 && elements[cur].foreign;
    if (inForeign && BREAKOUT.has(name)) {
      while (stack.length && elements[top()].foreign) pop(start);
      cur = top();
    } else if (inForeign) {
      const el = create(name, start, end, cur, tag, true);
      if (!tagText.endsWith("/>")) push(el);
      return;
    }
    if (topName() === "head" && !HEAD_CONTENT.has(name)) pop(start);
    if ((name === "html" || name === "body") && last(name) >= 0) return; // a second <html> / <body> adds no element
    if (inSelect()) {
      if (name === "select") return popUntil("select", start); // a <select> inside one acts as its end tag
      // inside a select that sits in a table, table structure closes the select first
      if (tablePos() >= 0 && /^(caption|table|tbody|tfoot|thead|tr|td|th)$/.test(name)) popUntil("select", start);
      if (name === "input" || name === "keygen" || name === "textarea") popUntil("select", start);
      else if (!SELECT_CONTENT.has(name)) return; // dropped: its text stays with the option
    }
    // a <table> inside a table (not in a cell) closes the open table first; table structure clears foster-parented
    // elements off the stack
    if (tableMode()) {
      if (name === "table") popUntil("table", start);
      else if (/^(caption|colgroup|col|tbody|tfoot|thead|tr|td|th)$/.test(name)) backToTable(start);
    }
    // implicit end tags
    if (CLOSES_P.has(name) && !(name === "table" && quirks) && inScope("p", ["button"])) popUntil("p", start);
    if (name === "li" && last("li") > Math.max(last("ul"), last("ol"), boundaryTop())) popUntil("li", start);
    if ((name === "dd" || name === "dt") && Math.max(last("dd"), last("dt")) > Math.max(last("dl"), boundaryTop())) popUntil(last("dd") > last("dt") ? "dd" : "dt", start);
    if (HEADINGS.has(name) && HEADINGS.has(topName())) pop(start);
    if (name === "option" && topName() === "option") pop(start);
    if (name === "optgroup") {
      if (topName() === "option") pop(start);
      if (topName() === "optgroup") pop(start);
    }
    if (name === "tr" && last("tr") > tablePos()) popUntil("tr", start);
    if ((name === "td" || name === "th") && Math.max(last("td"), last("th")) > tablePos()) popUntil(last("td") > last("th") ? "td" : "th", start);
    if ((name === "tbody" || name === "thead" || name === "tfoot") && Math.max(last("tbody"), last("thead"), last("tfoot")) > tablePos()) {
      const sec = ["tbody", "thead", "tfoot"].reduce((a, b) => (last(b) > last(a) ? b : a));
      popUntil(sec, start);
    }
    // foster parenting: inside a table, an element that is no table content belongs to the table's parent
    const parent = foster() && !TABLE_CONTENT.has(name) ? fosterParent() : top();
    const foreign = name === "svg" || name === "math";
    const el = create(name, start, end, parent, tag, foreign);
    if (VOID.has(name) || (foreign && tagText.endsWith("/>"))) return;
    push(el);
  };

  const endTag = (name: string, start: number, end: number) => {
    if (BLOCK.has(name)) lineBreak = true;
    const cur = top();
    if (cur >= 0 && elements[cur].foreign) {
      // in foreign content an end tag closes the matching foreign element, if there is one
      for (let i = stack.length - 1; i >= 0 && elements[stack[i]].foreign; i--) {
        if (elements[stack[i]].name === name) {
          while (stack.length > i) pop(end);
          return;
        }
        if (stack.length - i > 64) break; // a bounded look: deeper foreign nesting falls through to the HTML rules
      }
    }
    if (name === "body" || name === "html" || name === "br") return; // the body stays open; </br> adds nothing here
    if (inSelect() && name !== "select" && name !== "option" && name !== "optgroup" && name !== "template") return;
    if (name === "p") {
      if (inScope("p", ["button"])) popUntil("p", end);
      return;
    }
    if (name === "li") {
      if (last("li") > Math.max(last("ul"), last("ol"), boundaryTop())) popUntil("li", end);
      return;
    }
    if (name === "td" || name === "th" || name === "tr" || name === "tbody" || name === "thead" || name === "tfoot") {
      if (last(name) > tablePos()) popUntil(name, end);
      return;
    }
    if (SPECIAL.has(name)) {
      if (inScope(name)) popUntil(name, end); // an end tag with nothing open in scope is ignored
      return;
    }
    // any other end tag closes its element only if no special element is open above it (e.g. </span> under an open
    // <div> is ignored)
    if (last(name) > (specials.length ? specials[specials.length - 1] : -1)) popUntil(name, end);
  };

  // tags and comments in document order; comments inside raw text are text of that element, not tokens
  const comments = scan.comments.filter((c) => !c.inRawText);
  const stop = scan.unterminatedAt >= 0 ? scan.unterminatedAt : html.length;
  let ti = 0;
  let ci = 0;
  let at = 0;
  while (ti < scan.tags.length || ci < comments.length) {
    const t = scan.tags[ti];
    const c = comments[ci];
    if (c && (!t || c.start < t.start)) {
      text(at, c.start);
      at = c.end;
      ci++;
      continue;
    }
    text(at, t.start);
    at = t.end;
    if (t.closing) endTag(t.name, t.start, t.end);
    else startTag(t.name, t.start, t.end, t);
    ti++;
  }
  // the rest of the document; an unterminated tag drops everything after it, as the browser does
  text(at, stop);
  while (stack.length) pop(stop);
  return { elements, runs };
}
