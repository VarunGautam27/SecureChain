#!/usr/bin/env node
/**
 * Reads a JSON array of source-code strings from stdin, parses each with
 * acorn (a real, actively-maintained JS parser, unlike a pure-Python
 * reimplementation), and writes a JSON array of results to stdout - one
 * process launch for the whole batch, not one per file, since each
 * separate process launch has real fixed overhead.
 *
 * Each result is either the parsed ESTree AST (as plain JSON), or null if
 * that specific source failed to parse (both script and module mode
 * attempted) - one bad file never aborts the rest of the batch.
 */
const acorn = require("acorn");

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", () => {
  let sources;
  try {
    sources = JSON.parse(input);
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: "invalid input JSON: " + e.message }));
    process.exit(1);
  }

  const results = sources.map((source) => {
    const options = { ecmaVersion: "latest", locations: true, allowHashBang: true };
    try {
      return acorn.parse(source, { ...options, sourceType: "script" });
    } catch (scriptErr) {
      try {
        return acorn.parse(source, { ...options, sourceType: "module" });
      } catch (moduleErr) {
        return null;
      }
    }
  });

  process.stdout.write(JSON.stringify(results));
});
