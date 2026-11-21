// Shared marker detection. Same rules as agent/scanner.py: case-insensitive, ignores
// spaces/underscores/punctuation and common OCR confusions (0->O, 1->I, 5->S).
(function (root) {
  const MARKER = "WALLED_SENSITIVE";
  const KEY = "WALLEDSENSITIVE";
  const FIXES = { "0": "O", "1": "I", "5": "S", "|": "I", "$": "S" };

  function normalize(text) {
    return String(text).toUpperCase().replace(/[015|$]/g, (c) => FIXES[c]).replace(/[^A-Z0-9]/g, "");
  }

  function containsMarker(text) {
    return Boolean(text) && normalize(text).includes(KEY);
  }

  root.WalledDLP = Object.freeze({ MARKER, normalize, containsMarker });
})(globalThis);
