// Hide the gadget dylib from `_dyld_image_count` / `_dyld_get_image_name`
// enumeration — defends against detection code that scans
// dyld's loaded-image list for `frida` / `gum` / known-tweak names.
//
// Usage:
//   frida -H <device-ip>:<gadget-port> -n Gadget -l scripts/ios/hide-from-dyld.js
//
// Strategy:
//   `_dyld_image_count` lives in the dyld shared cache and Interceptor.attach
//   refuses to patch it (read-only / signed). Instead, we leave the count
//   alone and intercept `_dyld_get_image_name` so that any index pointing at
//   a hidden dylib is rewritten to point at a known-benign system entry.
//   Effect: the iteration count stays consistent (no OOB), the hidden
//   dylib's name disappears from public enumeration, and the substring
//   `PixelTrace` / `ajeossida` / `frida` / `gum` returns zero matches.
//
// Limitations:
//   - The aliased system entry shows up twice in the iteration. Detection
//     code that hashes the entire dyld list would notice the duplicate but
//     not the gadget. Acceptable for typical anti-Frida path-substring scans.
//   - Does not patch `_dyld_register_func_for_add_image` callbacks captured
//     before this script ran. Load this script as early as possible (best
//     via gadget's `interaction.type=script` config) so callbacks observe
//     the patched view.

const HIDE_PATTERNS = [
  /PixelTrace\.dylib$/i,
  /ajeossida/i,
  /libfrida/i,
  /libgum/i,
];

const cntPtr = Module.getGlobalExportByName('_dyld_image_count');
const namePtr = Module.getGlobalExportByName('_dyld_get_image_name');

if (!cntPtr || !namePtr) {
  console.log('[hide] dyld symbols not resolvable — aborting');
} else {
  const orig_count = new NativeFunction(cntPtr, 'uint32', []);
  const orig_name = new NativeFunction(namePtr, 'pointer', ['uint32']);

  const hiddenSet = new Set();
  const N0 = orig_count();
  for (let i = 0; i < N0; i++) {
    const p = orig_name(i);
    if (p.isNull()) continue;
    const s = p.readCString();
    if (s && HIDE_PATTERNS.some(re => re.test(s))) hiddenSet.add(i);
  }
  console.log('[hide] hiding ' + hiddenSet.size + ' image(s): ' + JSON.stringify([...hiddenSet]));

  // Pick a benign aliasing target: prefer a system lib path under /usr/lib/system
  // so the duplicate entry blends in. Fall back to index 0 if none match.
  let SAFE_IDX = 0;
  for (let i = 0; i < N0; i++) {
    if (hiddenSet.has(i)) continue;
    const s = orig_name(i).readCString() || '';
    if (s.startsWith('/usr/lib/system/') || s.startsWith('/System/Library/Frameworks/Foundation')) {
      SAFE_IDX = i;
      break;
    }
  }
  console.log('[hide] aliasing target [' + SAFE_IDX + ']: ' + orig_name(SAFE_IDX).readCString());

  Interceptor.attach(namePtr, {
    onEnter(args) {
      const i = args[0].toInt32();
      if (hiddenSet.has(i)) args[0] = ptr(SAFE_IDX);
    },
  });
  console.log('[hide] _dyld_get_image_name aliased');
}
