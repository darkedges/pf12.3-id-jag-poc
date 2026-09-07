const ANSI = Object.freeze({
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  cyan: '\u001b[36m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  blue: '\u001b[34m',
  magenta: '\u001b[35m',
  gray: '\u001b[90m'
});

function shouldColor(stream) {
  if (process.env.XAA_COLOR === 'always') return true;
  if (process.env.XAA_COLOR === 'never') return false;
  return true;
}

function parsePart(encoded, name) {
  try {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error(`JWT ${name} is not valid JSON`);
  }
}

export function decodeCompactJwt(token) {
  if (typeof token !== 'string' || token.length > 32768) throw new Error('JWT is missing or too large');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) {
    throw new Error('Expected a compact JWT');
  }
  return {
    header: parsePart(parts[0], 'header'),
    payload: parsePart(parts[1], 'body'),
    signaturePresent: parts[2].length > 0
  };
}

function paint(value, color, enabled) {
  return enabled ? `${color}${value}${ANSI.reset}` : value;
}

function formatJson(value, enabled, depth = 0) {
  const indentation = '  '.repeat(depth);
  const childIndentation = '  '.repeat(depth + 1);
  if (value === null) return paint('null', ANSI.gray, enabled);
  if (typeof value === 'string') return paint(JSON.stringify(value), ANSI.green, enabled);
  if (typeof value === 'number') return paint(String(value), ANSI.magenta, enabled);
  if (typeof value === 'boolean') return paint(String(value), ANSI.blue, enabled);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return [
      '[',
      ...value.map((item, index) => `${childIndentation}${formatJson(item, enabled, depth + 1)}${index < value.length - 1 ? ',' : ''}`),
      `${indentation}]`
    ].join('\n');
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) return '{}';
    return [
      '{',
      ...entries.map(([key, item], index) => `${childIndentation}${paint(JSON.stringify(key), ANSI.cyan, enabled)}${paint(':', ANSI.gray, enabled)} ${formatJson(item, enabled, depth + 1)}${index < entries.length - 1 ? ',' : ''}`),
      `${indentation}}`
    ].join('\n');
  }
  return paint(JSON.stringify(value), ANSI.gray, enabled);
}

export function printDecodedJwt(token, { label = 'Decoded JWT', stream = process.stdout } = {}) {
  const decoded = decodeCompactJwt(token);
  const color = shouldColor(stream);
  const output = [
    paint(`\n${label}`, `${ANSI.bold}${ANSI.cyan}`, color),
    paint('Header', ANSI.yellow, color),
    formatJson(decoded.header, color),
    paint('Body', ANSI.green, color),
    formatJson(decoded.payload, color),
    `${paint('Signature', ANSI.gray, color)}: present, not displayed`
  ].join('\n');
  stream.write(`${output}\n`);
  return decoded;
}

export function showJwtRequested(argv = process.argv, env = process.env) {
  return env.XAA_SHOW_JWT !== 'false' && !argv.includes('--no-show-jwt');
}
