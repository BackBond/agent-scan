'use strict';

function safeInline(value, maxLength = 500) {
  const cleaned = String(value).replace(/[\p{C}\p{Zl}\p{Zp}]/gu, '\uFFFD');
  const characters = Array.from(cleaned);
  return characters.length > maxLength ? `${characters.slice(0, maxLength - 1).join('')}\u2026` : cleaned;
}

module.exports = { safeInline };
