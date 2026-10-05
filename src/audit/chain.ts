import * as crypto from 'crypto';
import { AuditEvent } from './types';

export function computeHash(event: Omit<AuditEvent, 'hash'>): string {
  const canonical = canonicalStringify(event);
  const input = canonical + event.prev_hash;
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function canonicalStringify(value: unknown): string {
  if (value === undefined) {
    return '';
  }
  if (value === null) {
    return 'null';
  }
  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']';
  }
  const keys = Object.keys(value as object).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify((value as Record<string, unknown>)[k])).join(',') + '}';
}

export function verifyChain(events: AuditEvent[]): { intact: boolean; brokenAt?: number } {
  if (events.length === 0) {
    return { intact: true };
  }
  
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    
    if (i === 0) {
      if (event.prev_hash !== '0'.repeat(64)) {
        return { intact: false, brokenAt: 0 };
      }
    } else {
      if (event.prev_hash !== events[i - 1].hash) {
        return { intact: false, brokenAt: i };
      }
    }
    
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { hash: _omitHash, ...eventWithoutHash } = event;
    const expectedHash = computeHash(eventWithoutHash as Omit<AuditEvent, 'hash'>);
    if (event.hash !== expectedHash) {
      return { intact: false, brokenAt: i };
    }
  }
  
  return { intact: true };
}

export { verifyChain as verifyHashChain, computeHash as computeEventHash };
