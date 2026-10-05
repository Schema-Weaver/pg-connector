/* eslint-disable @typescript-eslint/no-explicit-any */
import { AgentMessage } from './envelope';
import { LIMITS, PROTOCOL_VERSION } from './constants';
import { ErrorCode } from './errors';

export class ProtocolError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public fatal: boolean = false,
  ) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/**
 * Serialize an AgentMessage to a UTF-8 JSON string.
 * Throws ProtocolError if message exceeds MAX_PAYLOAD_BYTES.
 */
export function serialize<T>(msg: AgentMessage<T>): string {
  const json = JSON.stringify(msg);
  if (Buffer.byteLength(json, 'utf8') > LIMITS.MAX_PAYLOAD_BYTES) {
    throw new ProtocolError('invalid_message', 'Message exceeds maximum payload size');
  }
  return json;
}

/**
 * Deserialize a JSON string into a typed AgentMessage.
 * Throws ProtocolError on JSON parse error, size limit, or protocol version mismatch.
 */
export function deserialize<T = unknown>(raw: string): AgentMessage<T> {
  if (Buffer.byteLength(raw, 'utf8') > LIMITS.MAX_PAYLOAD_BYTES) {
    throw new ProtocolError('invalid_message', 'Message exceeds maximum payload size');
  }
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ProtocolError('invalid_message', `Malformed JSON: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new ProtocolError('invalid_message', 'Message must be a JSON object');
  }

  if (parsed.v !== PROTOCOL_VERSION) {
    throw new ProtocolError('protocol_version_mismatch', `Protocol version mismatch. Expected ${PROTOCOL_VERSION}, got ${parsed.v}`);
  }

  return parsed as AgentMessage<T>;
}

/**
 * Serialize to Uint8Array (for WebSocket binary frames).
 */
export function serializeToBytes<T>(msg: AgentMessage<T>): Uint8Array {
  const json = serialize(msg);
  return Buffer.from(json, 'utf8');
}

/**
 * Deserialize from Uint8Array.
 */
export function deserializeFromBytes<T = unknown>(bytes: Uint8Array): AgentMessage<T> {
  const json = Buffer.from(bytes).toString('utf8');
  return deserialize<T>(json);
}
