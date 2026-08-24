/* eslint-disable @typescript-eslint/no-explicit-any */
import * as crypto from 'crypto';
import { WakeChannel, WakeChannelOptions } from './wake-channel';
import { DataChannel } from './data-channel';
import { AgentMessage } from '../protocol/envelope';
import { ProtocolError } from '../protocol/serialize';
import {
  AgentSessionState,
  MessageHandler,
  WakeEvent,
  StateChangeHandler
} from './types';
import { MachineConfig } from '../config/machine-config';

export interface AgentSessionOptions {
  /** Machine config (loaded by caller). */
  machineConfig: MachineConfig;
  /** Optional: returns configured database list from databases.config.json. */
  getDatabases?: () => Array<{ db_alias: string; database: string }>;
  /** Message handler. Called for every incoming message on the data channel. */
  onMessage: MessageHandler;
  /** State change handler. Called whenever AgentSessionState changes. */
  onStateChange?: StateChangeHandler;
  /** Optional: custom wake channel options (for tests). */
  wakeChannelOverrides?: Partial<WakeChannelOptions>;
  /** Optional: abort signal. */
  abortSignal?: AbortSignal;
}

export class AgentSession {
  private wakeChannel?: WakeChannel;
  private dataChannel?: DataChannel;
  private state: AgentSessionState;
  private readonly opts: AgentSessionOptions;
  private inFlightRequests: Map<string, AgentMessage> = new Map();
  private currentWakeEvent?: WakeEvent;

  private activeMessageHandler: MessageHandler;
  private activeStateChangeHandler?: StateChangeHandler;

  constructor(opts: AgentSessionOptions) {
    this.opts = opts;
    this.activeMessageHandler = opts.onMessage;
    this.activeStateChangeHandler = opts.onStateChange;

    this.state = {
      wake: 'disconnected',
      data: 'closed',
      has_in_flight: false,
      reconnect_attempts: 0,
    };

    if (this.opts.abortSignal) {
      if (this.opts.abortSignal.aborted) {
        this.stop().catch(() => {});
      } else {
        this.opts.abortSignal.addEventListener('abort', () => {
          this.stop().catch(err => {
            console.error('Error stopping AgentSession via abortSignal:', err);
          });
        });
      }
    }
  }

  /** Start the agent. Boots wake channel. Returns when fully started. */
  async start(): Promise<void> {
    this.updateState({
      wake: 'connecting',
    });

    this.wakeChannel = new WakeChannel({
      cloudUrl: this.opts.machineConfig.cloud_url,
      token: this.opts.machineConfig.agent_token,
      agentId: this.opts.machineConfig.agent_id,
      getDatabases: this.opts.getDatabases,
      onWake: (event) => this.handleWakeEvent(event),
      onStateChange: (wakeState, error) => {
        this.updateState({
          wake: wakeState,
          last_error: error || this.state.last_error,
          reconnect_attempts: this.wakeChannel ? this.wakeChannel.getReconnectAttempts() : 0,
          wake_connected_at: wakeState === 'connected' ? Date.now() : this.state.wake_connected_at,
        });
      },
      abortSignal: this.opts.abortSignal,
      ...this.opts.wakeChannelOverrides,
    });

    await this.wakeChannel.start();
  }

  /** Graceful shutdown. Closes data channel, then wake channel. */
  async stop(): Promise<void> {
    if (this.dataChannel) {
      await this.dataChannel.close('shutdown');
      this.dataChannel = undefined;
    }
    if (this.wakeChannel) {
      await this.wakeChannel.stop();
      this.wakeChannel = undefined;
    }
  }

  /**
   * Send a message out via the data channel.
   * If data channel is closed, opens it first (using current wake event's token).
   * Throws if no wake event has been received yet (i.e., no token to open data channel).
   */
  async send(msg: AgentMessage): Promise<void> {
    if (this.state.data !== 'open' || !this.dataChannel) {
      throw new ProtocolError('channel_closed', 'Data channel not open');
    }

    await this.dataChannel.send(msg);

    // Track requests (not responses/events/chunks/ends/errors)
    if (
      msg.type !== 'response' &&
      msg.type !== 'error' &&
      msg.type !== 'stream_chunk' &&
      msg.type !== 'stream_end' &&
      msg.type !== 'event'
    ) {
      this.trackInFlight(msg.id, msg);
    }
  }

  /** Register a message handler (overrides the one from opts). */
  setMessageHandler(handler: MessageHandler): void {
    this.activeMessageHandler = handler;
  }

  /** Register a state change handler (overrides the one from opts). */
  onStateChange(handler: StateChangeHandler): void {
    this.activeStateChangeHandler = handler;
  }

  /** Current state. */
  getState(): AgentSessionState {
    return this.state;
  }

  /**
   * Track an in-flight request (for reconnect/resume).
   * Called by execution engine before sending a request.
   * Cleared when response is received.
   */
  trackInFlight(requestId: string, msg: AgentMessage): void {
    this.inFlightRequests.set(requestId, msg);
    this.updateState({ has_in_flight: this.inFlightRequests.size > 0 });
  }

  untrackInFlight(requestId: string): void {
    this.inFlightRequests.delete(requestId);
    this.updateState({ has_in_flight: this.inFlightRequests.size > 0 });
  }

  getInFlight(): Map<string, AgentMessage> {
    return this.inFlightRequests;
  }

  private handleWakeEvent(event: WakeEvent): void {
    this.processWakeEvent(event).catch(err => {
      console.error('AgentSession: failed processing wake event:', err);
    });
  }

  private async processWakeEvent(event: WakeEvent): Promise<void> {
    const sameSession =
      this.dataChannel &&
      (this.state.data === 'open' || this.state.data === 'connecting') &&
      this.currentWakeEvent?.browser_session_id === event.browser_session_id;

    if (sameSession) {
      return;
    }

    if (this.dataChannel) {
      this.dataChannel.close('explicit_close').catch(() => {});
      this.dataChannel = undefined;
    }

    this.currentWakeEvent = event;

    this.dataChannel = new DataChannel({
      cloudUrl: this.opts.machineConfig.cloud_url,
      dataChannelToken: event.data_channel_token,
      agentId: this.opts.machineConfig.agent_id,
      browserSessionId: event.browser_session_id || 'unknown',
      onMessage: (msg) => this.activeMessageHandler(msg),
      onStateChange: (dataState, _reason, error) => {
        this.updateState({
          data: dataState,
          last_error: error || this.state.last_error,
          data_opened_at: dataState === 'open' ? Date.now() : this.state.data_opened_at,
        });
      },
      abortSignal: this.opts.abortSignal,
    });

    try {
      await this.dataChannel.connect();
    } catch (err: any) {
      console.error('AgentSession: failed to connect data channel:', err);
      return;
    }

    // Fast-track request if needed
    if (event.request_id) {
      const inFlightMsg = this.inFlightRequests.get(event.request_id);
      if (inFlightMsg) {
        const resumeEvent = {
          v: 1,
          id: crypto.randomUUID(),
          type: 'event' as const,
          project: inFlightMsg.project,
          user: inFlightMsg.user,
          db_alias: inFlightMsg.db_alias,
          ts: Date.now(),
          payload: {
            kind: 'resume_request' as const,
            data: {
              request_id: event.request_id,
            },
          },
        };
        this.send(resumeEvent as AgentMessage).catch(sendErr => {
          console.error('Failed to send resume_request event:', sendErr);
        });
      }
    }
  }

  private updateState(diff: Partial<AgentSessionState>) {
    this.state = { ...this.state, ...diff };
    if (this.activeStateChangeHandler) {
      this.activeStateChangeHandler(this.state);
    }
  }
}
