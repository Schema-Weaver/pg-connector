import { C } from './colors';
import { S } from './symbols';

export interface Spinner {
  start(text: string): void;
  succeed(text?: string): void;
  fail(text?: string): void;
  warn(text?: string): void;
  info(text?: string): void;
  stop(): void;
  update(text: string): void;
}

class SpinnerImpl implements Spinner {
  private interval: ReturnType<typeof setInterval> | null = null;
  private text = '';
  private frameIndex = 0;
  private active = false;
  private readonly frames = S.spinner;

  start(text: string): void {
    this.text = text;
    this.active = true;
    this.frameIndex = 0;
    if (!process.stdout.isTTY) {
      console.log(`  ${C.dim(text)}`);
      return;
    }
    this.render();
    this.interval = setInterval(() => {
      this.frameIndex = (this.frameIndex + 1) % this.frames.length;
      this.render();
    }, 80);
  }

  update(text: string): void {
    this.text = text;
    if (!process.stdout.isTTY) return;
    if (this.active) this.render();
  }

  succeed(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    console.log(`  ${C.green(S.check)} ${msg}`);
  }

  fail(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    console.log(`  ${C.red(S.cross)} ${msg}`);
  }

  warn(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    console.log(`  ${C.yellow(S.warning)} ${msg}`);
  }

  info(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    console.log(`  ${C.blue(S.info)} ${msg}`);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    if (this.active) {
      if (process.stdout.isTTY) {
        process.stdout.write('\r\x1b[K');
      }
      this.active = false;
    }
  }

  private render(): void {
    if (!process.stdout.isTTY) return;
    const frame = C.cyan(this.frames[this.frameIndex]);
    const text = C.dim(this.text);
    process.stdout.write(`\r  ${frame} ${text}`);
  }
}

export function createSpinner(): Spinner {
  return new SpinnerImpl();
}

export function withSpinner<T>(text: string, fn: (spinner: Spinner) => Promise<T>): Promise<T> {
  const spinner = createSpinner();
  spinner.start(text);
  return fn(spinner).finally(() => spinner.stop());
}
