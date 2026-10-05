
import { runStart } from './start';
import { runStop } from './stop';
import { runStatus } from './status';
import { runClean } from './clean';

export { runStart, runStop, runStatus, runClean };

export async function runRestart(args: string[]): Promise<void> {
  await runStop(args);
  await runStart(args);
}
