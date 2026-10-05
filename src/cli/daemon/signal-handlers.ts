import { ShutdownCoordinator } from './shutdown';

export function installSignalHandlers(coordinator: ShutdownCoordinator): () => void {
  const handlers: NodeJS.Signals[] = ['SIGTERM', 'SIGINT'];
  const installedHandlers = new Map<NodeJS.Signals, () => void>();

  const handler = async (_signal: NodeJS.Signals) => {
    const result = await coordinator.shutdown(30_000);
    process.exit(result === 'clean' ? 0 : 1);
  };

  for (const sig of handlers) {
    installedHandlers.set(sig, () => {
      void handler(sig);
    });
    process.on(sig, installedHandlers.get(sig)!);
  }

  const hupHandler = () => {
    
  };
  process.on('SIGHUP', hupHandler);
  installedHandlers.set('SIGHUP', hupHandler);

  return () => {
    for (const [sig, h] of installedHandlers) {
      process.off(sig, h);
    }
  };
}
