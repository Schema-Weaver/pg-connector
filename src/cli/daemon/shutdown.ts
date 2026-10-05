export interface ShutdownCoordinator {
  register(name: string, cleanup: () => Promise<void>): () => void;
  shutdown(timeoutMs?: number): Promise<'clean' | 'timeout'>;
  isShuttingDown(): boolean;
}

class ShutdownCoordinatorImpl implements ShutdownCoordinator {
  private resources = new Map<string, () => Promise<void>>();
  private shuttingDown = false;
  private shutdownPromise: Promise<'clean' | 'timeout'> | null = null;

  register(name: string, cleanup: () => Promise<void>): () => void {
    if (this.shuttingDown) {
      throw new Error(`Cannot register resource '${name}' during shutdown`);
    }
    this.resources.set(name, cleanup);
    return () => {
      this.resources.delete(name);
    };
  }

  isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  async shutdown(timeoutMs = 30_000): Promise<'clean' | 'timeout'> {
    if (this.shutdownPromise) {
      return this.shutdownPromise;
    }
    this.shuttingDown = true;

    this.shutdownPromise = (async () => {
      const entries = Array.from(this.resources.entries());
      let hasTimeout = false;
      const startTime = Date.now();

      for (const [name, cleanup] of entries) {
        const remaining = Math.max(0, timeoutMs - (Date.now() - startTime));
        debugLog(`[coordinator] ${new Date().toISOString()} starting cleanup of resource: ${name}`);
        
        let timeoutId: NodeJS.Timeout | undefined;
        const timeoutPromise = new Promise<'timeout'>((resolve) => {
          timeoutId = setTimeout(() => resolve('timeout'), remaining);
        });
        
        const workPromise = cleanup().then(() => 'clean' as const);
        
        try {
          const result = await Promise.race([workPromise, timeoutPromise]);
          if (timeoutId) clearTimeout(timeoutId);
          
          if (result === 'timeout') {
            console.warn(`[shutdown] ${new Date().toISOString()} resource '${name}' timed out after ${remaining}ms`);
            hasTimeout = true;
          }
          debugLog(`[coordinator] ${new Date().toISOString()} finished cleanup of resource: ${name}, result: ${result}`);
        } catch (err) {
          if (timeoutId) clearTimeout(timeoutId);
          console.error(`[coordinator] ${new Date().toISOString()} resource '${name}' threw error:`, err);
        }
      }
      
      return hasTimeout ? 'timeout' : 'clean';
    })();

    return this.shutdownPromise;
  }
}

export function createShutdownCoordinator(): ShutdownCoordinator {
  return new ShutdownCoordinatorImpl();
}

function debugLog(message: string): void {
  if (process.env.SW_AGENT_DEBUG === '1') {
    console.error(message);
  }
}
