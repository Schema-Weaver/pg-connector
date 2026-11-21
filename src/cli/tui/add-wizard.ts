import * as fs from 'fs';
import type { DbEntry } from '../../config/db-config';
import type { PermissionLevel } from '../../config/machine-config';
import {
  isValidEnvVarName,
  isValidHostname,
  isValidIdentifier,
  isValidIpv4,
  isValidIpv6,
} from '../../config/schema';
import {
  DB_TYPES,
  defaultPortFor,
  maxDatabaseNameLength,
  maxUserNameLength,
  MONGODB_READ_CONCERNS,
  MONGODB_READ_PREFERENCES,
  type DbType,
  type MongoReadConcern,
  type MongoReadPreference,
} from '../../drivers/config-shape';
import { C, truncateAnsi, visibleLength } from '../ui/colors';
import {
  createTuiScreen,
  setTuiActive,
  tuiCursorChar,
  wrapTuiText,
  type TuiMouseEvent,
  type TuiKey,
  type TuiRegion,
  type TuiScreen,
} from './screen';

export interface AddDatabaseDraft {
  dbType: DbType;
  connectionMode: 'url' | 'manual';
  connectionUrl: string;
  host: string;
  srv: boolean;
  port: number;
  database: string;
  user: string;
  passwordMode: 'env' | 'stored';
  passwordEnv?: string;
  passwordStored?: string;
  sslMode: DbEntry['ssl_mode'];
  sslRootCert: string | null;
  authSource: string | null;
  readPreference: MongoReadPreference | null;
  readConcern: MongoReadConcern | null;
  permission: PermissionLevel | null;
  alias: string;
  projectName: string;
}

export interface AddWizardOptions {
  aliasExists?: (alias: string) => boolean;
  /** Inject a screen for tests; production uses a real full-screen TTY. */
  screen?: TuiScreen;
}

interface SelectChoice {
  name: string;
  value: string;
}

interface Step {
  id: string;
  title: string;
  hint: string;
  kind: 'select' | 'input' | 'secret' | 'review';
  choices?: SelectChoice[];
  initial: string;
  /** Pre-filled value for the custom masked field. */
  initialSecret?: string;
  placeholder?: string;
  maxLength?: number;
  skip?: (draft: AddDatabaseDraft) => boolean;
  validate?: (value: string, draft: AddDatabaseDraft) => string | null;
  apply: (value: string, draft: AddDatabaseDraft) => void;
}

const ENGINE_CHOICES: SelectChoice[] = [
  { name: 'PostgreSQL', value: 'postgres' },
  { name: 'MySQL', value: 'mysql' },
  { name: 'MongoDB', value: 'mongodb' },
];

const PASSWORD_CHOICES: SelectChoice[] = [
  { name: 'Environment variable', value: 'env' },
  { name: 'Store encrypted', value: 'stored' },
];

const SSL_CHOICES: SelectChoice[] = [
  { name: 'require', value: 'require' },
  { name: 'verify-ca', value: 'verify-ca' },
  { name: 'verify-full', value: 'verify-full' },
  { name: 'disable', value: 'disable' },
];

const PERMISSION_CHOICES: SelectChoice[] = [
  { name: 'use default', value: '' },
  { name: 'read_only', value: 'read_only' },
  { name: 'auto_upgrade', value: 'auto_upgrade' },
  { name: 'manual', value: 'manual' },
  { name: 'full', value: 'full' },
];

const SSL_MODES = ['disable', 'require', 'verify-ca', 'verify-full'];

function defaultUser(dbType: DbType): string {
  if (dbType === 'mysql') return 'root';
  if (dbType === 'mongodb') return 'admin';
  return 'postgres';
}

function clone(draft: AddDatabaseDraft): AddDatabaseDraft {
  return { ...draft };
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

function suggestAlias(
  draft: AddDatabaseDraft,
  aliasExists: (alias: string) => boolean,
): string {
  const base = slug(draft.database) || `${draft.dbType}-db`;
  let candidate = base;
  let suffix = 2;
  while (aliasExists(candidate)) {
    const tail = `-${suffix}`;
    candidate = `${base.slice(0, 64 - tail.length)}${tail}`;
    suffix += 1;
  }
  return candidate;
}

function summary(draft: AddDatabaseDraft): string {
  const host = `${draft.host}${draft.dbType === 'mongodb' && draft.srv ? '' : `:${draft.port}`}`;
  const password =
    draft.passwordMode === 'env' ? `$${draft.passwordEnv ?? ''}` : 'encrypted at rest';
  const lines = [
    `Engine: ${draft.dbType}${draft.srv ? ' (mongodb+srv)' : ''}   Host: ${host}`,
    `Database: ${draft.database}   User: ${draft.user}`,
    `Password: ${password}   SSL: ${draft.sslMode}`,
  ];
  if (draft.dbType === 'mongodb') {
    lines.push(
      `Mongo: auth=${draft.authSource ?? draft.database} read=${draft.readPreference ?? 'primary'} concern=${draft.readConcern ?? 'local'}`,
    );
  }
  lines.push(`Alias: ${draft.alias}   Project: ${draft.projectName}`);
  lines.push(`Permission: ${draft.permission ?? 'default'}`);
  return lines.join('\n');
}

interface ParsedUrl {
  host: string;
  port: number;
  database: string;
  user: string;
  srv: boolean;
  sslMode: DbEntry['ssl_mode'];
  authSource: string | null;
  readPreference: MongoReadPreference | null;
  readConcern: MongoReadConcern | null;
}

function parseConnectionUrl(raw: string, engine: DbType): ParsedUrl | { error: string } {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { error: 'That URL could not be parsed.' };
  }

  const expected =
    engine === 'postgres'
      ? ['postgres:', 'postgresql:']
      : engine === 'mysql'
        ? ['mysql:']
        : ['mongodb:', 'mongodb+srv:'];
  if (!expected.includes(url.protocol)) {
    return { error: `Use ${expected.join(' or ')} for ${engine}.` };
  }
  if (url.password) {
    return { error: 'Passwords are not accepted in URLs. Choose a password source on the next step.' };
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host || (!isValidHostname(host) && !isValidIpv4(host) && !isValidIpv6(host))) {
    return { error: 'The URL has an invalid host.' };
  }

  const port = url.port ? Number(url.port) : defaultPortFor(engine);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: 'The URL has an invalid port.' };
  }

  const rawDatabase = decodeURIComponent(url.pathname.replace(/^\//, '').split('/')[0] || '');
  if (!rawDatabase || rawDatabase.length > maxDatabaseNameLength(engine)) {
    return { error: 'The URL must include a valid database name.' };
  }

  const user = decodeURIComponent(url.username || defaultUser(engine));
  if (!user || user.length > maxUserNameLength(engine)) {
    return { error: 'The URL has an invalid username.' };
  }

  let sslMode: DbEntry['ssl_mode'] = 'require';
  const sslParam = url.searchParams.get('sslmode');
  if (sslParam && SSL_MODES.includes(sslParam)) {
    sslMode = sslParam as DbEntry['ssl_mode'];
  }
  if (url.searchParams.get('tls') === 'false' || url.searchParams.get('ssl') === 'false') {
    sslMode = 'disable';
  }

  let authSource: string | null = null;
  let readPreference: MongoReadPreference | null = null;
  let readConcern: MongoReadConcern | null = null;
  if (engine === 'mongodb') {
    authSource = url.searchParams.get('authSource');
    const pref = url.searchParams.get('readPreference');
    if (pref && MONGODB_READ_PREFERENCES.includes(pref as MongoReadPreference)) {
      readPreference = pref as MongoReadPreference;
    }
    const concern = url.searchParams.get('readConcernLevel');
    if (concern && MONGODB_READ_CONCERNS.includes(concern as MongoReadConcern)) {
      readConcern = concern as MongoReadConcern;
    }
  }

  return {
    host,
    port,
    database: rawDatabase,
    user,
    srv: url.protocol === 'mongodb+srv:',
    sslMode,
    authSource,
    readPreference,
    readConcern,
  };
}

function buildSteps(
  draft: AddDatabaseDraft,
  aliasExists: (alias: string) => boolean,
): Step[] {
  const steps: Step[] = [
    {
      id: 'engine',
      title: 'Database engine',
      hint: 'Sets the driver, port and defaults.',
      kind: 'select',
      choices: ENGINE_CHOICES,
      initial: draft.dbType,
      apply: (value, current) => {
        const next = DB_TYPES.includes(value as DbType) ? (value as DbType) : 'postgres';
        current.dbType = next;
        current.connectionMode = 'manual';
        current.host = 'localhost';
        current.port = defaultPortFor(next);
        current.user = defaultUser(next);
        current.srv = false;
        current.authSource = null;
        current.readPreference = null;
        current.readConcern = null;
        current.connectionUrl = '';
      },
    },
    {
      id: 'connectionUrl',
      title: 'Connection URL',
      hint: 'Optional. Leave empty for manual entry. Never include a password.',
      kind: 'input',
      initial: draft.connectionUrl,
      placeholder: `${draft.dbType}://${defaultUser(draft.dbType)}@localhost:${defaultPortFor(draft.dbType)}/app`,
      validate: (value, current) => {
        if (!value.trim()) return null;
        const parsed = parseConnectionUrl(value, current.dbType);
        return 'error' in parsed ? parsed.error : null;
      },
      apply: (value, current) => {
        current.connectionUrl = value.trim();
        current.connectionMode = value.trim() ? 'url' : 'manual';
        if (!value.trim()) return;
        const parsed = parseConnectionUrl(value, current.dbType);
        if ('error' in parsed) return;
        current.host = parsed.host;
        current.port = parsed.port;
        current.database = parsed.database;
        current.user = parsed.user;
        current.srv = parsed.srv;
        current.sslMode = parsed.sslMode;
        current.authSource = parsed.authSource;
        current.readPreference = parsed.readPreference;
        current.readConcern = parsed.readConcern;
      },
    },
    {
      id: 'host',
      title: 'Host',
      hint: 'Hostname or IP address of the database server.',
      kind: 'input',
      skip: (current) => current.connectionMode === 'url',
      initial: draft.host || 'localhost',
      placeholder: 'localhost',
      validate: (value) =>
        isValidHostname(value) || isValidIpv4(value) || isValidIpv6(value)
          ? null
          : 'Enter a valid hostname or IP address.',
      apply: (value, current) => {
        current.host = value.trim();
      },
    },
    {
      id: 'srv',
      title: 'MongoDB DNS seed list',
      hint: 'mongodb+srv:// discovers hosts from DNS. The port field is ignored.',
      kind: 'select',
      skip: (current) => current.dbType !== 'mongodb' || current.connectionMode === 'url',
      choices: [
        { name: 'No — standard connection', value: 'no' },
        { name: 'Yes — mongodb+srv://', value: 'yes' },
      ],
      initial: draft.srv ? 'yes' : 'no',
      apply: (value, current) => {
        current.srv = value === 'yes';
      },
    },
    {
      id: 'port',
      title: 'Port',
      hint: `Default for ${draft.dbType}: ${defaultPortFor(draft.dbType)}.`,
      kind: 'input',
      skip: (current) =>
        current.connectionMode === 'url' || (current.dbType === 'mongodb' && current.srv),
      initial: String(draft.port),
      placeholder: String(defaultPortFor(draft.dbType)),
      maxLength: 5,
      validate: (value) => {
        const port = Number(value);
        return Number.isInteger(port) && port >= 1 && port <= 65535
          ? null
          : 'Port must be a number between 1 and 65535.';
      },
      apply: (value, current) => {
        current.port = Number(value);
      },
    },
    {
      id: 'database',
      title: 'Database name',
      hint: `Maximum ${maxDatabaseNameLength(draft.dbType)} characters.`,
      kind: 'input',
      skip: (current) => current.connectionMode === 'url',
      initial: draft.database,
      placeholder: 'e.g. orders_prod',
      maxLength: maxDatabaseNameLength(draft.dbType),
      validate: (value, current) =>
        value.trim().length > 0 && value.length <= maxDatabaseNameLength(current.dbType)
          ? null
          : 'Database name is required.',
      apply: (value, current) => {
        current.database = value.trim();
      },
    },
    {
      id: 'user',
      title: 'Username',
      hint: `Maximum ${maxUserNameLength(draft.dbType)} characters.`,
      kind: 'input',
      skip: (current) => current.connectionMode === 'url',
      initial: draft.user || defaultUser(draft.dbType),
      placeholder: defaultUser(draft.dbType),
      maxLength: maxUserNameLength(draft.dbType),
      validate: (value, current) =>
        value.trim().length > 0 && value.length <= maxUserNameLength(current.dbType)
          ? null
          : 'Username is required.',
      apply: (value, current) => {
        current.user = value.trim();
      },
    },
    {
      id: 'passwordSource',
      title: 'Password source',
      hint: 'Never passed in argv or URLs.',
      kind: 'select',
      choices: PASSWORD_CHOICES,
      initial: draft.passwordMode,
      apply: (value, current) => {
        current.passwordMode = value === 'stored' ? 'stored' : 'env';
        if (current.passwordMode === 'env') current.passwordStored = undefined;
        else current.passwordEnv = undefined;
      },
    },
    {
      id: 'passwordValue',
      title: draft.passwordMode === 'stored' ? 'Password' : 'Environment variable name',
      hint:
        draft.passwordMode === 'stored'
          ? 'The value is masked and encrypted at rest.'
          : 'Name of the variable that holds the password at connect time.',
      kind: 'secret',
      initial: draft.passwordMode === 'env' ? (draft.passwordEnv ?? 'DB_PASSWORD') : '',
      placeholder: draft.passwordMode === 'env' ? 'DB_PASSWORD' : undefined,
      initialSecret: draft.passwordMode === 'env' ? (draft.passwordEnv ?? '') : (draft.passwordStored ?? ''),
      validate: (value, current) =>
        current.passwordMode === 'env'
          ? isValidEnvVarName(value)
            ? null
            : 'Use an uppercase environment variable name, e.g. DB_PASSWORD.'
          : value.length > 0
            ? null
            : 'Password cannot be empty.',
      apply: (value, current) => {
        if (current.passwordMode === 'env') {
          current.passwordEnv = value.trim();
          current.passwordStored = undefined;
        } else {
          current.passwordStored = value;
          current.passwordEnv = undefined;
        }
      },
    },
    {
      id: 'sslMode',
      title: 'SSL mode',
      hint: 'Transport security for the database connection.',
      kind: 'select',
      choices: SSL_CHOICES,
      initial: draft.sslMode,
      apply: (value, current) => {
        current.sslMode = value as DbEntry['ssl_mode'];
      },
    },
    {
      id: 'sslCert',
      title: 'SSL root certificate path',
      hint: 'Optional. Leave empty to use the system trust store.',
      kind: 'input',
      skip: (current) => current.sslMode !== 'verify-ca' && current.sslMode !== 'verify-full',
      initial: draft.sslRootCert ?? '',
      placeholder: '/etc/ssl/certs/ca.pem',
      validate: (value) =>
        !value.trim() || fs.existsSync(value.trim()) ? null : 'Certificate file not found.',
      apply: (value, current) => {
        current.sslRootCert = value.trim() || null;
      },
    },
    {
      id: 'authSource',
      title: 'MongoDB auth source',
      hint: 'Authentication database. Usually the target database or admin.',
      kind: 'input',
      skip: (current) => current.dbType !== 'mongodb',
      initial: draft.authSource ?? draft.database,
      placeholder: draft.database || 'admin',
      apply: (value, current) => {
        current.authSource = value.trim() || current.database;
      },
    },
    {
      id: 'readPreference',
      title: 'MongoDB read preference',
      hint: 'Which replica set member may serve reads.',
      kind: 'select',
      skip: (current) => current.dbType !== 'mongodb',
      choices: MONGODB_READ_PREFERENCES.map((value) => ({ name: value, value })),
      initial: draft.readPreference ?? 'primary',
      apply: (value, current) => {
        current.readPreference = value as MongoReadPreference;
      },
    },
    {
      id: 'readConcern',
      title: 'MongoDB read concern',
      hint: 'Isolation level for reads.',
      kind: 'select',
      skip: (current) => current.dbType !== 'mongodb',
      choices: MONGODB_READ_CONCERNS.map((value) => ({ name: value, value })),
      initial: draft.readConcern ?? 'local',
      apply: (value, current) => {
        current.readConcern = value as MongoReadConcern;
      },
    },
    {
      id: 'permission',
      title: 'Permission override',
      hint: 'Least privilege is the default.',
      kind: 'select',
      choices: PERMISSION_CHOICES,
      initial: draft.permission ?? '',
      apply: (value, current) => {
        current.permission = value ? (value as PermissionLevel) : null;
      },
    },
    {
      id: 'alias',
      title: 'Database alias',
      hint: 'Suggested from the database name.',
      kind: 'input',
      initial: draft.alias || suggestAlias(draft, aliasExists),
      placeholder: suggestAlias(draft, aliasExists),
      maxLength: 64,
      validate: (value) => {
        const alias = value.trim();
        if (!isValidIdentifier(alias, 64) || alias.includes(' ')) {
          return 'Use 1-64 letters, numbers, hyphens or underscores.';
        }
        return aliasExists(alias) ? 'That alias already exists. Choose another.' : null;
      },
      apply: (value, current) => {
        current.alias = value.trim();
        current.projectName = current.alias;
      },
    },
    {
      id: 'review',
      title: 'Review and save',
      hint: 'Confirm the values below.',
      kind: 'review',
      choices: [
        { name: 'Save and test connection', value: 'save' },
        { name: 'Back', value: 'back' },
        { name: 'Cancel', value: 'cancel' },
      ],
      initial: 'save',
      apply: () => undefined,
    },
  ];

  return steps.filter((step) => !step.skip?.(draft));
}

export type AddWizardResult =
  | { status: 'complete'; draft: AddDatabaseDraft }
  | { status: 'cancelled' }
  | { status: 'unavailable' };

interface WizardHistoryEntry {
  id: string;
  draft: AddDatabaseDraft;
}

/** Full-screen `db add` wizard. */
export async function runAddDatabaseWizard(
  options: AddWizardOptions = {},
): Promise<AddWizardResult> {
  const aliasExists = options.aliasExists ?? (() => false);
  const screen = options.screen ?? createTuiScreen();
  if (!screen) return { status: 'unavailable' };

  const ownsScreen = !options.screen;
  if (ownsScreen) setTuiActive(true);

  return new Promise<AddWizardResult>((resolve) => {
    const draft: AddDatabaseDraft = {
      dbType: 'postgres',
      connectionMode: 'manual',
      connectionUrl: '',
      host: 'localhost',
      srv: false,
      port: defaultPortFor('postgres'),
      database: '',
      user: defaultUser('postgres'),
      passwordMode: 'env',
      passwordEnv: undefined,
      passwordStored: undefined,
      sslMode: 'require',
      sslRootCert: null,
      authSource: null,
      readPreference: null,
      readConcern: null,
      permission: null,
      alias: '',
      projectName: '',
    };

    const history: WizardHistoryEntry[] = [];
    const values = new Map<string, string>();
    let currentSteps = buildSteps(draft, aliasExists);
    let stepIndex = 0;
    let activeStepId = '';
    let editorValue = '';
    let editorCursor = 0;
    let selectedIndex = 0;
    let error = '';
    let settled = false;
    let offKey: (() => void) | null = null;
    let offResize: (() => void) | null = null;

    const finish = (value: AddDatabaseDraft | undefined) => {
      if (settled) return;
      settled = true;
      offKey?.();
      offResize?.();
      if (ownsScreen) {
        setTuiActive(false);
        screen.destroy();
      }
      resolve(value ? { status: 'complete', draft: clone(value) } : { status: 'cancelled' });
    };

    const clearDependentValues = (stepId: string, value: string) => {
      const forget = (...ids: string[]) => {
        for (const id of ids) values.delete(id);
      };
      if (stepId === 'engine') {
        forget(
          'connectionUrl',
          'host',
          'srv',
          'port',
          'database',
          'user',
          'sslMode',
          'sslCert',
          'authSource',
          'readPreference',
          'readConcern',
          'alias',
        );
      } else if (stepId === 'connectionUrl') {
        forget('alias');
        if (!value.trim()) {
          forget('host', 'srv', 'port', 'database', 'user', 'sslMode', 'sslCert', 'authSource', 'readPreference', 'readConcern');
        }
      } else if (stepId === 'database') {
        forget('alias');
      } else if (stepId === 'passwordSource') {
        forget('passwordValue');
      } else if (stepId === 'sslMode') {
        forget('sslCert');
      }
    };

    const back = () => {
      if (history.length === 0) {
        finish(undefined);
        return;
      }
      const previous = history.pop();
      if (!previous) return;
      Object.assign(draft, previous.draft);
      currentSteps = buildSteps(draft, aliasExists);
      const index = currentSteps.findIndex((item) => item.id === previous.id);
      stepIndex = index >= 0 ? index : 0;
      error = '';
      render();
    };

    const commit = (step: Step, value: string) => {
      const problem = step.validate?.(value, draft) ?? null;
      if (problem) {
        error = problem;
        render();
        return;
      }

      const before = clone(draft);
      values.set(step.id, value);
      clearDependentValues(step.id, value);
      step.apply(value, draft);
      history.push({ id: step.id, draft: before });

      currentSteps = buildSteps(draft, aliasExists);
      const currentIndex = currentSteps.findIndex((item) => item.id === step.id);
      stepIndex = Math.min(currentIndex + 1, currentSteps.length - 1);
      error = '';
      render();
    };

    const chooseReview = (value: string) => {
      if (value === 'save') finish(clone(draft));
      else if (value === 'back') back();
      else finish(undefined);
    };

    const moveSelection = (delta: number) => {
      const step = currentSteps[stepIndex];
      const count = step?.choices?.length ?? 0;
      if (count === 0) return;
      selectedIndex = (selectedIndex + delta + count) % count;
      error = '';
      render();
    };

    const insertText = (text: string) => {
      const step = currentSteps[stepIndex];
      if (!text) return;
      const max = step?.maxLength ?? 500;
      const allowed = text.slice(0, Math.max(0, max - editorValue.length));
      if (!allowed) return;
      editorValue =
        editorValue.slice(0, editorCursor) + allowed + editorValue.slice(editorCursor);
      editorCursor += allowed.length;
      error = '';
      render();
    };

    const deleteSelection = (backward: boolean) => {
      if (backward) {
        if (editorCursor <= 0) return;
        editorValue =
          editorValue.slice(0, editorCursor - 1) + editorValue.slice(editorCursor);
        editorCursor -= 1;
      } else {
        if (editorCursor >= editorValue.length) return;
        editorValue =
          editorValue.slice(0, editorCursor) + editorValue.slice(editorCursor + 1);
      }
      error = '';
      render();
    };

    const onKey = (key: TuiKey) => {
      if (settled) return;

      if (key.ctrl && key.name === 'c') {
        finish(undefined);
        return;
      }
      if (key.name === 'escape') {
        back();
        return;
      }

      const step = currentSteps[stepIndex];
      if (!step) return;

      if (step.kind === 'input' || step.kind === 'secret') {
        if (key.name === 'return') {
          commit(step, editorValue);
          return;
        }
        if (key.name === 'backspace') {
          deleteSelection(true);
          return;
        }
        if (key.name === 'delete') {
          deleteSelection(false);
          return;
        }
        if (key.name === 'left') {
          editorCursor = Math.max(0, editorCursor - 1);
          render();
          return;
        }
        if (key.name === 'right') {
          editorCursor = Math.min(editorValue.length, editorCursor + 1);
          render();
          return;
        }
        if (key.name === 'home') {
          editorCursor = 0;
          render();
          return;
        }
        if (key.name === 'end') {
          editorCursor = editorValue.length;
          render();
          return;
        }
        if (key.ctrl && key.name === 'u') {
          editorValue = '';
          editorCursor = 0;
          error = '';
          render();
          return;
        }
        if (key.ctrl && key.name === 'w') {
          const before = editorValue.slice(0, editorCursor).replace(/\s*\S+\s*$/, '');
          editorValue = before + editorValue.slice(editorCursor);
          editorCursor = before.length;
          error = '';
          render();
          return;
        }
        if (key.ctrl || key.meta) return;
        if (key.name === 'tab') return;
        insertText(key.sequence);
        return;
      }

      const choices = step.choices ?? [];
      if (key.name === 'up') {
        moveSelection(-1);
      } else if (key.name === 'down') {
        moveSelection(1);
      } else if (key.name === 'pageup') {
        moveSelection(-Math.max(1, Math.floor(choices.length / 2)));
      } else if (key.name === 'pagedown') {
        moveSelection(Math.max(1, Math.floor(choices.length / 2)));
      } else if (key.name === 'home') {
        selectedIndex = 0;
        render();
      } else if (key.name === 'end') {
        selectedIndex = Math.max(0, choices.length - 1);
        render();
      } else if (/^[0-9]$/.test(key.name)) {
        const index = Number(key.name) - 1;
        if (index >= 0 && index < choices.length) {
          selectedIndex = index;
          error = '';
          render();
        }
      } else if (key.name === 'return') {
        const choice = choices[selectedIndex];
        if (!choice) return;
        if (step.kind === 'review') chooseReview(choice.value);
        else commit(step, choice.value);
      }
    };

    const render = () => {
      if (settled) return;
      currentSteps = buildSteps(draft, aliasExists);
      stepIndex = Math.max(0, Math.min(stepIndex, currentSteps.length - 1));
      const step = currentSteps[stepIndex];
      if (!step) {
        finish(undefined);
        return;
      }

      if (step.id !== activeStepId) {
        activeStepId = step.id;
        const saved = values.get(step.id);
        if (step.kind === 'input' || step.kind === 'secret') {
          editorValue = saved ?? step.initial;
          editorCursor = editorValue.length;
        } else {
          const savedIndex = saved
            ? (step.choices ?? []).findIndex((choice) => choice.value === saved)
            : -1;
          const initialIndex = (step.choices ?? []).findIndex(
            (choice) => choice.value === step.initial,
          );
          selectedIndex = savedIndex >= 0 ? savedIndex : Math.max(0, initialIndex);
        }
      }

      const width = Math.max(40, screen.width);
      const height = Math.max(10, screen.height);
      const left = 2;
      const right = Math.max(20, width - 2);
      const bodyWidth = Math.max(16, right - left - 2);
      const lines: string[] = Array.from({ length: height }, () => '');
      const regions: TuiRegion[] = [];

      const put = (row: number, col: number, text: string) => {
        if (row < 0 || row >= height || col >= width) return;
        lines[row] = lines[row].padEnd(col, ' ') + truncateAnsi(text, width - col, '');
      };

      const region = (
        row: number,
        col: number,
        regionWidth: number,
        onClick?: (event: TuiMouseEvent) => void,
        onWheel?: (delta: number) => void,
      ) => {
        regions.push({
          rect: { x: col, y: row, width: regionWidth, height: 1 },
          onClick,
          onWheel,
        });
      };

      const footerRow = height - 1;
      const contentEnd = footerRow - 2;
      const fieldX = left + 2;
      const hintWidth = Math.min(72, right - left);
      const introStart = height < 14 ? 3 : 4;
      const introBudget = Math.max(1, contentEnd - introStart - 1);

      put(0, left, C.bold(C.white('Add a database')));
      put(0, left + 18, C.dim(draft.dbType));
      const progress = `${stepIndex + 1}/${currentSteps.length}`;
      put(0, Math.max(left + 26, right - visibleLength(progress)), C.dim(progress));
      put(introStart - 2, left, C.bold(C.brightCyan(step.title)));

      let row = introStart;
      let introUsed = 0;
      const putIntro = (text: string, color: (value: string) => string) => {
        for (const line of wrapTuiText(text, hintWidth).slice(0, 2)) {
          if (!line.trim() || introUsed >= introBudget) continue;
          put(row++, left, color(line));
          introUsed += 1;
        }
      };
      putIntro(step.hint, C.dim);
      if (error) putIntro(`! ${error}`, C.red);
      if (height >= 14 && row <= contentEnd) row += 1;

      if (step.kind === 'input' || step.kind === 'secret') {
        const maxVisible = Math.max(8, bodyWidth - 2);
        const start = Math.max(
          0,
          Math.min(editorCursor - maxVisible + 1, Math.max(0, editorValue.length - maxVisible + 1)),
        );
        const raw = step.kind === 'secret' ? '•'.repeat(editorValue.length) : editorValue;
        const visibleRaw = raw.slice(start, start + maxVisible);
        const cursorIndex = Math.max(0, editorCursor - start);
        const before = visibleRaw.slice(0, cursorIndex);
        const at = visibleRaw[cursorIndex] ?? ' ';
        const after = visibleRaw.slice(cursorIndex + 1);
        const placeholder = editorValue.length === 0 ? C.dim(step.placeholder ?? '') : '';

        if (row <= contentEnd) {
          put(row, left, `${C.brightCyan('›')} ${before}${tuiCursorChar(at)}${after}${placeholder}`);
          const valueX = left + 2;
          region(row, left, right - left, (event) => {
            if (event.action === 'move') return;
            editorCursor = Math.min(editorValue.length, start + Math.max(0, event.x - valueX));
            render();
          });
        }
      } else {
        const choices = step.choices ?? [];

        if (step.kind === 'review') {
          let summaryBudget = Math.max(0, contentEnd - row - choices.length - 1);
          for (const line of summary(draft).split('\n')) {
            for (const wrapped of wrapTuiText(line, bodyWidth).slice(0, 2)) {
              if (summaryBudget <= 0) break;
              put(row++, fieldX, C.dim(wrapped));
              summaryBudget -= 1;
            }
          }
          if (row <= contentEnd) row += 1;
        }

        const maxRows = Math.max(1, Math.min(choices.length, contentEnd - row + 1));
        const startIndex = Math.max(
          0,
          Math.min(selectedIndex - maxRows + 1, choices.length - maxRows),
        );

        for (let i = startIndex; i < startIndex + maxRows; i += 1) {
          const choice = choices[i];
          if (!choice) continue;
          const selected = i === selectedIndex;
          const marker = selected ? C.brightCyan('›') : ' ';
          const name = selected ? C.brightCyan(choice.name) : C.white(choice.name);
          put(row, fieldX, `${marker} ${C.dim(`${i + 1})`)} ${name}`);
          region(
            row,
            left,
            right - left,
            (event) => {
              if (event.action === 'move') {
                if (selectedIndex !== i) {
                  selectedIndex = i;
                  render();
                }
                return;
              }
              selectedIndex = i;
              if (step.kind === 'review') chooseReview(choice.value);
              else commit(step, choice.value);
            },
            (delta) => {
              selectedIndex = (selectedIndex + delta + choices.length) % choices.length;
              render();
            },
          );
          row += 1;
        }
      }

      const commitCurrent = () => {
        const current = currentSteps[stepIndex];
        if (!current) return;
        if (current.kind === 'input' || current.kind === 'secret') {
          commit(current, editorValue);
        } else {
          const choice = current.choices?.[selectedIndex];
          if (!choice) return;
          if (current.kind === 'review') chooseReview(choice.value);
          else commit(current, choice.value);
        }
      };

      let offset = left;
      const action = (
        label: string,
        color: (text: string) => string,
        handler: () => void,
      ) => {
        put(footerRow, offset, color(label));
        region(footerRow, offset, visibleLength(label), (event) => {
          if (event.action !== 'move') handler();
        });
        offset += visibleLength(label) + 3;
      };
      action('enter continue', C.brightCyan, commitCurrent);
      action('esc back', C.dim, back);
      action('ctrl+c cancel', C.dim, () => finish(undefined));

      screen.render({ lines, regions });
    };
    offKey = screen.onKey(onKey);
    offResize = screen.onResize(render);
    render();
  });
}
