var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// ../pla748-cad/node_modules/@paperclipai/plugin-sdk/dist/define-plugin.js
function definePlugin(definition) {
  return Object.freeze({ definition });
}

// ../pla748-cad/node_modules/@paperclipai/plugin-sdk/dist/worker-rpc-host.js
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

// ../pla748-cad/node_modules/@paperclipai/plugin-sdk/dist/protocol.js
var JSONRPC_VERSION = "2.0";
var JSONRPC_ERROR_CODES = {
  /** Invalid JSON was received by the server. */
  PARSE_ERROR: -32700,
  /** The JSON sent is not a valid Request object. */
  INVALID_REQUEST: -32600,
  /** The method does not exist or is not available. */
  METHOD_NOT_FOUND: -32601,
  /** Invalid method parameter(s). */
  INVALID_PARAMS: -32602,
  /** Internal JSON-RPC error. */
  INTERNAL_ERROR: -32603
};
var PLUGIN_RPC_ERROR_CODES = {
  /** The worker process is not running or not reachable. */
  WORKER_UNAVAILABLE: -32e3,
  /** The plugin does not have the required capability for this operation. */
  CAPABILITY_DENIED: -32001,
  /** The worker reported an unhandled error during method execution. */
  WORKER_ERROR: -32002,
  /** The method call timed out waiting for the worker response. */
  TIMEOUT: -32003,
  /** The worker does not implement the requested optional method. */
  METHOD_NOT_IMPLEMENTED: -32004,
  /** A catch-all for errors that do not fit other categories. */
  UNKNOWN: -32099
};
var _nextId = 1;
var MAX_SAFE_RPC_ID = Number.MAX_SAFE_INTEGER - 1;
function createRequest(method, params, id) {
  if (_nextId >= MAX_SAFE_RPC_ID) {
    _nextId = 1;
  }
  return {
    jsonrpc: JSONRPC_VERSION,
    id: id ?? _nextId++,
    method,
    params
  };
}
function createSuccessResponse(id, result) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    result
  };
}
function createErrorResponse(id, code, message, data) {
  const response = {
    jsonrpc: JSONRPC_VERSION,
    id,
    error: data !== void 0 ? { code, message, data } : { code, message }
  };
  return response;
}
function createNotification(method, params) {
  return {
    jsonrpc: JSONRPC_VERSION,
    method,
    params
  };
}
function isJsonRpcRequest(value) {
  if (typeof value !== "object" || value === null)
    return false;
  const obj = value;
  return obj.jsonrpc === JSONRPC_VERSION && typeof obj.method === "string" && "id" in obj && obj.id !== void 0 && obj.id !== null;
}
function isJsonRpcNotification(value) {
  if (typeof value !== "object" || value === null)
    return false;
  const obj = value;
  return obj.jsonrpc === JSONRPC_VERSION && typeof obj.method === "string" && !("id" in obj);
}
function isJsonRpcResponse(value) {
  if (typeof value !== "object" || value === null)
    return false;
  const obj = value;
  return obj.jsonrpc === JSONRPC_VERSION && "id" in obj && ("result" in obj || "error" in obj);
}
function isJsonRpcSuccessResponse(response) {
  return "result" in response && !("error" in response && response.error !== void 0);
}
function isJsonRpcErrorResponse(response) {
  return "error" in response && response.error !== void 0;
}
var MESSAGE_DELIMITER = "\n";
function serializeMessage(message) {
  return JSON.stringify(message) + MESSAGE_DELIMITER;
}
function parseMessage(line) {
  const trimmed = line.trim();
  if (trimmed.length === 0) {
    throw new JsonRpcParseError("Empty message");
  }
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new JsonRpcParseError(`Invalid JSON: ${trimmed.slice(0, 200)}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new JsonRpcParseError("Message must be a JSON object");
  }
  const obj = parsed;
  if (obj.jsonrpc !== JSONRPC_VERSION) {
    throw new JsonRpcParseError(`Invalid or missing jsonrpc version (expected "${JSONRPC_VERSION}", got ${JSON.stringify(obj.jsonrpc)})`);
  }
  return parsed;
}
var JsonRpcParseError = class extends Error {
  name = "JsonRpcParseError";
  constructor(message) {
    super(message);
  }
};
var JsonRpcCallError = class extends Error {
  name = "JsonRpcCallError";
  /** The JSON-RPC error code. */
  code;
  /** Optional structured error data from the response. */
  data;
  constructor(error) {
    super(error.message);
    this.code = error.code;
    this.data = error.data;
  }
};

// ../pla748-cad/node_modules/@paperclipai/plugin-sdk/dist/worker-rpc-host.js
var DEFAULT_RPC_TIMEOUT_MS = 3e4;
function runWorker(plugin2, moduleUrl, options) {
  if (options?.stdin != null && options?.stdout != null) {
    return startWorkerRpcHost({
      plugin: plugin2,
      stdin: options.stdin,
      stdout: options.stdout
    });
  }
  const entry = process.argv[1];
  if (typeof entry !== "string")
    return;
  const thisFile = path.resolve(fileURLToPath(moduleUrl));
  const entryPath = path.resolve(entry);
  if (thisFile === entryPath) {
    startWorkerRpcHost({ plugin: plugin2 });
  }
}
function startWorkerRpcHost(options) {
  const { plugin: plugin2 } = options;
  const stdinStream = options.stdin ?? process.stdin;
  const stdoutStream = options.stdout ?? process.stdout;
  const rpcTimeoutMs = options.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
  let running = true;
  let initialized = false;
  let manifest = null;
  let currentConfig = {};
  let databaseNamespace = null;
  const eventHandlers = [];
  const jobHandlers = /* @__PURE__ */ new Map();
  const launcherRegistrations = /* @__PURE__ */ new Map();
  const dataHandlers = /* @__PURE__ */ new Map();
  const actionHandlers = /* @__PURE__ */ new Map();
  const toolHandlers = /* @__PURE__ */ new Map();
  const sessionEventCallbacks = /* @__PURE__ */ new Map();
  const pendingRequests = /* @__PURE__ */ new Map();
  let nextOutboundId = 1;
  const MAX_OUTBOUND_ID = Number.MAX_SAFE_INTEGER - 1;
  function sendMessage(message) {
    if (!running)
      return;
    const serialized = serializeMessage(message);
    stdoutStream.write(serialized);
  }
  function callHost(method, params, timeoutMs) {
    return new Promise((resolve2, reject) => {
      if (!running) {
        reject(new Error(`Cannot call "${method}" \u2014 worker RPC host is not running`));
        return;
      }
      if (nextOutboundId >= MAX_OUTBOUND_ID) {
        nextOutboundId = 1;
      }
      const id = nextOutboundId++;
      const timeout = timeoutMs ?? rpcTimeoutMs;
      let settled = false;
      const settle = (fn, value) => {
        if (settled)
          return;
        settled = true;
        clearTimeout(timer);
        pendingRequests.delete(id);
        fn(value);
      };
      const timer = setTimeout(() => {
        settle(reject, new JsonRpcCallError({
          code: PLUGIN_RPC_ERROR_CODES.TIMEOUT,
          message: `Worker\u2192host call "${method}" timed out after ${timeout}ms`
        }));
      }, timeout);
      pendingRequests.set(id, {
        resolve: (response) => {
          if (isJsonRpcSuccessResponse(response)) {
            settle(resolve2, response.result);
          } else if (isJsonRpcErrorResponse(response)) {
            settle(reject, new JsonRpcCallError(response.error));
          } else {
            settle(reject, new Error(`Unexpected response format for "${method}"`));
          }
        },
        timer
      });
      try {
        const request = createRequest(method, params, id);
        sendMessage(request);
      } catch (err) {
        settle(reject, err instanceof Error ? err : new Error(String(err)));
      }
    });
  }
  function notifyHost(method, params) {
    try {
      sendMessage(createNotification(method, params));
    } catch {
    }
  }
  function buildContext() {
    return {
      get manifest() {
        if (!manifest)
          throw new Error("Plugin context accessed before initialization");
        return manifest;
      },
      config: {
        async get() {
          return callHost("config.get", {});
        }
      },
      events: {
        on(name, filterOrFn, maybeFn) {
          let registration;
          if (typeof filterOrFn === "function") {
            registration = { name, fn: filterOrFn };
          } else {
            if (!maybeFn)
              throw new Error("Event handler function is required");
            registration = { name, filter: filterOrFn, fn: maybeFn };
          }
          eventHandlers.push(registration);
          void callHost("events.subscribe", { eventPattern: name, filter: registration.filter ?? null }).catch((err) => {
            notifyHost("log", {
              level: "warn",
              message: `Failed to subscribe to event "${name}" on host: ${err instanceof Error ? err.message : String(err)}`
            });
          });
          return () => {
            const idx = eventHandlers.indexOf(registration);
            if (idx !== -1)
              eventHandlers.splice(idx, 1);
          };
        },
        async emit(name, companyId, payload) {
          await callHost("events.emit", { name, companyId, payload });
        }
      },
      jobs: {
        register(key, fn) {
          jobHandlers.set(key, fn);
        }
      },
      launchers: {
        register(launcher) {
          launcherRegistrations.set(launcher.id, launcher);
        }
      },
      db: {
        get namespace() {
          return databaseNamespace ?? "";
        },
        async query(sql, params) {
          return callHost("db.query", { sql, params });
        },
        async execute(sql, params) {
          return callHost("db.execute", { sql, params });
        }
      },
      http: {
        async fetch(url, init) {
          const serializedInit = {};
          if (init) {
            if (init.method)
              serializedInit.method = init.method;
            if (init.headers) {
              if (init.headers instanceof Headers) {
                const obj = {};
                init.headers.forEach((v, k) => {
                  obj[k] = v;
                });
                serializedInit.headers = obj;
              } else if (Array.isArray(init.headers)) {
                const obj = {};
                for (const [k, v] of init.headers)
                  obj[k] = v;
                serializedInit.headers = obj;
              } else {
                serializedInit.headers = init.headers;
              }
            }
            if (init.body !== void 0 && init.body !== null) {
              serializedInit.body = typeof init.body === "string" ? init.body : String(init.body);
            }
          }
          const result = await callHost("http.fetch", {
            url,
            init: Object.keys(serializedInit).length > 0 ? serializedInit : void 0
          });
          return new Response(result.body, {
            status: result.status,
            statusText: result.statusText,
            headers: result.headers
          });
        }
      },
      secrets: {
        async resolve(secretRef) {
          return callHost("secrets.resolve", { secretRef });
        }
      },
      activity: {
        async log(entry) {
          await callHost("activity.log", {
            companyId: entry.companyId,
            message: entry.message,
            entityType: entry.entityType,
            entityId: entry.entityId,
            metadata: entry.metadata
          });
        }
      },
      state: {
        async get(input) {
          return callHost("state.get", {
            scopeKind: input.scopeKind,
            scopeId: input.scopeId,
            namespace: input.namespace,
            stateKey: input.stateKey
          });
        },
        async set(input, value) {
          await callHost("state.set", {
            scopeKind: input.scopeKind,
            scopeId: input.scopeId,
            namespace: input.namespace,
            stateKey: input.stateKey,
            value
          });
        },
        async delete(input) {
          await callHost("state.delete", {
            scopeKind: input.scopeKind,
            scopeId: input.scopeId,
            namespace: input.namespace,
            stateKey: input.stateKey
          });
        }
      },
      entities: {
        async upsert(input) {
          return callHost("entities.upsert", {
            entityType: input.entityType,
            scopeKind: input.scopeKind,
            scopeId: input.scopeId,
            externalId: input.externalId,
            title: input.title,
            status: input.status,
            data: input.data
          });
        },
        async list(query) {
          return callHost("entities.list", {
            entityType: query.entityType,
            scopeKind: query.scopeKind,
            scopeId: query.scopeId,
            externalId: query.externalId,
            limit: query.limit,
            offset: query.offset
          });
        }
      },
      projects: {
        async list(input) {
          return callHost("projects.list", {
            companyId: input.companyId,
            limit: input.limit,
            offset: input.offset
          });
        },
        async get(projectId, companyId) {
          return callHost("projects.get", { projectId, companyId });
        },
        async listWorkspaces(projectId, companyId) {
          return callHost("projects.listWorkspaces", { projectId, companyId });
        },
        async getPrimaryWorkspace(projectId, companyId) {
          return callHost("projects.getPrimaryWorkspace", { projectId, companyId });
        },
        async getWorkspaceForIssue(issueId, companyId) {
          return callHost("projects.getWorkspaceForIssue", { issueId, companyId });
        }
      },
      companies: {
        async list(input) {
          return callHost("companies.list", {
            limit: input?.limit,
            offset: input?.offset
          });
        },
        async get(companyId) {
          return callHost("companies.get", { companyId });
        }
      },
      issues: {
        async list(input) {
          return callHost("issues.list", {
            companyId: input.companyId,
            projectId: input.projectId,
            assigneeAgentId: input.assigneeAgentId,
            originKind: input.originKind,
            originId: input.originId,
            status: input.status,
            limit: input.limit,
            offset: input.offset
          });
        },
        async get(issueId, companyId) {
          return callHost("issues.get", { issueId, companyId });
        },
        async create(input) {
          return callHost("issues.create", {
            companyId: input.companyId,
            projectId: input.projectId,
            goalId: input.goalId,
            parentId: input.parentId,
            inheritExecutionWorkspaceFromIssueId: input.inheritExecutionWorkspaceFromIssueId,
            title: input.title,
            description: input.description,
            status: input.status,
            priority: input.priority,
            assigneeAgentId: input.assigneeAgentId,
            assigneeUserId: input.assigneeUserId,
            requestDepth: input.requestDepth,
            billingCode: input.billingCode,
            originKind: input.originKind,
            originId: input.originId,
            originRunId: input.originRunId,
            blockedByIssueIds: input.blockedByIssueIds,
            labelIds: input.labelIds,
            executionWorkspaceId: input.executionWorkspaceId,
            executionWorkspacePreference: input.executionWorkspacePreference,
            executionWorkspaceSettings: input.executionWorkspaceSettings,
            actorAgentId: input.actor?.actorAgentId,
            actorUserId: input.actor?.actorUserId,
            actorRunId: input.actor?.actorRunId
          });
        },
        async update(issueId, patch, companyId, actor) {
          return callHost("issues.update", {
            issueId,
            patch: {
              ...patch,
              actorAgentId: actor?.actorAgentId,
              actorUserId: actor?.actorUserId,
              actorRunId: actor?.actorRunId
            },
            companyId
          });
        },
        async assertCheckoutOwner(input) {
          return callHost("issues.assertCheckoutOwner", input);
        },
        async getSubtree(issueId, companyId, options2) {
          return callHost("issues.getSubtree", {
            issueId,
            companyId,
            includeRoot: options2?.includeRoot,
            includeRelations: options2?.includeRelations,
            includeDocuments: options2?.includeDocuments,
            includeActiveRuns: options2?.includeActiveRuns,
            includeAssignees: options2?.includeAssignees
          });
        },
        async requestWakeup(issueId, companyId, options2) {
          return callHost("issues.requestWakeup", {
            issueId,
            companyId,
            reason: options2?.reason,
            contextSource: options2?.contextSource,
            idempotencyKey: options2?.idempotencyKey,
            actorAgentId: options2?.actorAgentId,
            actorUserId: options2?.actorUserId,
            actorRunId: options2?.actorRunId
          });
        },
        async requestWakeups(issueIds, companyId, options2) {
          return callHost("issues.requestWakeups", {
            issueIds,
            companyId,
            reason: options2?.reason,
            contextSource: options2?.contextSource,
            idempotencyKeyPrefix: options2?.idempotencyKeyPrefix,
            actorAgentId: options2?.actorAgentId,
            actorUserId: options2?.actorUserId,
            actorRunId: options2?.actorRunId
          });
        },
        async listComments(issueId, companyId) {
          return callHost("issues.listComments", { issueId, companyId });
        },
        async createComment(issueId, body, companyId, options2) {
          return callHost("issues.createComment", { issueId, body, companyId, authorAgentId: options2?.authorAgentId });
        },
        async createInteraction(issueId, interaction, companyId, options2) {
          return callHost("issues.createInteraction", {
            issueId,
            companyId,
            interaction,
            authorAgentId: options2?.authorAgentId
          });
        },
        async suggestTasks(issueId, interaction, companyId, options2) {
          return callHost("issues.createInteraction", {
            issueId,
            companyId,
            interaction: {
              ...interaction,
              kind: "suggest_tasks"
            },
            authorAgentId: options2?.authorAgentId
          });
        },
        async askUserQuestions(issueId, interaction, companyId, options2) {
          return callHost("issues.createInteraction", {
            issueId,
            companyId,
            interaction: {
              ...interaction,
              kind: "ask_user_questions"
            },
            authorAgentId: options2?.authorAgentId
          });
        },
        async requestConfirmation(issueId, interaction, companyId, options2) {
          return callHost("issues.createInteraction", {
            issueId,
            companyId,
            interaction: {
              ...interaction,
              kind: "request_confirmation"
            },
            authorAgentId: options2?.authorAgentId
          });
        },
        documents: {
          async list(issueId, companyId) {
            return callHost("issues.documents.list", { issueId, companyId });
          },
          async get(issueId, key, companyId) {
            return callHost("issues.documents.get", { issueId, key, companyId });
          },
          async upsert(input) {
            return callHost("issues.documents.upsert", {
              issueId: input.issueId,
              key: input.key,
              body: input.body,
              companyId: input.companyId,
              title: input.title,
              format: input.format,
              changeSummary: input.changeSummary
            });
          },
          async delete(issueId, key, companyId) {
            return callHost("issues.documents.delete", { issueId, key, companyId });
          }
        },
        relations: {
          async get(issueId, companyId) {
            return callHost("issues.relations.get", { issueId, companyId });
          },
          async setBlockedBy(issueId, blockedByIssueIds, companyId, actor) {
            return callHost("issues.relations.setBlockedBy", {
              issueId,
              companyId,
              blockedByIssueIds,
              actorAgentId: actor?.actorAgentId,
              actorUserId: actor?.actorUserId,
              actorRunId: actor?.actorRunId
            });
          },
          async addBlockers(issueId, blockerIssueIds, companyId, actor) {
            return callHost("issues.relations.addBlockers", {
              issueId,
              companyId,
              blockerIssueIds,
              actorAgentId: actor?.actorAgentId,
              actorUserId: actor?.actorUserId,
              actorRunId: actor?.actorRunId
            });
          },
          async removeBlockers(issueId, blockerIssueIds, companyId, actor) {
            return callHost("issues.relations.removeBlockers", {
              issueId,
              companyId,
              blockerIssueIds,
              actorAgentId: actor?.actorAgentId,
              actorUserId: actor?.actorUserId,
              actorRunId: actor?.actorRunId
            });
          }
        },
        summaries: {
          async getOrchestration(input) {
            return callHost("issues.summaries.getOrchestration", input);
          }
        }
      },
      agents: {
        async list(input) {
          return callHost("agents.list", {
            companyId: input.companyId,
            status: input.status,
            limit: input.limit,
            offset: input.offset
          });
        },
        async get(agentId, companyId) {
          return callHost("agents.get", { agentId, companyId });
        },
        async pause(agentId, companyId) {
          return callHost("agents.pause", { agentId, companyId });
        },
        async resume(agentId, companyId) {
          return callHost("agents.resume", { agentId, companyId });
        },
        async invoke(agentId, companyId, opts) {
          return callHost("agents.invoke", { agentId, companyId, prompt: opts.prompt, reason: opts.reason });
        },
        sessions: {
          async create(agentId, companyId, opts) {
            return callHost("agents.sessions.create", {
              agentId,
              companyId,
              taskKey: opts?.taskKey,
              reason: opts?.reason
            });
          },
          async list(agentId, companyId) {
            return callHost("agents.sessions.list", { agentId, companyId });
          },
          async sendMessage(sessionId, companyId, opts) {
            if (opts.onEvent) {
              sessionEventCallbacks.set(sessionId, opts.onEvent);
            }
            try {
              return await callHost("agents.sessions.sendMessage", {
                sessionId,
                companyId,
                prompt: opts.prompt,
                reason: opts.reason
              });
            } catch (err) {
              sessionEventCallbacks.delete(sessionId);
              throw err;
            }
          },
          async close(sessionId, companyId) {
            sessionEventCallbacks.delete(sessionId);
            await callHost("agents.sessions.close", { sessionId, companyId });
          }
        }
      },
      goals: {
        async list(input) {
          return callHost("goals.list", {
            companyId: input.companyId,
            level: input.level,
            status: input.status,
            limit: input.limit,
            offset: input.offset
          });
        },
        async get(goalId, companyId) {
          return callHost("goals.get", { goalId, companyId });
        },
        async create(input) {
          return callHost("goals.create", {
            companyId: input.companyId,
            title: input.title,
            description: input.description,
            level: input.level,
            status: input.status,
            parentId: input.parentId,
            ownerAgentId: input.ownerAgentId
          });
        },
        async update(goalId, patch, companyId) {
          return callHost("goals.update", {
            goalId,
            patch,
            companyId
          });
        }
      },
      data: {
        register(key, handler) {
          dataHandlers.set(key, handler);
        }
      },
      actions: {
        register(key, handler) {
          actionHandlers.set(key, handler);
        }
      },
      streams: /* @__PURE__ */ (() => {
        const channelCompanyMap = /* @__PURE__ */ new Map();
        return {
          open(channel, companyId) {
            channelCompanyMap.set(channel, companyId);
            notifyHost("streams.open", { channel, companyId });
          },
          emit(channel, event) {
            const companyId = channelCompanyMap.get(channel) ?? "";
            notifyHost("streams.emit", { channel, companyId, event });
          },
          close(channel) {
            const companyId = channelCompanyMap.get(channel) ?? "";
            channelCompanyMap.delete(channel);
            notifyHost("streams.close", { channel, companyId });
          }
        };
      })(),
      tools: {
        register(name, declaration, fn) {
          toolHandlers.set(name, { declaration, fn });
        }
      },
      metrics: {
        async write(name, value, tags) {
          await callHost("metrics.write", { name, value, tags });
        }
      },
      telemetry: {
        async track(eventName, dimensions) {
          await callHost("telemetry.track", { eventName, dimensions });
        }
      },
      logger: {
        info(message, meta) {
          notifyHost("log", { level: "info", message, meta });
        },
        warn(message, meta) {
          notifyHost("log", { level: "warn", message, meta });
        },
        error(message, meta) {
          notifyHost("log", { level: "error", message, meta });
        },
        debug(message, meta) {
          notifyHost("log", { level: "debug", message, meta });
        }
      }
    };
  }
  const ctx = buildContext();
  async function handleHostRequest(request) {
    const { id, method, params } = request;
    try {
      const result = await dispatchMethod(method, params);
      sendMessage(createSuccessResponse(id, result ?? null));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      const errorCode = typeof err?.code === "number" ? err.code : PLUGIN_RPC_ERROR_CODES.WORKER_ERROR;
      sendMessage(createErrorResponse(id, errorCode, errorMessage));
    }
  }
  async function dispatchMethod(method, params) {
    switch (method) {
      case "initialize":
        return handleInitialize(params);
      case "health":
        return handleHealth();
      case "shutdown":
        return handleShutdown();
      case "validateConfig":
        return handleValidateConfig(params);
      case "configChanged":
        return handleConfigChanged(params);
      case "onEvent":
        return handleOnEvent(params);
      case "runJob":
        return handleRunJob(params);
      case "handleWebhook":
        return handleWebhook(params);
      case "handleApiRequest":
        return handleApiRequest(params);
      case "getData":
        return handleGetData(params);
      case "performAction":
        return handlePerformAction(params);
      case "executeTool":
        return handleExecuteTool(params);
      case "environmentValidateConfig":
        return handleEnvironmentValidateConfig(params);
      case "environmentProbe":
        return handleEnvironmentProbe(params);
      case "environmentAcquireLease":
        return handleEnvironmentAcquireLease(params);
      case "environmentResumeLease":
        return handleEnvironmentResumeLease(params);
      case "environmentReleaseLease":
        return handleEnvironmentReleaseLease(params);
      case "environmentDestroyLease":
        return handleEnvironmentDestroyLease(params);
      case "environmentRealizeWorkspace":
        return handleEnvironmentRealizeWorkspace(params);
      case "environmentExecute":
        return handleEnvironmentExecute(params);
      default:
        throw Object.assign(new Error(`Unknown method: ${method}`), { code: JSONRPC_ERROR_CODES.METHOD_NOT_FOUND });
    }
  }
  async function handleInitialize(params) {
    if (initialized) {
      throw new Error("Worker already initialized");
    }
    manifest = params.manifest;
    currentConfig = params.config;
    databaseNamespace = params.databaseNamespace ?? null;
    await plugin2.definition.setup(ctx);
    initialized = true;
    const supportedMethods = [];
    if (plugin2.definition.onValidateConfig)
      supportedMethods.push("validateConfig");
    if (plugin2.definition.onConfigChanged)
      supportedMethods.push("configChanged");
    if (plugin2.definition.onHealth)
      supportedMethods.push("health");
    if (plugin2.definition.onShutdown)
      supportedMethods.push("shutdown");
    if (plugin2.definition.onApiRequest)
      supportedMethods.push("handleApiRequest");
    if (plugin2.definition.onEnvironmentValidateConfig)
      supportedMethods.push("environmentValidateConfig");
    if (plugin2.definition.onEnvironmentProbe)
      supportedMethods.push("environmentProbe");
    if (plugin2.definition.onEnvironmentAcquireLease)
      supportedMethods.push("environmentAcquireLease");
    if (plugin2.definition.onEnvironmentResumeLease)
      supportedMethods.push("environmentResumeLease");
    if (plugin2.definition.onEnvironmentReleaseLease)
      supportedMethods.push("environmentReleaseLease");
    if (plugin2.definition.onEnvironmentDestroyLease)
      supportedMethods.push("environmentDestroyLease");
    if (plugin2.definition.onEnvironmentRealizeWorkspace)
      supportedMethods.push("environmentRealizeWorkspace");
    if (plugin2.definition.onEnvironmentExecute)
      supportedMethods.push("environmentExecute");
    return { ok: true, supportedMethods };
  }
  async function handleHealth() {
    if (plugin2.definition.onHealth) {
      return plugin2.definition.onHealth();
    }
    return { status: "ok" };
  }
  async function handleShutdown() {
    if (plugin2.definition.onShutdown) {
      await plugin2.definition.onShutdown();
    }
    setImmediate(() => {
      cleanup();
      if (!options.stdin && !options.stdout) {
        process.exit(0);
      }
    });
  }
  async function handleValidateConfig(params) {
    if (!plugin2.definition.onValidateConfig) {
      throw Object.assign(new Error("validateConfig is not implemented by this plugin"), { code: PLUGIN_RPC_ERROR_CODES.METHOD_NOT_IMPLEMENTED });
    }
    return plugin2.definition.onValidateConfig(params.config);
  }
  async function handleConfigChanged(params) {
    currentConfig = params.config;
    if (plugin2.definition.onConfigChanged) {
      await plugin2.definition.onConfigChanged(params.config);
    }
  }
  async function handleOnEvent(params) {
    const event = params.event;
    for (const registration of eventHandlers) {
      const exactMatch = registration.name === event.eventType;
      const wildcardPluginAll = registration.name === "plugin.*" && event.eventType.startsWith("plugin.");
      const wildcardPluginOne = registration.name.endsWith(".*") && event.eventType.startsWith(registration.name.slice(0, -1));
      if (!exactMatch && !wildcardPluginAll && !wildcardPluginOne)
        continue;
      if (registration.filter && !allowsEvent(registration.filter, event))
        continue;
      try {
        await registration.fn(event);
      } catch (err) {
        notifyHost("log", {
          level: "error",
          message: `Event handler for "${registration.name}" failed: ${err instanceof Error ? err.message : String(err)}`,
          meta: { eventType: event.eventType, stack: err instanceof Error ? err.stack : void 0 }
        });
      }
    }
  }
  async function handleRunJob(params) {
    const handler = jobHandlers.get(params.job.jobKey);
    if (!handler) {
      throw new Error(`No handler registered for job "${params.job.jobKey}"`);
    }
    await handler(params.job);
  }
  async function handleWebhook(params) {
    if (!plugin2.definition.onWebhook) {
      throw Object.assign(new Error("handleWebhook is not implemented by this plugin"), { code: PLUGIN_RPC_ERROR_CODES.METHOD_NOT_IMPLEMENTED });
    }
    await plugin2.definition.onWebhook(params);
  }
  async function handleApiRequest(params) {
    if (!plugin2.definition.onApiRequest) {
      throw Object.assign(new Error("handleApiRequest is not implemented by this plugin"), { code: PLUGIN_RPC_ERROR_CODES.METHOD_NOT_IMPLEMENTED });
    }
    return plugin2.definition.onApiRequest(params);
  }
  async function handleGetData(params) {
    const handler = dataHandlers.get(params.key);
    if (!handler) {
      throw new Error(`No data handler registered for key "${params.key}"`);
    }
    return handler(params.renderEnvironment === void 0 ? params.params : { ...params.params, renderEnvironment: params.renderEnvironment });
  }
  async function handlePerformAction(params) {
    const handler = actionHandlers.get(params.key);
    if (!handler) {
      throw new Error(`No action handler registered for key "${params.key}"`);
    }
    return handler(params.renderEnvironment === void 0 ? params.params : { ...params.params, renderEnvironment: params.renderEnvironment });
  }
  async function handleExecuteTool(params) {
    const entry = toolHandlers.get(params.toolName);
    if (!entry) {
      throw new Error(`No tool handler registered for "${params.toolName}"`);
    }
    return entry.fn(params.parameters, params.runContext);
  }
  function methodNotImplemented(method) {
    return Object.assign(new Error(`${method} is not implemented by this plugin`), { code: PLUGIN_RPC_ERROR_CODES.METHOD_NOT_IMPLEMENTED });
  }
  async function handleEnvironmentValidateConfig(params) {
    if (!plugin2.definition.onEnvironmentValidateConfig) {
      throw methodNotImplemented("environmentValidateConfig");
    }
    return plugin2.definition.onEnvironmentValidateConfig(params);
  }
  async function handleEnvironmentProbe(params) {
    if (!plugin2.definition.onEnvironmentProbe) {
      throw methodNotImplemented("environmentProbe");
    }
    return plugin2.definition.onEnvironmentProbe(params);
  }
  async function handleEnvironmentAcquireLease(params) {
    if (!plugin2.definition.onEnvironmentAcquireLease) {
      throw methodNotImplemented("environmentAcquireLease");
    }
    return plugin2.definition.onEnvironmentAcquireLease(params);
  }
  async function handleEnvironmentResumeLease(params) {
    if (!plugin2.definition.onEnvironmentResumeLease) {
      throw methodNotImplemented("environmentResumeLease");
    }
    return plugin2.definition.onEnvironmentResumeLease(params);
  }
  async function handleEnvironmentReleaseLease(params) {
    if (!plugin2.definition.onEnvironmentReleaseLease) {
      throw methodNotImplemented("environmentReleaseLease");
    }
    return plugin2.definition.onEnvironmentReleaseLease(params);
  }
  async function handleEnvironmentDestroyLease(params) {
    if (!plugin2.definition.onEnvironmentDestroyLease) {
      throw methodNotImplemented("environmentDestroyLease");
    }
    return plugin2.definition.onEnvironmentDestroyLease(params);
  }
  async function handleEnvironmentRealizeWorkspace(params) {
    if (!plugin2.definition.onEnvironmentRealizeWorkspace) {
      throw methodNotImplemented("environmentRealizeWorkspace");
    }
    return plugin2.definition.onEnvironmentRealizeWorkspace(params);
  }
  async function handleEnvironmentExecute(params) {
    if (!plugin2.definition.onEnvironmentExecute) {
      throw methodNotImplemented("environmentExecute");
    }
    return plugin2.definition.onEnvironmentExecute(params);
  }
  function allowsEvent(filter, event) {
    const payload = event.payload;
    if (filter.companyId !== void 0) {
      const companyId = event.companyId ?? String(payload?.companyId ?? "");
      if (companyId !== filter.companyId)
        return false;
    }
    if (filter.projectId !== void 0) {
      const projectId = event.entityType === "project" ? event.entityId : String(payload?.projectId ?? "");
      if (projectId !== filter.projectId)
        return false;
    }
    if (filter.agentId !== void 0) {
      const agentId = event.entityType === "agent" ? event.entityId : String(payload?.agentId ?? "");
      if (agentId !== filter.agentId)
        return false;
    }
    return true;
  }
  function handleHostResponse(response) {
    const id = response.id;
    if (id === null || id === void 0)
      return;
    const pending = pendingRequests.get(id);
    if (!pending)
      return;
    clearTimeout(pending.timer);
    pendingRequests.delete(id);
    pending.resolve(response);
  }
  function handleLine(line) {
    if (!line.trim())
      return;
    let message;
    try {
      message = parseMessage(line);
    } catch (err) {
      if (err instanceof JsonRpcParseError) {
        sendMessage(createErrorResponse(null, JSONRPC_ERROR_CODES.PARSE_ERROR, `Parse error: ${err.message}`));
      }
      return;
    }
    if (isJsonRpcResponse(message)) {
      handleHostResponse(message);
    } else if (isJsonRpcRequest(message)) {
      handleHostRequest(message).catch((err) => {
        const errorMessage = err instanceof Error ? err.message : String(err);
        const errorCode = err?.code ?? PLUGIN_RPC_ERROR_CODES.WORKER_ERROR;
        try {
          sendMessage(createErrorResponse(message.id, typeof errorCode === "number" ? errorCode : PLUGIN_RPC_ERROR_CODES.WORKER_ERROR, errorMessage));
        } catch {
        }
      });
    } else if (isJsonRpcNotification(message)) {
      const notif = message;
      if (notif.method === "agents.sessions.event" && notif.params) {
        const event = notif.params;
        const cb = sessionEventCallbacks.get(event.sessionId);
        if (cb)
          cb(event);
      } else if (notif.method === "onEvent" && notif.params) {
        handleOnEvent(notif.params).catch((err) => {
          notifyHost("log", {
            level: "error",
            message: `Failed to handle event notification: ${err instanceof Error ? err.message : String(err)}`
          });
        });
      }
    }
  }
  function cleanup() {
    running = false;
    if (readline) {
      readline.close();
      readline = null;
    }
    for (const [id, pending] of pendingRequests) {
      clearTimeout(pending.timer);
      pending.resolve(createErrorResponse(id, PLUGIN_RPC_ERROR_CODES.WORKER_UNAVAILABLE, "Worker RPC host is shutting down"));
    }
    pendingRequests.clear();
    sessionEventCallbacks.clear();
  }
  let readline = createInterface({
    input: stdinStream,
    crlfDelay: Infinity
  });
  readline.on("line", handleLine);
  readline.on("close", () => {
    if (running) {
      cleanup();
      if (!options.stdin && !options.stdout) {
        process.exit(0);
      }
    }
  });
  if (!options.stdin && !options.stdout) {
    process.on("uncaughtException", (err) => {
      notifyHost("log", {
        level: "error",
        message: `Uncaught exception: ${err.message}`,
        meta: { stack: err.stack }
      });
      setTimeout(() => process.exit(1), 100);
    });
    process.on("unhandledRejection", (reason) => {
      const message = reason instanceof Error ? reason.message : String(reason);
      const stack = reason instanceof Error ? reason.stack : void 0;
      notifyHost("log", {
        level: "error",
        message: `Unhandled rejection: ${message}`,
        meta: { stack }
      });
    });
  }
  return {
    get running() {
      return running;
    },
    stop() {
      cleanup();
    }
  };
}

// ../pla748-cad/node_modules/zod/v3/external.js
var external_exports = {};
__export(external_exports, {
  BRAND: () => BRAND,
  DIRTY: () => DIRTY,
  EMPTY_PATH: () => EMPTY_PATH,
  INVALID: () => INVALID,
  NEVER: () => NEVER,
  OK: () => OK,
  ParseStatus: () => ParseStatus,
  Schema: () => ZodType,
  ZodAny: () => ZodAny,
  ZodArray: () => ZodArray,
  ZodBigInt: () => ZodBigInt,
  ZodBoolean: () => ZodBoolean,
  ZodBranded: () => ZodBranded,
  ZodCatch: () => ZodCatch,
  ZodDate: () => ZodDate,
  ZodDefault: () => ZodDefault,
  ZodDiscriminatedUnion: () => ZodDiscriminatedUnion,
  ZodEffects: () => ZodEffects,
  ZodEnum: () => ZodEnum,
  ZodError: () => ZodError,
  ZodFirstPartyTypeKind: () => ZodFirstPartyTypeKind,
  ZodFunction: () => ZodFunction,
  ZodIntersection: () => ZodIntersection,
  ZodIssueCode: () => ZodIssueCode,
  ZodLazy: () => ZodLazy,
  ZodLiteral: () => ZodLiteral,
  ZodMap: () => ZodMap,
  ZodNaN: () => ZodNaN,
  ZodNativeEnum: () => ZodNativeEnum,
  ZodNever: () => ZodNever,
  ZodNull: () => ZodNull,
  ZodNullable: () => ZodNullable,
  ZodNumber: () => ZodNumber,
  ZodObject: () => ZodObject,
  ZodOptional: () => ZodOptional,
  ZodParsedType: () => ZodParsedType,
  ZodPipeline: () => ZodPipeline,
  ZodPromise: () => ZodPromise,
  ZodReadonly: () => ZodReadonly,
  ZodRecord: () => ZodRecord,
  ZodSchema: () => ZodType,
  ZodSet: () => ZodSet,
  ZodString: () => ZodString,
  ZodSymbol: () => ZodSymbol,
  ZodTransformer: () => ZodEffects,
  ZodTuple: () => ZodTuple,
  ZodType: () => ZodType,
  ZodUndefined: () => ZodUndefined,
  ZodUnion: () => ZodUnion,
  ZodUnknown: () => ZodUnknown,
  ZodVoid: () => ZodVoid,
  addIssueToContext: () => addIssueToContext,
  any: () => anyType,
  array: () => arrayType,
  bigint: () => bigIntType,
  boolean: () => booleanType,
  coerce: () => coerce,
  custom: () => custom,
  date: () => dateType,
  datetimeRegex: () => datetimeRegex,
  defaultErrorMap: () => en_default,
  discriminatedUnion: () => discriminatedUnionType,
  effect: () => effectsType,
  enum: () => enumType,
  function: () => functionType,
  getErrorMap: () => getErrorMap,
  getParsedType: () => getParsedType,
  instanceof: () => instanceOfType,
  intersection: () => intersectionType,
  isAborted: () => isAborted,
  isAsync: () => isAsync,
  isDirty: () => isDirty,
  isValid: () => isValid,
  late: () => late,
  lazy: () => lazyType,
  literal: () => literalType,
  makeIssue: () => makeIssue,
  map: () => mapType,
  nan: () => nanType,
  nativeEnum: () => nativeEnumType,
  never: () => neverType,
  null: () => nullType,
  nullable: () => nullableType,
  number: () => numberType,
  object: () => objectType,
  objectUtil: () => objectUtil,
  oboolean: () => oboolean,
  onumber: () => onumber,
  optional: () => optionalType,
  ostring: () => ostring,
  pipeline: () => pipelineType,
  preprocess: () => preprocessType,
  promise: () => promiseType,
  quotelessJson: () => quotelessJson,
  record: () => recordType,
  set: () => setType,
  setErrorMap: () => setErrorMap,
  strictObject: () => strictObjectType,
  string: () => stringType,
  symbol: () => symbolType,
  transformer: () => effectsType,
  tuple: () => tupleType,
  undefined: () => undefinedType,
  union: () => unionType,
  unknown: () => unknownType,
  util: () => util,
  void: () => voidType
});

// ../pla748-cad/node_modules/zod/v3/helpers/util.js
var util;
(function(util2) {
  util2.assertEqual = (_) => {
  };
  function assertIs(_arg) {
  }
  util2.assertIs = assertIs;
  function assertNever(_x) {
    throw new Error();
  }
  util2.assertNever = assertNever;
  util2.arrayToEnum = (items) => {
    const obj = {};
    for (const item of items) {
      obj[item] = item;
    }
    return obj;
  };
  util2.getValidEnumValues = (obj) => {
    const validKeys = util2.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
    const filtered = {};
    for (const k of validKeys) {
      filtered[k] = obj[k];
    }
    return util2.objectValues(filtered);
  };
  util2.objectValues = (obj) => {
    return util2.objectKeys(obj).map(function(e) {
      return obj[e];
    });
  };
  util2.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
    const keys = [];
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        keys.push(key);
      }
    }
    return keys;
  };
  util2.find = (arr, checker) => {
    for (const item of arr) {
      if (checker(item))
        return item;
    }
    return void 0;
  };
  util2.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
  function joinValues(array, separator = " | ") {
    return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
  }
  util2.joinValues = joinValues;
  util2.jsonStringifyReplacer = (_, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  };
})(util || (util = {}));
var objectUtil;
(function(objectUtil2) {
  objectUtil2.mergeShapes = (first, second) => {
    return {
      ...first,
      ...second
      // second overwrites first
    };
  };
})(objectUtil || (objectUtil = {}));
var ZodParsedType = util.arrayToEnum([
  "string",
  "nan",
  "number",
  "integer",
  "float",
  "boolean",
  "date",
  "bigint",
  "symbol",
  "function",
  "undefined",
  "null",
  "array",
  "object",
  "unknown",
  "promise",
  "void",
  "never",
  "map",
  "set"
]);
var getParsedType = (data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return ZodParsedType.undefined;
    case "string":
      return ZodParsedType.string;
    case "number":
      return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
    case "boolean":
      return ZodParsedType.boolean;
    case "function":
      return ZodParsedType.function;
    case "bigint":
      return ZodParsedType.bigint;
    case "symbol":
      return ZodParsedType.symbol;
    case "object":
      if (Array.isArray(data)) {
        return ZodParsedType.array;
      }
      if (data === null) {
        return ZodParsedType.null;
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return ZodParsedType.promise;
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return ZodParsedType.map;
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return ZodParsedType.set;
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return ZodParsedType.date;
      }
      return ZodParsedType.object;
    default:
      return ZodParsedType.unknown;
  }
};

// ../pla748-cad/node_modules/zod/v3/ZodError.js
var ZodIssueCode = util.arrayToEnum([
  "invalid_type",
  "invalid_literal",
  "custom",
  "invalid_union",
  "invalid_union_discriminator",
  "invalid_enum_value",
  "unrecognized_keys",
  "invalid_arguments",
  "invalid_return_type",
  "invalid_date",
  "invalid_string",
  "too_small",
  "too_big",
  "invalid_intersection_types",
  "not_multiple_of",
  "not_finite"
]);
var quotelessJson = (obj) => {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(/"([^"]+)":/g, "$1:");
};
var ZodError = class _ZodError extends Error {
  get errors() {
    return this.issues;
  }
  constructor(issues) {
    super();
    this.issues = [];
    this.addIssue = (sub) => {
      this.issues = [...this.issues, sub];
    };
    this.addIssues = (subs = []) => {
      this.issues = [...this.issues, ...subs];
    };
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
    this.name = "ZodError";
    this.issues = issues;
  }
  format(_mapper) {
    const mapper = _mapper || function(issue) {
      return issue.message;
    };
    const fieldErrors = { _errors: [] };
    const processError = (error) => {
      for (const issue of error.issues) {
        if (issue.code === "invalid_union") {
          issue.unionErrors.map(processError);
        } else if (issue.code === "invalid_return_type") {
          processError(issue.returnTypeError);
        } else if (issue.code === "invalid_arguments") {
          processError(issue.argumentsError);
        } else if (issue.path.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < issue.path.length) {
            const el = issue.path[i];
            const terminal = i === issue.path.length - 1;
            if (!terminal) {
              curr[el] = curr[el] || { _errors: [] };
            } else {
              curr[el] = curr[el] || { _errors: [] };
              curr[el]._errors.push(mapper(issue));
            }
            curr = curr[el];
            i++;
          }
        }
      }
    };
    processError(this);
    return fieldErrors;
  }
  static assert(value) {
    if (!(value instanceof _ZodError)) {
      throw new Error(`Not a ZodError: ${value}`);
    }
  }
  toString() {
    return this.message;
  }
  get message() {
    return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
  }
  get isEmpty() {
    return this.issues.length === 0;
  }
  flatten(mapper = (issue) => issue.message) {
    const fieldErrors = {};
    const formErrors = [];
    for (const sub of this.issues) {
      if (sub.path.length > 0) {
        const firstEl = sub.path[0];
        fieldErrors[firstEl] = fieldErrors[firstEl] || [];
        fieldErrors[firstEl].push(mapper(sub));
      } else {
        formErrors.push(mapper(sub));
      }
    }
    return { formErrors, fieldErrors };
  }
  get formErrors() {
    return this.flatten();
  }
};
ZodError.create = (issues) => {
  const error = new ZodError(issues);
  return error;
};

// ../pla748-cad/node_modules/zod/v3/locales/en.js
var errorMap = (issue, _ctx) => {
  let message;
  switch (issue.code) {
    case ZodIssueCode.invalid_type:
      if (issue.received === ZodParsedType.undefined) {
        message = "Required";
      } else {
        message = `Expected ${issue.expected}, received ${issue.received}`;
      }
      break;
    case ZodIssueCode.invalid_literal:
      message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
      break;
    case ZodIssueCode.unrecognized_keys:
      message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
      break;
    case ZodIssueCode.invalid_union:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_union_discriminator:
      message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
      break;
    case ZodIssueCode.invalid_enum_value:
      message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
      break;
    case ZodIssueCode.invalid_arguments:
      message = `Invalid function arguments`;
      break;
    case ZodIssueCode.invalid_return_type:
      message = `Invalid function return type`;
      break;
    case ZodIssueCode.invalid_date:
      message = `Invalid date`;
      break;
    case ZodIssueCode.invalid_string:
      if (typeof issue.validation === "object") {
        if ("includes" in issue.validation) {
          message = `Invalid input: must include "${issue.validation.includes}"`;
          if (typeof issue.validation.position === "number") {
            message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
          }
        } else if ("startsWith" in issue.validation) {
          message = `Invalid input: must start with "${issue.validation.startsWith}"`;
        } else if ("endsWith" in issue.validation) {
          message = `Invalid input: must end with "${issue.validation.endsWith}"`;
        } else {
          util.assertNever(issue.validation);
        }
      } else if (issue.validation !== "regex") {
        message = `Invalid ${issue.validation}`;
      } else {
        message = "Invalid";
      }
      break;
    case ZodIssueCode.too_small:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "bigint")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.too_big:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "bigint")
        message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.custom:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_intersection_types:
      message = `Intersection results could not be merged`;
      break;
    case ZodIssueCode.not_multiple_of:
      message = `Number must be a multiple of ${issue.multipleOf}`;
      break;
    case ZodIssueCode.not_finite:
      message = "Number must be finite";
      break;
    default:
      message = _ctx.defaultError;
      util.assertNever(issue);
  }
  return { message };
};
var en_default = errorMap;

// ../pla748-cad/node_modules/zod/v3/errors.js
var overrideErrorMap = en_default;
function setErrorMap(map) {
  overrideErrorMap = map;
}
function getErrorMap() {
  return overrideErrorMap;
}

// ../pla748-cad/node_modules/zod/v3/helpers/parseUtil.js
var makeIssue = (params) => {
  const { data, path: path4, errorMaps, issueData } = params;
  const fullPath = [...path4, ...issueData.path || []];
  const fullIssue = {
    ...issueData,
    path: fullPath
  };
  if (issueData.message !== void 0) {
    return {
      ...issueData,
      path: fullPath,
      message: issueData.message
    };
  }
  let errorMessage = "";
  const maps = errorMaps.filter((m) => !!m).slice().reverse();
  for (const map of maps) {
    errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
  }
  return {
    ...issueData,
    path: fullPath,
    message: errorMessage
  };
};
var EMPTY_PATH = [];
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      // contextual error map is first priority
      ctx.schemaErrorMap,
      // then schema-bound map if available
      overrideMap,
      // then global override map
      overrideMap === en_default ? void 0 : en_default
      // then global default map
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}
var ParseStatus = class _ParseStatus {
  constructor() {
    this.value = "valid";
  }
  dirty() {
    if (this.value === "valid")
      this.value = "dirty";
  }
  abort() {
    if (this.value !== "aborted")
      this.value = "aborted";
  }
  static mergeArray(status, results) {
    const arrayValue = [];
    for (const s of results) {
      if (s.status === "aborted")
        return INVALID;
      if (s.status === "dirty")
        status.dirty();
      arrayValue.push(s.value);
    }
    return { status: status.value, value: arrayValue };
  }
  static async mergeObjectAsync(status, pairs) {
    const syncPairs = [];
    for (const pair of pairs) {
      const key = await pair.key;
      const value = await pair.value;
      syncPairs.push({
        key,
        value
      });
    }
    return _ParseStatus.mergeObjectSync(status, syncPairs);
  }
  static mergeObjectSync(status, pairs) {
    const finalObject = {};
    for (const pair of pairs) {
      const { key, value } = pair;
      if (key.status === "aborted")
        return INVALID;
      if (value.status === "aborted")
        return INVALID;
      if (key.status === "dirty")
        status.dirty();
      if (value.status === "dirty")
        status.dirty();
      if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
        finalObject[key.value] = value.value;
      }
    }
    return { status: status.value, value: finalObject };
  }
};
var INVALID = Object.freeze({
  status: "aborted"
});
var DIRTY = (value) => ({ status: "dirty", value });
var OK = (value) => ({ status: "valid", value });
var isAborted = (x) => x.status === "aborted";
var isDirty = (x) => x.status === "dirty";
var isValid = (x) => x.status === "valid";
var isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;

// ../pla748-cad/node_modules/zod/v3/helpers/errorUtil.js
var errorUtil;
(function(errorUtil2) {
  errorUtil2.errToObj = (message) => typeof message === "string" ? { message } : message || {};
  errorUtil2.toString = (message) => typeof message === "string" ? message : message?.message;
})(errorUtil || (errorUtil = {}));

// ../pla748-cad/node_modules/zod/v3/types.js
var ParseInputLazyPath = class {
  constructor(parent, value, path4, key) {
    this._cachedPath = [];
    this.parent = parent;
    this.data = value;
    this._path = path4;
    this._key = key;
  }
  get path() {
    if (!this._cachedPath.length) {
      if (Array.isArray(this._key)) {
        this._cachedPath.push(...this._path, ...this._key);
      } else {
        this._cachedPath.push(...this._path, this._key);
      }
    }
    return this._cachedPath;
  }
};
var handleResult = (ctx, result) => {
  if (isValid(result)) {
    return { success: true, data: result.value };
  } else {
    if (!ctx.common.issues.length) {
      throw new Error("Validation failed but no issues detected.");
    }
    return {
      success: false,
      get error() {
        if (this._error)
          return this._error;
        const error = new ZodError(ctx.common.issues);
        this._error = error;
        return this._error;
      }
    };
  }
};
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap: errorMap2, invalid_type_error, required_error, description } = params;
  if (errorMap2 && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap2)
    return { errorMap: errorMap2, description };
  const customMap = (iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  };
  return { errorMap: customMap, description };
}
var ZodType = class {
  get description() {
    return this._def.description;
  }
  _getType(input) {
    return getParsedType(input.data);
  }
  _getOrReturnCtx(input, ctx) {
    return ctx || {
      common: input.parent.common,
      data: input.data,
      parsedType: getParsedType(input.data),
      schemaErrorMap: this._def.errorMap,
      path: input.path,
      parent: input.parent
    };
  }
  _processInputParams(input) {
    return {
      status: new ParseStatus(),
      ctx: {
        common: input.parent.common,
        data: input.data,
        parsedType: getParsedType(input.data),
        schemaErrorMap: this._def.errorMap,
        path: input.path,
        parent: input.parent
      }
    };
  }
  _parseSync(input) {
    const result = this._parse(input);
    if (isAsync(result)) {
      throw new Error("Synchronous parse encountered promise.");
    }
    return result;
  }
  _parseAsync(input) {
    const result = this._parse(input);
    return Promise.resolve(result);
  }
  parse(data, params) {
    const result = this.safeParse(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  safeParse(data, params) {
    const ctx = {
      common: {
        issues: [],
        async: params?.async ?? false,
        contextualErrorMap: params?.errorMap
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const result = this._parseSync({ data, path: ctx.path, parent: ctx });
    return handleResult(ctx, result);
  }
  "~validate"(data) {
    const ctx = {
      common: {
        issues: [],
        async: !!this["~standard"].async
      },
      path: [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    if (!this["~standard"].async) {
      try {
        const result = this._parseSync({ data, path: [], parent: ctx });
        return isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        };
      } catch (err) {
        if (err?.message?.toLowerCase()?.includes("encountered")) {
          this["~standard"].async = true;
        }
        ctx.common = {
          issues: [],
          async: true
        };
      }
    }
    return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
      value: result.value
    } : {
      issues: ctx.common.issues
    });
  }
  async parseAsync(data, params) {
    const result = await this.safeParseAsync(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  async safeParseAsync(data, params) {
    const ctx = {
      common: {
        issues: [],
        contextualErrorMap: params?.errorMap,
        async: true
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
    const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
    return handleResult(ctx, result);
  }
  refine(check, message) {
    const getIssueProperties = (val) => {
      if (typeof message === "string" || typeof message === "undefined") {
        return { message };
      } else if (typeof message === "function") {
        return message(val);
      } else {
        return message;
      }
    };
    return this._refinement((val, ctx) => {
      const result = check(val);
      const setError = () => ctx.addIssue({
        code: ZodIssueCode.custom,
        ...getIssueProperties(val)
      });
      if (typeof Promise !== "undefined" && result instanceof Promise) {
        return result.then((data) => {
          if (!data) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      if (!result) {
        setError();
        return false;
      } else {
        return true;
      }
    });
  }
  refinement(check, refinementData) {
    return this._refinement((val, ctx) => {
      if (!check(val)) {
        ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
        return false;
      } else {
        return true;
      }
    });
  }
  _refinement(refinement) {
    return new ZodEffects({
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "refinement", refinement }
    });
  }
  superRefine(refinement) {
    return this._refinement(refinement);
  }
  constructor(def) {
    this.spa = this.safeParseAsync;
    this._def = def;
    this.parse = this.parse.bind(this);
    this.safeParse = this.safeParse.bind(this);
    this.parseAsync = this.parseAsync.bind(this);
    this.safeParseAsync = this.safeParseAsync.bind(this);
    this.spa = this.spa.bind(this);
    this.refine = this.refine.bind(this);
    this.refinement = this.refinement.bind(this);
    this.superRefine = this.superRefine.bind(this);
    this.optional = this.optional.bind(this);
    this.nullable = this.nullable.bind(this);
    this.nullish = this.nullish.bind(this);
    this.array = this.array.bind(this);
    this.promise = this.promise.bind(this);
    this.or = this.or.bind(this);
    this.and = this.and.bind(this);
    this.transform = this.transform.bind(this);
    this.brand = this.brand.bind(this);
    this.default = this.default.bind(this);
    this.catch = this.catch.bind(this);
    this.describe = this.describe.bind(this);
    this.pipe = this.pipe.bind(this);
    this.readonly = this.readonly.bind(this);
    this.isNullable = this.isNullable.bind(this);
    this.isOptional = this.isOptional.bind(this);
    this["~standard"] = {
      version: 1,
      vendor: "zod",
      validate: (data) => this["~validate"](data)
    };
  }
  optional() {
    return ZodOptional.create(this, this._def);
  }
  nullable() {
    return ZodNullable.create(this, this._def);
  }
  nullish() {
    return this.nullable().optional();
  }
  array() {
    return ZodArray.create(this);
  }
  promise() {
    return ZodPromise.create(this, this._def);
  }
  or(option) {
    return ZodUnion.create([this, option], this._def);
  }
  and(incoming) {
    return ZodIntersection.create(this, incoming, this._def);
  }
  transform(transform) {
    return new ZodEffects({
      ...processCreateParams(this._def),
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "transform", transform }
    });
  }
  default(def) {
    const defaultValueFunc = typeof def === "function" ? def : () => def;
    return new ZodDefault({
      ...processCreateParams(this._def),
      innerType: this,
      defaultValue: defaultValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodDefault
    });
  }
  brand() {
    return new ZodBranded({
      typeName: ZodFirstPartyTypeKind.ZodBranded,
      type: this,
      ...processCreateParams(this._def)
    });
  }
  catch(def) {
    const catchValueFunc = typeof def === "function" ? def : () => def;
    return new ZodCatch({
      ...processCreateParams(this._def),
      innerType: this,
      catchValue: catchValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodCatch
    });
  }
  describe(description) {
    const This = this.constructor;
    return new This({
      ...this._def,
      description
    });
  }
  pipe(target) {
    return ZodPipeline.create(this, target);
  }
  readonly() {
    return ZodReadonly.create(this);
  }
  isOptional() {
    return this.safeParse(void 0).success;
  }
  isNullable() {
    return this.safeParse(null).success;
  }
};
var cuidRegex = /^c[^\s-]{8,}$/i;
var cuid2Regex = /^[0-9a-z]+$/;
var ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
var uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
var nanoidRegex = /^[a-z0-9_-]{21}$/i;
var jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
var durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
var emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
var _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
var emojiRegex;
var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
var ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
var base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
var dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
var dateRegex = new RegExp(`^${dateRegexSource}$`);
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}
var ZodString = class _ZodString extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = String(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.string) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.string,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.length < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.length > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "length") {
        const tooBig = input.data.length > check.value;
        const tooSmall = input.data.length < check.value;
        if (tooBig || tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          if (tooBig) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          } else if (tooSmall) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          }
          status.dirty();
        }
      } else if (check.kind === "email") {
        if (!emailRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "email",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "emoji") {
        if (!emojiRegex) {
          emojiRegex = new RegExp(_emojiRegex, "u");
        }
        if (!emojiRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "emoji",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "uuid") {
        if (!uuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "uuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "nanoid") {
        if (!nanoidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "nanoid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid") {
        if (!cuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid2") {
        if (!cuid2Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid2",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ulid") {
        if (!ulidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ulid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "url") {
        try {
          new URL(input.data);
        } catch {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "regex") {
        check.regex.lastIndex = 0;
        const testResult = check.regex.test(input.data);
        if (!testResult) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "regex",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "trim") {
        input.data = input.data.trim();
      } else if (check.kind === "includes") {
        if (!input.data.includes(check.value, check.position)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { includes: check.value, position: check.position },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "toLowerCase") {
        input.data = input.data.toLowerCase();
      } else if (check.kind === "toUpperCase") {
        input.data = input.data.toUpperCase();
      } else if (check.kind === "startsWith") {
        if (!input.data.startsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { startsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "endsWith") {
        if (!input.data.endsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { endsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "datetime") {
        const regex = datetimeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "datetime",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "date") {
        const regex = dateRegex;
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "date",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "time") {
        const regex = timeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "time",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "duration") {
        if (!durationRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "duration",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ip") {
        if (!isValidIP(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ip",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "jwt") {
        if (!isValidJWT(input.data, check.alg)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "jwt",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cidr") {
        if (!isValidCidr(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cidr",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64") {
        if (!base64Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64url") {
        if (!base64urlRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _regex(regex, validation, message) {
    return this.refinement((data) => regex.test(data), {
      validation,
      code: ZodIssueCode.invalid_string,
      ...errorUtil.errToObj(message)
    });
  }
  _addCheck(check) {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  email(message) {
    return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
  }
  url(message) {
    return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
  }
  emoji(message) {
    return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
  }
  uuid(message) {
    return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
  }
  nanoid(message) {
    return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
  }
  cuid(message) {
    return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
  }
  cuid2(message) {
    return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
  }
  ulid(message) {
    return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
  }
  base64(message) {
    return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
  }
  base64url(message) {
    return this._addCheck({
      kind: "base64url",
      ...errorUtil.errToObj(message)
    });
  }
  jwt(options) {
    return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
  }
  ip(options) {
    return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
  }
  cidr(options) {
    return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
  }
  datetime(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "datetime",
        precision: null,
        offset: false,
        local: false,
        message: options
      });
    }
    return this._addCheck({
      kind: "datetime",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      offset: options?.offset ?? false,
      local: options?.local ?? false,
      ...errorUtil.errToObj(options?.message)
    });
  }
  date(message) {
    return this._addCheck({ kind: "date", message });
  }
  time(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "time",
        precision: null,
        message: options
      });
    }
    return this._addCheck({
      kind: "time",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      ...errorUtil.errToObj(options?.message)
    });
  }
  duration(message) {
    return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
  }
  regex(regex, message) {
    return this._addCheck({
      kind: "regex",
      regex,
      ...errorUtil.errToObj(message)
    });
  }
  includes(value, options) {
    return this._addCheck({
      kind: "includes",
      value,
      position: options?.position,
      ...errorUtil.errToObj(options?.message)
    });
  }
  startsWith(value, message) {
    return this._addCheck({
      kind: "startsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  endsWith(value, message) {
    return this._addCheck({
      kind: "endsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  min(minLength, message) {
    return this._addCheck({
      kind: "min",
      value: minLength,
      ...errorUtil.errToObj(message)
    });
  }
  max(maxLength, message) {
    return this._addCheck({
      kind: "max",
      value: maxLength,
      ...errorUtil.errToObj(message)
    });
  }
  length(len, message) {
    return this._addCheck({
      kind: "length",
      value: len,
      ...errorUtil.errToObj(message)
    });
  }
  /**
   * Equivalent to `.min(1)`
   */
  nonempty(message) {
    return this.min(1, errorUtil.errToObj(message));
  }
  trim() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "trim" }]
    });
  }
  toLowerCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toLowerCase" }]
    });
  }
  toUpperCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toUpperCase" }]
    });
  }
  get isDatetime() {
    return !!this._def.checks.find((ch) => ch.kind === "datetime");
  }
  get isDate() {
    return !!this._def.checks.find((ch) => ch.kind === "date");
  }
  get isTime() {
    return !!this._def.checks.find((ch) => ch.kind === "time");
  }
  get isDuration() {
    return !!this._def.checks.find((ch) => ch.kind === "duration");
  }
  get isEmail() {
    return !!this._def.checks.find((ch) => ch.kind === "email");
  }
  get isURL() {
    return !!this._def.checks.find((ch) => ch.kind === "url");
  }
  get isEmoji() {
    return !!this._def.checks.find((ch) => ch.kind === "emoji");
  }
  get isUUID() {
    return !!this._def.checks.find((ch) => ch.kind === "uuid");
  }
  get isNANOID() {
    return !!this._def.checks.find((ch) => ch.kind === "nanoid");
  }
  get isCUID() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid");
  }
  get isCUID2() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid2");
  }
  get isULID() {
    return !!this._def.checks.find((ch) => ch.kind === "ulid");
  }
  get isIP() {
    return !!this._def.checks.find((ch) => ch.kind === "ip");
  }
  get isCIDR() {
    return !!this._def.checks.find((ch) => ch.kind === "cidr");
  }
  get isBase64() {
    return !!this._def.checks.find((ch) => ch.kind === "base64");
  }
  get isBase64url() {
    return !!this._def.checks.find((ch) => ch.kind === "base64url");
  }
  get minLength() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxLength() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodString.create = (params) => {
  return new ZodString({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodString,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
var ZodNumber = class _ZodNumber extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
    this.step = this.multipleOf;
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Number(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.number) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.number,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "int") {
        if (!util.isInteger(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: "integer",
            received: "float",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (floatSafeRemainder(input.data, check.value) !== 0) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "finite") {
        if (!Number.isFinite(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_finite,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodNumber({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodNumber({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  int(message) {
    return this._addCheck({
      kind: "int",
      message: errorUtil.toString(message)
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  finite(message) {
    return this._addCheck({
      kind: "finite",
      message: errorUtil.toString(message)
    });
  }
  safe(message) {
    return this._addCheck({
      kind: "min",
      inclusive: true,
      value: Number.MIN_SAFE_INTEGER,
      message: errorUtil.toString(message)
    })._addCheck({
      kind: "max",
      inclusive: true,
      value: Number.MAX_SAFE_INTEGER,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
  get isInt() {
    return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
  }
  get isFinite() {
    let max = null;
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
        return true;
      } else if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      } else if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return Number.isFinite(min) && Number.isFinite(max);
  }
};
ZodNumber.create = (params) => {
  return new ZodNumber({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodNumber,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodBigInt = class _ZodBigInt extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
  }
  _parse(input) {
    if (this._def.coerce) {
      try {
        input.data = BigInt(input.data);
      } catch {
        return this._getInvalidInput(input);
      }
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.bigint) {
      return this._getInvalidInput(input);
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            type: "bigint",
            minimum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            type: "bigint",
            maximum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (input.data % check.value !== BigInt(0)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _getInvalidInput(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.bigint,
      received: ctx.parsedType
    });
    return INVALID;
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodBigInt({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodBigInt({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodBigInt.create = (params) => {
  return new ZodBigInt({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodBigInt,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
var ZodBoolean = class extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = Boolean(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.boolean) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.boolean,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodBoolean.create = (params) => {
  return new ZodBoolean({
    typeName: ZodFirstPartyTypeKind.ZodBoolean,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodDate = class _ZodDate extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = new Date(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.date) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.date,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    if (Number.isNaN(input.data.getTime())) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_date
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.getTime() < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            message: check.message,
            inclusive: true,
            exact: false,
            minimum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.getTime() > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            message: check.message,
            inclusive: true,
            exact: false,
            maximum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return {
      status: status.value,
      value: new Date(input.data.getTime())
    };
  }
  _addCheck(check) {
    return new _ZodDate({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  min(minDate, message) {
    return this._addCheck({
      kind: "min",
      value: minDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  max(maxDate, message) {
    return this._addCheck({
      kind: "max",
      value: maxDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  get minDate() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min != null ? new Date(min) : null;
  }
  get maxDate() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max != null ? new Date(max) : null;
  }
};
ZodDate.create = (params) => {
  return new ZodDate({
    checks: [],
    coerce: params?.coerce || false,
    typeName: ZodFirstPartyTypeKind.ZodDate,
    ...processCreateParams(params)
  });
};
var ZodSymbol = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.symbol) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.symbol,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodSymbol.create = (params) => {
  return new ZodSymbol({
    typeName: ZodFirstPartyTypeKind.ZodSymbol,
    ...processCreateParams(params)
  });
};
var ZodUndefined = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.undefined,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodUndefined.create = (params) => {
  return new ZodUndefined({
    typeName: ZodFirstPartyTypeKind.ZodUndefined,
    ...processCreateParams(params)
  });
};
var ZodNull = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.null) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.null,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodNull.create = (params) => {
  return new ZodNull({
    typeName: ZodFirstPartyTypeKind.ZodNull,
    ...processCreateParams(params)
  });
};
var ZodAny = class extends ZodType {
  constructor() {
    super(...arguments);
    this._any = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodAny.create = (params) => {
  return new ZodAny({
    typeName: ZodFirstPartyTypeKind.ZodAny,
    ...processCreateParams(params)
  });
};
var ZodUnknown = class extends ZodType {
  constructor() {
    super(...arguments);
    this._unknown = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodUnknown.create = (params) => {
  return new ZodUnknown({
    typeName: ZodFirstPartyTypeKind.ZodUnknown,
    ...processCreateParams(params)
  });
};
var ZodNever = class extends ZodType {
  _parse(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.never,
      received: ctx.parsedType
    });
    return INVALID;
  }
};
ZodNever.create = (params) => {
  return new ZodNever({
    typeName: ZodFirstPartyTypeKind.ZodNever,
    ...processCreateParams(params)
  });
};
var ZodVoid = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.void,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodVoid.create = (params) => {
  return new ZodVoid({
    typeName: ZodFirstPartyTypeKind.ZodVoid,
    ...processCreateParams(params)
  });
};
var ZodArray = class _ZodArray extends ZodType {
  _parse(input) {
    const { ctx, status } = this._processInputParams(input);
    const def = this._def;
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (def.exactLength !== null) {
      const tooBig = ctx.data.length > def.exactLength.value;
      const tooSmall = ctx.data.length < def.exactLength.value;
      if (tooBig || tooSmall) {
        addIssueToContext(ctx, {
          code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
          minimum: tooSmall ? def.exactLength.value : void 0,
          maximum: tooBig ? def.exactLength.value : void 0,
          type: "array",
          inclusive: true,
          exact: true,
          message: def.exactLength.message
        });
        status.dirty();
      }
    }
    if (def.minLength !== null) {
      if (ctx.data.length < def.minLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.minLength.message
        });
        status.dirty();
      }
    }
    if (def.maxLength !== null) {
      if (ctx.data.length > def.maxLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.maxLength.message
        });
        status.dirty();
      }
    }
    if (ctx.common.async) {
      return Promise.all([...ctx.data].map((item, i) => {
        return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
      })).then((result2) => {
        return ParseStatus.mergeArray(status, result2);
      });
    }
    const result = [...ctx.data].map((item, i) => {
      return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
    });
    return ParseStatus.mergeArray(status, result);
  }
  get element() {
    return this._def.type;
  }
  min(minLength, message) {
    return new _ZodArray({
      ...this._def,
      minLength: { value: minLength, message: errorUtil.toString(message) }
    });
  }
  max(maxLength, message) {
    return new _ZodArray({
      ...this._def,
      maxLength: { value: maxLength, message: errorUtil.toString(message) }
    });
  }
  length(len, message) {
    return new _ZodArray({
      ...this._def,
      exactLength: { value: len, message: errorUtil.toString(message) }
    });
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodArray.create = (schema, params) => {
  return new ZodArray({
    type: schema,
    minLength: null,
    maxLength: null,
    exactLength: null,
    typeName: ZodFirstPartyTypeKind.ZodArray,
    ...processCreateParams(params)
  });
};
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: () => newShape
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}
var ZodObject = class _ZodObject extends ZodType {
  constructor() {
    super(...arguments);
    this._cached = null;
    this.nonstrict = this.passthrough;
    this.augment = this.extend;
  }
  _getCached() {
    if (this._cached !== null)
      return this._cached;
    const shape = this._def.shape();
    const keys = util.objectKeys(shape);
    this._cached = { shape, keys };
    return this._cached;
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.object) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const { status, ctx } = this._processInputParams(input);
    const { shape, keys: shapeKeys } = this._getCached();
    const extraKeys = [];
    if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
      for (const key in ctx.data) {
        if (!shapeKeys.includes(key)) {
          extraKeys.push(key);
        }
      }
    }
    const pairs = [];
    for (const key of shapeKeys) {
      const keyValidator = shape[key];
      const value = ctx.data[key];
      pairs.push({
        key: { status: "valid", value: key },
        value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (this._def.catchall instanceof ZodNever) {
      const unknownKeys = this._def.unknownKeys;
      if (unknownKeys === "passthrough") {
        for (const key of extraKeys) {
          pairs.push({
            key: { status: "valid", value: key },
            value: { status: "valid", value: ctx.data[key] }
          });
        }
      } else if (unknownKeys === "strict") {
        if (extraKeys.length > 0) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.unrecognized_keys,
            keys: extraKeys
          });
          status.dirty();
        }
      } else if (unknownKeys === "strip") {
      } else {
        throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
      }
    } else {
      const catchall = this._def.catchall;
      for (const key of extraKeys) {
        const value = ctx.data[key];
        pairs.push({
          key: { status: "valid", value: key },
          value: catchall._parse(
            new ParseInputLazyPath(ctx, value, ctx.path, key)
            //, ctx.child(key), value, getParsedType(value)
          ),
          alwaysSet: key in ctx.data
        });
      }
    }
    if (ctx.common.async) {
      return Promise.resolve().then(async () => {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value,
            alwaysSet: pair.alwaysSet
          });
        }
        return syncPairs;
      }).then((syncPairs) => {
        return ParseStatus.mergeObjectSync(status, syncPairs);
      });
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get shape() {
    return this._def.shape();
  }
  strict(message) {
    errorUtil.errToObj;
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strict",
      ...message !== void 0 ? {
        errorMap: (issue, ctx) => {
          const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
          if (issue.code === "unrecognized_keys")
            return {
              message: errorUtil.errToObj(message).message ?? defaultError
            };
          return {
            message: defaultError
          };
        }
      } : {}
    });
  }
  strip() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strip"
    });
  }
  passthrough() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "passthrough"
    });
  }
  // const AugmentFactory =
  //   <Def extends ZodObjectDef>(def: Def) =>
  //   <Augmentation extends ZodRawShape>(
  //     augmentation: Augmentation
  //   ): ZodObject<
  //     extendShape<ReturnType<Def["shape"]>, Augmentation>,
  //     Def["unknownKeys"],
  //     Def["catchall"]
  //   > => {
  //     return new ZodObject({
  //       ...def,
  //       shape: () => ({
  //         ...def.shape(),
  //         ...augmentation,
  //       }),
  //     }) as any;
  //   };
  extend(augmentation) {
    return new _ZodObject({
      ...this._def,
      shape: () => ({
        ...this._def.shape(),
        ...augmentation
      })
    });
  }
  /**
   * Prior to zod@1.0.12 there was a bug in the
   * inferred type of merged objects. Please
   * upgrade if you are experiencing issues.
   */
  merge(merging) {
    const merged = new _ZodObject({
      unknownKeys: merging._def.unknownKeys,
      catchall: merging._def.catchall,
      shape: () => ({
        ...this._def.shape(),
        ...merging._def.shape()
      }),
      typeName: ZodFirstPartyTypeKind.ZodObject
    });
    return merged;
  }
  // merge<
  //   Incoming extends AnyZodObject,
  //   Augmentation extends Incoming["shape"],
  //   NewOutput extends {
  //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
  //       ? Augmentation[k]["_output"]
  //       : k extends keyof Output
  //       ? Output[k]
  //       : never;
  //   },
  //   NewInput extends {
  //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
  //       ? Augmentation[k]["_input"]
  //       : k extends keyof Input
  //       ? Input[k]
  //       : never;
  //   }
  // >(
  //   merging: Incoming
  // ): ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"],
  //   NewOutput,
  //   NewInput
  // > {
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  setKey(key, schema) {
    return this.augment({ [key]: schema });
  }
  // merge<Incoming extends AnyZodObject>(
  //   merging: Incoming
  // ): //ZodObject<T & Incoming["_shape"], UnknownKeys, Catchall> = (merging) => {
  // ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"]
  // > {
  //   // const mergedShape = objectUtil.mergeShapes(
  //   //   this._def.shape(),
  //   //   merging._def.shape()
  //   // );
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  catchall(index) {
    return new _ZodObject({
      ...this._def,
      catchall: index
    });
  }
  pick(mask) {
    const shape = {};
    for (const key of util.objectKeys(mask)) {
      if (mask[key] && this.shape[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  omit(mask) {
    const shape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (!mask[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  /**
   * @deprecated
   */
  deepPartial() {
    return deepPartialify(this);
  }
  partial(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      const fieldSchema = this.shape[key];
      if (mask && !mask[key]) {
        newShape[key] = fieldSchema;
      } else {
        newShape[key] = fieldSchema.optional();
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  required(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (mask && !mask[key]) {
        newShape[key] = this.shape[key];
      } else {
        const fieldSchema = this.shape[key];
        let newField = fieldSchema;
        while (newField instanceof ZodOptional) {
          newField = newField._def.innerType;
        }
        newShape[key] = newField;
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  keyof() {
    return createZodEnum(util.objectKeys(this.shape));
  }
};
ZodObject.create = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.strictCreate = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strict",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.lazycreate = (shape, params) => {
  return new ZodObject({
    shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
var ZodUnion = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const options = this._def.options;
    function handleResults(results) {
      for (const result of results) {
        if (result.result.status === "valid") {
          return result.result;
        }
      }
      for (const result of results) {
        if (result.result.status === "dirty") {
          ctx.common.issues.push(...result.ctx.common.issues);
          return result.result;
        }
      }
      const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return Promise.all(options.map(async (option) => {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        return {
          result: await option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: childCtx
          }),
          ctx: childCtx
        };
      })).then(handleResults);
    } else {
      let dirty = void 0;
      const issues = [];
      for (const option of options) {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        const result = option._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: childCtx
        });
        if (result.status === "valid") {
          return result;
        } else if (result.status === "dirty" && !dirty) {
          dirty = { result, ctx: childCtx };
        }
        if (childCtx.common.issues.length) {
          issues.push(childCtx.common.issues);
        }
      }
      if (dirty) {
        ctx.common.issues.push(...dirty.ctx.common.issues);
        return dirty.result;
      }
      const unionErrors = issues.map((issues2) => new ZodError(issues2));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
  }
  get options() {
    return this._def.options;
  }
};
ZodUnion.create = (types, params) => {
  return new ZodUnion({
    options: types,
    typeName: ZodFirstPartyTypeKind.ZodUnion,
    ...processCreateParams(params)
  });
};
var getDiscriminator = (type) => {
  if (type instanceof ZodLazy) {
    return getDiscriminator(type.schema);
  } else if (type instanceof ZodEffects) {
    return getDiscriminator(type.innerType());
  } else if (type instanceof ZodLiteral) {
    return [type.value];
  } else if (type instanceof ZodEnum) {
    return type.options;
  } else if (type instanceof ZodNativeEnum) {
    return util.objectValues(type.enum);
  } else if (type instanceof ZodDefault) {
    return getDiscriminator(type._def.innerType);
  } else if (type instanceof ZodUndefined) {
    return [void 0];
  } else if (type instanceof ZodNull) {
    return [null];
  } else if (type instanceof ZodOptional) {
    return [void 0, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodNullable) {
    return [null, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodBranded) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodReadonly) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodCatch) {
    return getDiscriminator(type._def.innerType);
  } else {
    return [];
  }
};
var ZodDiscriminatedUnion = class _ZodDiscriminatedUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const discriminator = this.discriminator;
    const discriminatorValue = ctx.data[discriminator];
    const option = this.optionsMap.get(discriminatorValue);
    if (!option) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union_discriminator,
        options: Array.from(this.optionsMap.keys()),
        path: [discriminator]
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return option._parseAsync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    } else {
      return option._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    }
  }
  get discriminator() {
    return this._def.discriminator;
  }
  get options() {
    return this._def.options;
  }
  get optionsMap() {
    return this._def.optionsMap;
  }
  /**
   * The constructor of the discriminated union schema. Its behaviour is very similar to that of the normal z.union() constructor.
   * However, it only allows a union of objects, all of which need to share a discriminator property. This property must
   * have a different value for each object in the union.
   * @param discriminator the name of the discriminator property
   * @param types an array of object schemas
   * @param params
   */
  static create(discriminator, options, params) {
    const optionsMap = /* @__PURE__ */ new Map();
    for (const type of options) {
      const discriminatorValues = getDiscriminator(type.shape[discriminator]);
      if (!discriminatorValues.length) {
        throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
      }
      for (const value of discriminatorValues) {
        if (optionsMap.has(value)) {
          throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
        }
        optionsMap.set(value, type);
      }
    }
    return new _ZodDiscriminatedUnion({
      typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
      discriminator,
      options,
      optionsMap,
      ...processCreateParams(params)
    });
  }
};
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0; index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}
var ZodIntersection = class extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const handleParsed = (parsedLeft, parsedRight) => {
      if (isAborted(parsedLeft) || isAborted(parsedRight)) {
        return INVALID;
      }
      const merged = mergeValues(parsedLeft.value, parsedRight.value);
      if (!merged.valid) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_intersection_types
        });
        return INVALID;
      }
      if (isDirty(parsedLeft) || isDirty(parsedRight)) {
        status.dirty();
      }
      return { status: status.value, value: merged.data };
    };
    if (ctx.common.async) {
      return Promise.all([
        this._def.left._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        }),
        this._def.right._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        })
      ]).then(([left, right]) => handleParsed(left, right));
    } else {
      return handleParsed(this._def.left._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }), this._def.right._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }));
    }
  }
};
ZodIntersection.create = (left, right, params) => {
  return new ZodIntersection({
    left,
    right,
    typeName: ZodFirstPartyTypeKind.ZodIntersection,
    ...processCreateParams(params)
  });
};
var ZodTuple = class _ZodTuple extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (ctx.data.length < this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_small,
        minimum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      return INVALID;
    }
    const rest = this._def.rest;
    if (!rest && ctx.data.length > this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_big,
        maximum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      status.dirty();
    }
    const items = [...ctx.data].map((item, itemIndex) => {
      const schema = this._def.items[itemIndex] || this._def.rest;
      if (!schema)
        return null;
      return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
    }).filter((x) => !!x);
    if (ctx.common.async) {
      return Promise.all(items).then((results) => {
        return ParseStatus.mergeArray(status, results);
      });
    } else {
      return ParseStatus.mergeArray(status, items);
    }
  }
  get items() {
    return this._def.items;
  }
  rest(rest) {
    return new _ZodTuple({
      ...this._def,
      rest
    });
  }
};
ZodTuple.create = (schemas, params) => {
  if (!Array.isArray(schemas)) {
    throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
  }
  return new ZodTuple({
    items: schemas,
    typeName: ZodFirstPartyTypeKind.ZodTuple,
    rest: null,
    ...processCreateParams(params)
  });
};
var ZodRecord = class _ZodRecord extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const pairs = [];
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    for (const key in ctx.data) {
      pairs.push({
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
        value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (ctx.common.async) {
      return ParseStatus.mergeObjectAsync(status, pairs);
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get element() {
    return this._def.valueType;
  }
  static create(first, second, third) {
    if (second instanceof ZodType) {
      return new _ZodRecord({
        keyType: first,
        valueType: second,
        typeName: ZodFirstPartyTypeKind.ZodRecord,
        ...processCreateParams(third)
      });
    }
    return new _ZodRecord({
      keyType: ZodString.create(),
      valueType: first,
      typeName: ZodFirstPartyTypeKind.ZodRecord,
      ...processCreateParams(second)
    });
  }
};
var ZodMap = class extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.map) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.map,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    const pairs = [...ctx.data.entries()].map(([key, value], index) => {
      return {
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
        value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
      };
    });
    if (ctx.common.async) {
      const finalMap = /* @__PURE__ */ new Map();
      return Promise.resolve().then(async () => {
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          if (key.status === "aborted" || value.status === "aborted") {
            return INVALID;
          }
          if (key.status === "dirty" || value.status === "dirty") {
            status.dirty();
          }
          finalMap.set(key.value, value.value);
        }
        return { status: status.value, value: finalMap };
      });
    } else {
      const finalMap = /* @__PURE__ */ new Map();
      for (const pair of pairs) {
        const key = pair.key;
        const value = pair.value;
        if (key.status === "aborted" || value.status === "aborted") {
          return INVALID;
        }
        if (key.status === "dirty" || value.status === "dirty") {
          status.dirty();
        }
        finalMap.set(key.value, value.value);
      }
      return { status: status.value, value: finalMap };
    }
  }
};
ZodMap.create = (keyType, valueType, params) => {
  return new ZodMap({
    valueType,
    keyType,
    typeName: ZodFirstPartyTypeKind.ZodMap,
    ...processCreateParams(params)
  });
};
var ZodSet = class _ZodSet extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.set) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.set,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const def = this._def;
    if (def.minSize !== null) {
      if (ctx.data.size < def.minSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.minSize.message
        });
        status.dirty();
      }
    }
    if (def.maxSize !== null) {
      if (ctx.data.size > def.maxSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.maxSize.message
        });
        status.dirty();
      }
    }
    const valueType = this._def.valueType;
    function finalizeSet(elements2) {
      const parsedSet = /* @__PURE__ */ new Set();
      for (const element of elements2) {
        if (element.status === "aborted")
          return INVALID;
        if (element.status === "dirty")
          status.dirty();
        parsedSet.add(element.value);
      }
      return { status: status.value, value: parsedSet };
    }
    const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
    if (ctx.common.async) {
      return Promise.all(elements).then((elements2) => finalizeSet(elements2));
    } else {
      return finalizeSet(elements);
    }
  }
  min(minSize, message) {
    return new _ZodSet({
      ...this._def,
      minSize: { value: minSize, message: errorUtil.toString(message) }
    });
  }
  max(maxSize, message) {
    return new _ZodSet({
      ...this._def,
      maxSize: { value: maxSize, message: errorUtil.toString(message) }
    });
  }
  size(size, message) {
    return this.min(size, message).max(size, message);
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodSet.create = (valueType, params) => {
  return new ZodSet({
    valueType,
    minSize: null,
    maxSize: null,
    typeName: ZodFirstPartyTypeKind.ZodSet,
    ...processCreateParams(params)
  });
};
var ZodFunction = class _ZodFunction extends ZodType {
  constructor() {
    super(...arguments);
    this.validate = this.implement;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.function) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.function,
        received: ctx.parsedType
      });
      return INVALID;
    }
    function makeArgsIssue(args, error) {
      return makeIssue({
        data: args,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_arguments,
          argumentsError: error
        }
      });
    }
    function makeReturnsIssue(returns, error) {
      return makeIssue({
        data: returns,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_return_type,
          returnTypeError: error
        }
      });
    }
    const params = { errorMap: ctx.common.contextualErrorMap };
    const fn = ctx.data;
    if (this._def.returns instanceof ZodPromise) {
      const me = this;
      return OK(async function(...args) {
        const error = new ZodError([]);
        const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
          error.addIssue(makeArgsIssue(args, e));
          throw error;
        });
        const result = await Reflect.apply(fn, this, parsedArgs);
        const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
          error.addIssue(makeReturnsIssue(result, e));
          throw error;
        });
        return parsedReturns;
      });
    } else {
      const me = this;
      return OK(function(...args) {
        const parsedArgs = me._def.args.safeParse(args, params);
        if (!parsedArgs.success) {
          throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
        }
        const result = Reflect.apply(fn, this, parsedArgs.data);
        const parsedReturns = me._def.returns.safeParse(result, params);
        if (!parsedReturns.success) {
          throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
        }
        return parsedReturns.data;
      });
    }
  }
  parameters() {
    return this._def.args;
  }
  returnType() {
    return this._def.returns;
  }
  args(...items) {
    return new _ZodFunction({
      ...this._def,
      args: ZodTuple.create(items).rest(ZodUnknown.create())
    });
  }
  returns(returnType) {
    return new _ZodFunction({
      ...this._def,
      returns: returnType
    });
  }
  implement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  strictImplement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  static create(args, returns, params) {
    return new _ZodFunction({
      args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
      returns: returns || ZodUnknown.create(),
      typeName: ZodFirstPartyTypeKind.ZodFunction,
      ...processCreateParams(params)
    });
  }
};
var ZodLazy = class extends ZodType {
  get schema() {
    return this._def.getter();
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const lazySchema = this._def.getter();
    return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
  }
};
ZodLazy.create = (getter, params) => {
  return new ZodLazy({
    getter,
    typeName: ZodFirstPartyTypeKind.ZodLazy,
    ...processCreateParams(params)
  });
};
var ZodLiteral = class extends ZodType {
  _parse(input) {
    if (input.data !== this._def.value) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_literal,
        expected: this._def.value
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
  get value() {
    return this._def.value;
  }
};
ZodLiteral.create = (value, params) => {
  return new ZodLiteral({
    value,
    typeName: ZodFirstPartyTypeKind.ZodLiteral,
    ...processCreateParams(params)
  });
};
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}
var ZodEnum = class _ZodEnum extends ZodType {
  _parse(input) {
    if (typeof input.data !== "string") {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(this._def.values);
    }
    if (!this._cache.has(input.data)) {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get options() {
    return this._def.values;
  }
  get enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Values() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  extract(values, newDef = this._def) {
    return _ZodEnum.create(values, {
      ...this._def,
      ...newDef
    });
  }
  exclude(values, newDef = this._def) {
    return _ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
      ...this._def,
      ...newDef
    });
  }
};
ZodEnum.create = createZodEnum;
var ZodNativeEnum = class extends ZodType {
  _parse(input) {
    const nativeEnumValues = util.getValidEnumValues(this._def.values);
    const ctx = this._getOrReturnCtx(input);
    if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(util.getValidEnumValues(this._def.values));
    }
    if (!this._cache.has(input.data)) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get enum() {
    return this._def.values;
  }
};
ZodNativeEnum.create = (values, params) => {
  return new ZodNativeEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
    ...processCreateParams(params)
  });
};
var ZodPromise = class extends ZodType {
  unwrap() {
    return this._def.type;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.promise,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
    return OK(promisified.then((data) => {
      return this._def.type.parseAsync(data, {
        path: ctx.path,
        errorMap: ctx.common.contextualErrorMap
      });
    }));
  }
};
ZodPromise.create = (schema, params) => {
  return new ZodPromise({
    type: schema,
    typeName: ZodFirstPartyTypeKind.ZodPromise,
    ...processCreateParams(params)
  });
};
var ZodEffects = class extends ZodType {
  innerType() {
    return this._def.schema;
  }
  sourceType() {
    return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const effect = this._def.effect || null;
    const checkCtx = {
      addIssue: (arg) => {
        addIssueToContext(ctx, arg);
        if (arg.fatal) {
          status.abort();
        } else {
          status.dirty();
        }
      },
      get path() {
        return ctx.path;
      }
    };
    checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
    if (effect.type === "preprocess") {
      const processed = effect.transform(ctx.data, checkCtx);
      if (ctx.common.async) {
        return Promise.resolve(processed).then(async (processed2) => {
          if (status.value === "aborted")
            return INVALID;
          const result = await this._def.schema._parseAsync({
            data: processed2,
            path: ctx.path,
            parent: ctx
          });
          if (result.status === "aborted")
            return INVALID;
          if (result.status === "dirty")
            return DIRTY(result.value);
          if (status.value === "dirty")
            return DIRTY(result.value);
          return result;
        });
      } else {
        if (status.value === "aborted")
          return INVALID;
        const result = this._def.schema._parseSync({
          data: processed,
          path: ctx.path,
          parent: ctx
        });
        if (result.status === "aborted")
          return INVALID;
        if (result.status === "dirty")
          return DIRTY(result.value);
        if (status.value === "dirty")
          return DIRTY(result.value);
        return result;
      }
    }
    if (effect.type === "refinement") {
      const executeRefinement = (acc) => {
        const result = effect.refinement(acc, checkCtx);
        if (ctx.common.async) {
          return Promise.resolve(result);
        }
        if (result instanceof Promise) {
          throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
        }
        return acc;
      };
      if (ctx.common.async === false) {
        const inner = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inner.status === "aborted")
          return INVALID;
        if (inner.status === "dirty")
          status.dirty();
        executeRefinement(inner.value);
        return { status: status.value, value: inner.value };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
          if (inner.status === "aborted")
            return INVALID;
          if (inner.status === "dirty")
            status.dirty();
          return executeRefinement(inner.value).then(() => {
            return { status: status.value, value: inner.value };
          });
        });
      }
    }
    if (effect.type === "transform") {
      if (ctx.common.async === false) {
        const base = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (!isValid(base))
          return INVALID;
        const result = effect.transform(base.value, checkCtx);
        if (result instanceof Promise) {
          throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
        }
        return { status: status.value, value: result };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
          if (!isValid(base))
            return INVALID;
          return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
            status: status.value,
            value: result
          }));
        });
      }
    }
    util.assertNever(effect);
  }
};
ZodEffects.create = (schema, effect, params) => {
  return new ZodEffects({
    schema,
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    effect,
    ...processCreateParams(params)
  });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
  return new ZodEffects({
    schema,
    effect: { type: "preprocess", transform: preprocess },
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    ...processCreateParams(params)
  });
};
var ZodOptional = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.undefined) {
      return OK(void 0);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodOptional.create = (type, params) => {
  return new ZodOptional({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodOptional,
    ...processCreateParams(params)
  });
};
var ZodNullable = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.null) {
      return OK(null);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodNullable.create = (type, params) => {
  return new ZodNullable({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodNullable,
    ...processCreateParams(params)
  });
};
var ZodDefault = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    let data = ctx.data;
    if (ctx.parsedType === ZodParsedType.undefined) {
      data = this._def.defaultValue();
    }
    return this._def.innerType._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  removeDefault() {
    return this._def.innerType;
  }
};
ZodDefault.create = (type, params) => {
  return new ZodDefault({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodDefault,
    defaultValue: typeof params.default === "function" ? params.default : () => params.default,
    ...processCreateParams(params)
  });
};
var ZodCatch = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const newCtx = {
      ...ctx,
      common: {
        ...ctx.common,
        issues: []
      }
    };
    const result = this._def.innerType._parse({
      data: newCtx.data,
      path: newCtx.path,
      parent: {
        ...newCtx
      }
    });
    if (isAsync(result)) {
      return result.then((result2) => {
        return {
          status: "valid",
          value: result2.status === "valid" ? result2.value : this._def.catchValue({
            get error() {
              return new ZodError(newCtx.common.issues);
            },
            input: newCtx.data
          })
        };
      });
    } else {
      return {
        status: "valid",
        value: result.status === "valid" ? result.value : this._def.catchValue({
          get error() {
            return new ZodError(newCtx.common.issues);
          },
          input: newCtx.data
        })
      };
    }
  }
  removeCatch() {
    return this._def.innerType;
  }
};
ZodCatch.create = (type, params) => {
  return new ZodCatch({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodCatch,
    catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
    ...processCreateParams(params)
  });
};
var ZodNaN = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.nan) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.nan,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
};
ZodNaN.create = (params) => {
  return new ZodNaN({
    typeName: ZodFirstPartyTypeKind.ZodNaN,
    ...processCreateParams(params)
  });
};
var BRAND = /* @__PURE__ */ Symbol("zod_brand");
var ZodBranded = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const data = ctx.data;
    return this._def.type._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  unwrap() {
    return this._def.type;
  }
};
var ZodPipeline = class _ZodPipeline extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.common.async) {
      const handleAsync = async () => {
        const inResult = await this._def.in._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inResult.status === "aborted")
          return INVALID;
        if (inResult.status === "dirty") {
          status.dirty();
          return DIRTY(inResult.value);
        } else {
          return this._def.out._parseAsync({
            data: inResult.value,
            path: ctx.path,
            parent: ctx
          });
        }
      };
      return handleAsync();
    } else {
      const inResult = this._def.in._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
      if (inResult.status === "aborted")
        return INVALID;
      if (inResult.status === "dirty") {
        status.dirty();
        return {
          status: "dirty",
          value: inResult.value
        };
      } else {
        return this._def.out._parseSync({
          data: inResult.value,
          path: ctx.path,
          parent: ctx
        });
      }
    }
  }
  static create(a, b) {
    return new _ZodPipeline({
      in: a,
      out: b,
      typeName: ZodFirstPartyTypeKind.ZodPipeline
    });
  }
};
var ZodReadonly = class extends ZodType {
  _parse(input) {
    const result = this._def.innerType._parse(input);
    const freeze = (data) => {
      if (isValid(data)) {
        data.value = Object.freeze(data.value);
      }
      return data;
    };
    return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodReadonly.create = (type, params) => {
  return new ZodReadonly({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodReadonly,
    ...processCreateParams(params)
  });
};
function cleanParams(params, data) {
  const p = typeof params === "function" ? params(data) : typeof params === "string" ? { message: params } : params;
  const p2 = typeof p === "string" ? { message: p } : p;
  return p2;
}
function custom(check, _params = {}, fatal) {
  if (check)
    return ZodAny.create().superRefine((data, ctx) => {
      const r = check(data);
      if (r instanceof Promise) {
        return r.then((r2) => {
          if (!r2) {
            const params = cleanParams(_params, data);
            const _fatal = params.fatal ?? fatal ?? true;
            ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
          }
        });
      }
      if (!r) {
        const params = cleanParams(_params, data);
        const _fatal = params.fatal ?? fatal ?? true;
        ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
      }
      return;
    });
  return ZodAny.create();
}
var late = {
  object: ZodObject.lazycreate
};
var ZodFirstPartyTypeKind;
(function(ZodFirstPartyTypeKind2) {
  ZodFirstPartyTypeKind2["ZodString"] = "ZodString";
  ZodFirstPartyTypeKind2["ZodNumber"] = "ZodNumber";
  ZodFirstPartyTypeKind2["ZodNaN"] = "ZodNaN";
  ZodFirstPartyTypeKind2["ZodBigInt"] = "ZodBigInt";
  ZodFirstPartyTypeKind2["ZodBoolean"] = "ZodBoolean";
  ZodFirstPartyTypeKind2["ZodDate"] = "ZodDate";
  ZodFirstPartyTypeKind2["ZodSymbol"] = "ZodSymbol";
  ZodFirstPartyTypeKind2["ZodUndefined"] = "ZodUndefined";
  ZodFirstPartyTypeKind2["ZodNull"] = "ZodNull";
  ZodFirstPartyTypeKind2["ZodAny"] = "ZodAny";
  ZodFirstPartyTypeKind2["ZodUnknown"] = "ZodUnknown";
  ZodFirstPartyTypeKind2["ZodNever"] = "ZodNever";
  ZodFirstPartyTypeKind2["ZodVoid"] = "ZodVoid";
  ZodFirstPartyTypeKind2["ZodArray"] = "ZodArray";
  ZodFirstPartyTypeKind2["ZodObject"] = "ZodObject";
  ZodFirstPartyTypeKind2["ZodUnion"] = "ZodUnion";
  ZodFirstPartyTypeKind2["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
  ZodFirstPartyTypeKind2["ZodIntersection"] = "ZodIntersection";
  ZodFirstPartyTypeKind2["ZodTuple"] = "ZodTuple";
  ZodFirstPartyTypeKind2["ZodRecord"] = "ZodRecord";
  ZodFirstPartyTypeKind2["ZodMap"] = "ZodMap";
  ZodFirstPartyTypeKind2["ZodSet"] = "ZodSet";
  ZodFirstPartyTypeKind2["ZodFunction"] = "ZodFunction";
  ZodFirstPartyTypeKind2["ZodLazy"] = "ZodLazy";
  ZodFirstPartyTypeKind2["ZodLiteral"] = "ZodLiteral";
  ZodFirstPartyTypeKind2["ZodEnum"] = "ZodEnum";
  ZodFirstPartyTypeKind2["ZodEffects"] = "ZodEffects";
  ZodFirstPartyTypeKind2["ZodNativeEnum"] = "ZodNativeEnum";
  ZodFirstPartyTypeKind2["ZodOptional"] = "ZodOptional";
  ZodFirstPartyTypeKind2["ZodNullable"] = "ZodNullable";
  ZodFirstPartyTypeKind2["ZodDefault"] = "ZodDefault";
  ZodFirstPartyTypeKind2["ZodCatch"] = "ZodCatch";
  ZodFirstPartyTypeKind2["ZodPromise"] = "ZodPromise";
  ZodFirstPartyTypeKind2["ZodBranded"] = "ZodBranded";
  ZodFirstPartyTypeKind2["ZodPipeline"] = "ZodPipeline";
  ZodFirstPartyTypeKind2["ZodReadonly"] = "ZodReadonly";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
var instanceOfType = (cls, params = {
  message: `Input not instance of ${cls.name}`
}) => custom((data) => data instanceof cls, params);
var stringType = ZodString.create;
var numberType = ZodNumber.create;
var nanType = ZodNaN.create;
var bigIntType = ZodBigInt.create;
var booleanType = ZodBoolean.create;
var dateType = ZodDate.create;
var symbolType = ZodSymbol.create;
var undefinedType = ZodUndefined.create;
var nullType = ZodNull.create;
var anyType = ZodAny.create;
var unknownType = ZodUnknown.create;
var neverType = ZodNever.create;
var voidType = ZodVoid.create;
var arrayType = ZodArray.create;
var objectType = ZodObject.create;
var strictObjectType = ZodObject.strictCreate;
var unionType = ZodUnion.create;
var discriminatedUnionType = ZodDiscriminatedUnion.create;
var intersectionType = ZodIntersection.create;
var tupleType = ZodTuple.create;
var recordType = ZodRecord.create;
var mapType = ZodMap.create;
var setType = ZodSet.create;
var functionType = ZodFunction.create;
var lazyType = ZodLazy.create;
var literalType = ZodLiteral.create;
var enumType = ZodEnum.create;
var nativeEnumType = ZodNativeEnum.create;
var promiseType = ZodPromise.create;
var effectsType = ZodEffects.create;
var optionalType = ZodOptional.create;
var nullableType = ZodNullable.create;
var preprocessType = ZodEffects.createWithPreprocess;
var pipelineType = ZodPipeline.create;
var ostring = () => stringType().optional();
var onumber = () => numberType().optional();
var oboolean = () => booleanType().optional();
var coerce = {
  string: ((arg) => ZodString.create({ ...arg, coerce: true })),
  number: ((arg) => ZodNumber.create({ ...arg, coerce: true })),
  boolean: ((arg) => ZodBoolean.create({
    ...arg,
    coerce: true
  })),
  bigint: ((arg) => ZodBigInt.create({ ...arg, coerce: true })),
  date: ((arg) => ZodDate.create({ ...arg, coerce: true }))
};
var NEVER = INVALID;

// ../pla748-cad/node_modules/@paperclipai/shared/dist/constants.js
var COMPANY_STATUSES = ["active", "paused", "archived"];
var DEFAULT_COMPANY_ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024;
var MAX_COMPANY_ATTACHMENT_MAX_BYTES = 1024 * 1024 * 1024;
var DEPLOYMENT_MODES = ["local_trusted", "authenticated"];
var DEPLOYMENT_EXPOSURES = ["private", "public"];
var BIND_MODES = ["loopback", "lan", "tailnet", "custom"];
var AUTH_BASE_URL_MODES = ["auto", "explicit"];
var AGENT_STATUSES = [
  "active",
  "paused",
  "idle",
  "running",
  "error",
  "pending_approval",
  "terminated"
];
var AGENT_ADAPTER_TYPES = [
  "process",
  "http",
  "claude_local",
  "codex_local",
  "gemini_local",
  "opencode_local",
  "pi_local",
  "cursor",
  "openclaw_gateway"
];
var AGENT_ROLES = [
  "ceo",
  "cto",
  "cmo",
  "cfo",
  "security",
  "engineer",
  "designer",
  "pm",
  "qa",
  "devops",
  "researcher",
  "general"
];
var AGENT_ICON_NAMES = [
  "bot",
  "cpu",
  "brain",
  "zap",
  "rocket",
  "code",
  "terminal",
  "shield",
  "eye",
  "search",
  "wrench",
  "hammer",
  "lightbulb",
  "sparkles",
  "star",
  "heart",
  "flame",
  "bug",
  "cog",
  "database",
  "globe",
  "lock",
  "mail",
  "message-square",
  "file-code",
  "git-branch",
  "package",
  "puzzle",
  "target",
  "wand",
  "atom",
  "circuit-board",
  "radar",
  "swords",
  "telescope",
  "microscope",
  "crown",
  "gem",
  "hexagon",
  "pentagon",
  "fingerprint"
];
var ISSUE_STATUSES = [
  "backlog",
  "todo",
  "in_progress",
  "in_review",
  "done",
  "blocked",
  "cancelled"
];
var INBOX_MINE_ISSUE_STATUSES = [
  "backlog",
  "todo",
  "in_progress",
  "in_review",
  "blocked",
  "done"
];
var INBOX_MINE_ISSUE_STATUS_FILTER = INBOX_MINE_ISSUE_STATUSES.join(",");
var ISSUE_PRIORITIES = ["critical", "high", "medium", "low"];
var MAX_ISSUE_REQUEST_DEPTH = 1024;
function clampIssueRequestDepth(value) {
  if (typeof value !== "number" || !Number.isFinite(value))
    return 0;
  return Math.min(MAX_ISSUE_REQUEST_DEPTH, Math.max(0, Math.floor(value)));
}
var ISSUE_THREAD_INTERACTION_KINDS = [
  "suggest_tasks",
  "ask_user_questions",
  "request_confirmation"
];
var ISSUE_THREAD_INTERACTION_STATUSES = [
  "pending",
  "accepted",
  "rejected",
  "answered",
  "expired",
  "failed"
];
var ISSUE_THREAD_INTERACTION_CONTINUATION_POLICIES = [
  "none",
  "wake_assignee",
  "wake_assignee_on_accept"
];
var ISSUE_TREE_CONTROL_MODES = ["pause", "resume", "cancel", "restore"];
var ISSUE_TREE_HOLD_RELEASE_POLICY_STRATEGIES = ["manual", "after_active_runs_finish"];
var ISSUE_CONTINUATION_SUMMARY_DOCUMENT_KEY = "continuation-summary";
var SYSTEM_ISSUE_DOCUMENT_KEYS = [ISSUE_CONTINUATION_SUMMARY_DOCUMENT_KEY];
var SYSTEM_ISSUE_DOCUMENT_KEY_SET = new Set(SYSTEM_ISSUE_DOCUMENT_KEYS);
var ISSUE_EXECUTION_POLICY_MODES = ["normal", "auto"];
var ISSUE_EXECUTION_STAGE_TYPES = ["review", "approval"];
var ISSUE_EXECUTION_STATE_STATUSES = ["idle", "pending", "changes_requested", "completed"];
var ISSUE_EXECUTION_DECISION_OUTCOMES = ["approved", "changes_requested"];
var GOAL_LEVELS = ["company", "team", "agent", "task"];
var GOAL_STATUSES = ["planned", "active", "achieved", "cancelled"];
var PROJECT_STATUSES = [
  "backlog",
  "planned",
  "in_progress",
  "completed",
  "cancelled"
];
var ENVIRONMENT_DRIVERS = ["local", "ssh", "sandbox", "plugin"];
var ENVIRONMENT_STATUSES = ["active", "archived"];
var ENVIRONMENT_LEASE_STATUSES = ["active", "released", "expired", "failed", "retained"];
var ENVIRONMENT_LEASE_CLEANUP_STATUSES = ["pending", "success", "failed"];
var ROUTINE_STATUSES = ["active", "paused", "archived"];
var ROUTINE_CONCURRENCY_POLICIES = ["coalesce_if_active", "always_enqueue", "skip_if_active"];
var ROUTINE_CATCH_UP_POLICIES = ["skip_missed", "enqueue_missed_with_cap"];
var ROUTINE_TRIGGER_SIGNING_MODES = ["bearer", "hmac_sha256", "github_hmac", "none"];
var ROUTINE_VARIABLE_TYPES = ["text", "textarea", "number", "boolean", "select"];
var APPROVAL_TYPES = [
  "hire_agent",
  "approve_ceo_strategy",
  "budget_override_required",
  "request_board_approval"
];
var SECRET_PROVIDERS = [
  "local_encrypted",
  "aws_secrets_manager",
  "gcp_secret_manager",
  "vault"
];
var STORAGE_PROVIDERS = ["local_disk", "s3"];
var BILLING_TYPES = [
  "metered_api",
  "subscription_included",
  "subscription_overage",
  "credits",
  "fixed",
  "unknown"
];
var FINANCE_EVENT_KINDS = [
  "inference_charge",
  "platform_fee",
  "credit_purchase",
  "credit_refund",
  "credit_expiry",
  "byok_fee",
  "gateway_overhead",
  "log_storage_charge",
  "logpush_charge",
  "provisioned_capacity_charge",
  "training_charge",
  "custom_model_import_charge",
  "custom_model_storage_charge",
  "manual_adjustment"
];
var FINANCE_DIRECTIONS = ["debit", "credit"];
var FINANCE_UNITS = [
  "input_token",
  "output_token",
  "cached_input_token",
  "request",
  "credit_usd",
  "credit_unit",
  "model_unit_minute",
  "model_unit_hour",
  "gb_month",
  "train_token",
  "unknown"
];
var BUDGET_SCOPE_TYPES = ["company", "agent", "project"];
var BUDGET_METRICS = ["billed_cents"];
var BUDGET_WINDOW_KINDS = ["calendar_month_utc", "lifetime"];
var BUDGET_INCIDENT_RESOLUTION_ACTIONS = [
  "keep_paused",
  "raise_budget_and_resume"
];
var HUMAN_COMPANY_MEMBERSHIP_ROLES = [
  "owner",
  "admin",
  "operator",
  "viewer"
];
var INVITE_JOIN_TYPES = ["human", "agent", "both"];
var JOIN_REQUEST_TYPES = ["human", "agent"];
var JOIN_REQUEST_STATUSES = ["pending_approval", "approved", "rejected"];
var PERMISSION_KEYS = [
  "agents:create",
  "environments:manage",
  "users:invite",
  "users:manage_permissions",
  "tasks:assign",
  "tasks:assign_scope",
  "tasks:manage_active_checkouts",
  "joins:approve"
];
var PLUGIN_STATUSES = [
  "installed",
  "ready",
  "disabled",
  "error",
  "upgrade_pending",
  "uninstalled"
];
var PLUGIN_CATEGORIES = [
  "connector",
  "workspace",
  "automation",
  "ui"
];
var PLUGIN_CAPABILITIES = [
  // Data Read
  "companies.read",
  "projects.read",
  "project.workspaces.read",
  "issues.read",
  "issue.relations.read",
  "issue.subtree.read",
  "issue.comments.read",
  "issue.documents.read",
  "agents.read",
  "goals.read",
  "goals.create",
  "goals.update",
  "activity.read",
  "costs.read",
  "issues.orchestration.read",
  "database.namespace.read",
  // Data Write
  "issues.create",
  "issues.update",
  "issue.relations.write",
  "issues.checkout",
  "issues.wakeup",
  "issue.comments.create",
  "issue.interactions.create",
  "issue.documents.write",
  "agents.pause",
  "agents.resume",
  "agents.invoke",
  "agent.sessions.create",
  "agent.sessions.list",
  "agent.sessions.send",
  "agent.sessions.close",
  "activity.log.write",
  "metrics.write",
  "telemetry.track",
  "database.namespace.migrate",
  "database.namespace.write",
  // Plugin State
  "plugin.state.read",
  "plugin.state.write",
  // Runtime / Integration
  "events.subscribe",
  "events.emit",
  "jobs.schedule",
  "webhooks.receive",
  "api.routes.register",
  "http.outbound",
  "secrets.read-ref",
  "environment.drivers.register",
  // Agent Tools
  "agent.tools.register",
  // UI
  "instance.settings.register",
  "ui.sidebar.register",
  "ui.page.register",
  "ui.detailTab.register",
  "ui.dashboardWidget.register",
  "ui.commentAnnotation.register",
  "ui.action.register"
];
var PLUGIN_DATABASE_CORE_READ_TABLES = [
  "companies",
  "projects",
  "goals",
  "agents",
  "issues",
  "issue_documents",
  "issue_relations",
  "issue_comments",
  "heartbeat_runs",
  "cost_events",
  "approvals",
  "issue_approvals",
  "budget_incidents"
];
var PLUGIN_API_ROUTE_METHODS = ["GET", "POST", "PATCH", "DELETE"];
var PLUGIN_API_ROUTE_AUTH_MODES = ["board", "agent", "board-or-agent", "webhook"];
var PLUGIN_API_ROUTE_CHECKOUT_POLICIES = [
  "none",
  "required-for-agent-in-progress",
  "always-for-agent"
];
var PLUGIN_UI_SLOT_TYPES = [
  "page",
  "detailTab",
  "taskDetailView",
  "dashboardWidget",
  "sidebar",
  "sidebarPanel",
  "projectSidebarItem",
  "globalToolbarButton",
  "toolbarButton",
  "contextMenuItem",
  "commentAnnotation",
  "commentContextMenuItem",
  "settingsPage"
];
var PLUGIN_RESERVED_COMPANY_ROUTE_SEGMENTS = [
  "dashboard",
  "onboarding",
  "companies",
  "company",
  "settings",
  "plugins",
  "org",
  "agents",
  "projects",
  "issues",
  "goals",
  "approvals",
  "costs",
  "activity",
  "inbox",
  "design-guide",
  "tests"
];
var PLUGIN_LAUNCHER_PLACEMENT_ZONES = [
  "page",
  "detailTab",
  "taskDetailView",
  "dashboardWidget",
  "sidebar",
  "sidebarPanel",
  "projectSidebarItem",
  "globalToolbarButton",
  "toolbarButton",
  "contextMenuItem",
  "commentAnnotation",
  "commentContextMenuItem",
  "settingsPage"
];
var PLUGIN_LAUNCHER_ACTIONS = [
  "navigate",
  "openModal",
  "openDrawer",
  "openPopover",
  "performAction",
  "deepLink"
];
var PLUGIN_LAUNCHER_BOUNDS = [
  "inline",
  "compact",
  "default",
  "wide",
  "full"
];
var PLUGIN_LAUNCHER_RENDER_ENVIRONMENTS = [
  "hostInline",
  "hostOverlay",
  "hostRoute",
  "external",
  "iframe"
];
var PLUGIN_UI_SLOT_ENTITY_TYPES = [
  "project",
  "issue",
  "agent",
  "goal",
  "run",
  "comment"
];
var PLUGIN_STATE_SCOPE_KINDS = [
  "instance",
  "company",
  "project",
  "project_workspace",
  "agent",
  "issue",
  "goal",
  "run"
];

// ../pla748-cad/node_modules/@paperclipai/shared/dist/adapter-type.js
var agentAdapterTypeSchema = external_exports.string().trim().min(1).default("process").describe(`Known built-in adapters: ${AGENT_ADAPTER_TYPES.join(", ")}. External adapters may register additional non-empty string types at runtime.`);
var optionalAgentAdapterTypeSchema = external_exports.string().trim().min(1).optional();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/network-bind.js
function normalizeHost(host) {
  const trimmed = host?.trim();
  return trimmed ? trimmed : void 0;
}
function isLoopbackHost(host) {
  const normalized = normalizeHost(host)?.toLowerCase();
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}
function isAllInterfacesHost(host) {
  const normalized = normalizeHost(host)?.toLowerCase();
  return normalized === "0.0.0.0" || normalized === "::";
}
function inferBindModeFromHost(host, opts) {
  const normalized = normalizeHost(host);
  const tailnetBindHost = normalizeHost(opts?.tailnetBindHost);
  if (!normalized || isLoopbackHost(normalized))
    return "loopback";
  if (isAllInterfacesHost(normalized))
    return "lan";
  if (tailnetBindHost && normalized === tailnetBindHost)
    return "tailnet";
  return "custom";
}
function validateConfiguredBindMode(input) {
  const bind = input.bind ?? inferBindModeFromHost(input.host);
  const customBindHost = normalizeHost(input.customBindHost);
  const errors = [];
  if (input.deploymentMode === "local_trusted" && bind !== "loopback") {
    errors.push("local_trusted requires server.bind=loopback");
  }
  if (bind === "custom" && !customBindHost) {
    const legacyHost = normalizeHost(input.host);
    if (!legacyHost || isLoopbackHost(legacyHost) || isAllInterfacesHost(legacyHost)) {
      errors.push("server.customBindHost is required when server.bind=custom");
    }
  }
  if (input.deploymentMode === "authenticated" && input.deploymentExposure === "public" && bind === "tailnet") {
    errors.push("server.bind=tailnet is only supported for authenticated/private deployments");
  }
  return errors;
}

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/sidebar-preferences.js
var sidebarOrderedIdSchema = external_exports.string().uuid();
var sidebarOrderPreferenceSchema = external_exports.object({
  orderedIds: external_exports.array(sidebarOrderedIdSchema),
  updatedAt: external_exports.coerce.date().nullable()
});
var upsertSidebarOrderPreferenceSchema = external_exports.object({
  orderedIds: external_exports.array(sidebarOrderedIdSchema)
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/execution-workspace.js
var executionWorkspaceStatusSchema = external_exports.enum([
  "active",
  "idle",
  "in_review",
  "archived",
  "cleanup_failed"
]);
var executionWorkspaceConfigSchema = external_exports.object({
  environmentId: external_exports.string().uuid().optional().nullable(),
  provisionCommand: external_exports.string().optional().nullable(),
  teardownCommand: external_exports.string().optional().nullable(),
  cleanupCommand: external_exports.string().optional().nullable(),
  workspaceRuntime: external_exports.record(external_exports.unknown()).optional().nullable(),
  desiredState: external_exports.enum(["running", "stopped", "manual"]).optional().nullable(),
  serviceStates: external_exports.record(external_exports.enum(["running", "stopped", "manual"])).optional().nullable()
}).strict();
var workspaceRuntimeControlTargetSchema = external_exports.object({
  workspaceCommandId: external_exports.string().min(1).optional().nullable(),
  runtimeServiceId: external_exports.string().uuid().optional().nullable(),
  serviceIndex: external_exports.number().int().nonnegative().optional().nullable()
}).strict();
var executionWorkspaceCloseReadinessStateSchema = external_exports.enum([
  "ready",
  "ready_with_warnings",
  "blocked"
]);
var executionWorkspaceCloseActionKindSchema = external_exports.enum([
  "archive_record",
  "stop_runtime_services",
  "cleanup_command",
  "teardown_command",
  "git_worktree_remove",
  "git_branch_delete",
  "remove_local_directory"
]);
var executionWorkspaceCloseActionSchema = external_exports.object({
  kind: executionWorkspaceCloseActionKindSchema,
  label: external_exports.string(),
  description: external_exports.string(),
  command: external_exports.string().nullable()
}).strict();
var executionWorkspaceCloseLinkedIssueSchema = external_exports.object({
  id: external_exports.string().uuid(),
  identifier: external_exports.string().nullable(),
  title: external_exports.string(),
  status: external_exports.string(),
  isTerminal: external_exports.boolean()
}).strict();
var executionWorkspaceCloseGitReadinessSchema = external_exports.object({
  repoRoot: external_exports.string().nullable(),
  workspacePath: external_exports.string().nullable(),
  branchName: external_exports.string().nullable(),
  baseRef: external_exports.string().nullable(),
  hasDirtyTrackedFiles: external_exports.boolean(),
  hasUntrackedFiles: external_exports.boolean(),
  dirtyEntryCount: external_exports.number().int().nonnegative(),
  untrackedEntryCount: external_exports.number().int().nonnegative(),
  aheadCount: external_exports.number().int().nonnegative().nullable(),
  behindCount: external_exports.number().int().nonnegative().nullable(),
  isMergedIntoBase: external_exports.boolean().nullable(),
  createdByRuntime: external_exports.boolean()
}).strict();
var workspaceRuntimeServiceSchema = external_exports.object({
  id: external_exports.string(),
  companyId: external_exports.string().uuid(),
  projectId: external_exports.string().uuid().nullable(),
  projectWorkspaceId: external_exports.string().uuid().nullable(),
  executionWorkspaceId: external_exports.string().uuid().nullable(),
  issueId: external_exports.string().uuid().nullable(),
  scopeType: external_exports.enum(["project_workspace", "execution_workspace", "run", "agent"]),
  scopeId: external_exports.string().nullable(),
  serviceName: external_exports.string(),
  status: external_exports.enum(["starting", "running", "stopped", "failed"]),
  lifecycle: external_exports.enum(["shared", "ephemeral"]),
  reuseKey: external_exports.string().nullable(),
  command: external_exports.string().nullable(),
  cwd: external_exports.string().nullable(),
  port: external_exports.number().int().nullable(),
  url: external_exports.string().nullable(),
  provider: external_exports.enum(["local_process", "adapter_managed"]),
  providerRef: external_exports.string().nullable(),
  ownerAgentId: external_exports.string().uuid().nullable(),
  startedByRunId: external_exports.string().uuid().nullable(),
  lastUsedAt: external_exports.coerce.date(),
  startedAt: external_exports.coerce.date(),
  stoppedAt: external_exports.coerce.date().nullable(),
  stopPolicy: external_exports.record(external_exports.unknown()).nullable(),
  healthStatus: external_exports.enum(["unknown", "healthy", "unhealthy"]),
  configIndex: external_exports.number().int().nonnegative().nullable().optional(),
  createdAt: external_exports.coerce.date(),
  updatedAt: external_exports.coerce.date()
}).strict();
var executionWorkspaceCloseReadinessSchema = external_exports.object({
  workspaceId: external_exports.string().uuid(),
  state: executionWorkspaceCloseReadinessStateSchema,
  blockingReasons: external_exports.array(external_exports.string()),
  warnings: external_exports.array(external_exports.string()),
  linkedIssues: external_exports.array(executionWorkspaceCloseLinkedIssueSchema),
  plannedActions: external_exports.array(executionWorkspaceCloseActionSchema),
  isDestructiveCloseAllowed: external_exports.boolean(),
  isSharedWorkspace: external_exports.boolean(),
  isProjectPrimaryWorkspace: external_exports.boolean(),
  git: executionWorkspaceCloseGitReadinessSchema.nullable(),
  runtimeServices: external_exports.array(workspaceRuntimeServiceSchema)
}).strict();
var updateExecutionWorkspaceSchema = external_exports.object({
  name: external_exports.string().min(1).optional(),
  cwd: external_exports.string().optional().nullable(),
  repoUrl: external_exports.string().optional().nullable(),
  baseRef: external_exports.string().optional().nullable(),
  branchName: external_exports.string().optional().nullable(),
  providerRef: external_exports.string().optional().nullable(),
  status: executionWorkspaceStatusSchema.optional(),
  cleanupEligibleAt: external_exports.string().datetime().optional().nullable(),
  cleanupReason: external_exports.string().optional().nullable(),
  config: executionWorkspaceConfigSchema.optional().nullable(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/types/feedback.js
var FEEDBACK_TARGET_TYPES = ["issue_comment", "issue_document_revision"];
var FEEDBACK_VOTE_VALUES = ["up", "down"];
var FEEDBACK_DATA_SHARING_PREFERENCES = ["allowed", "not_allowed", "prompt"];
var DEFAULT_FEEDBACK_DATA_SHARING_PREFERENCE = "prompt";
var FEEDBACK_TRACE_STATUSES = ["local_only", "pending", "sent", "failed"];

// ../pla748-cad/node_modules/@paperclipai/shared/dist/types/instance.js
var DAILY_RETENTION_PRESETS = [3, 7, 14];
var WEEKLY_RETENTION_PRESETS = [1, 2, 4];
var MONTHLY_RETENTION_PRESETS = [1, 3, 6];
var DEFAULT_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS = 24;
var MIN_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS = 1;
var MAX_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS = 24 * 30;
var DEFAULT_BACKUP_RETENTION = {
  dailyDays: 7,
  weeklyWeeks: 4,
  monthlyMonths: 1
};

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/feedback.js
var feedbackTargetTypeSchema = external_exports.enum(FEEDBACK_TARGET_TYPES);
var feedbackTraceStatusSchema = external_exports.enum(FEEDBACK_TRACE_STATUSES);
var feedbackVoteValueSchema = external_exports.enum(FEEDBACK_VOTE_VALUES);
var feedbackDataSharingPreferenceSchema = external_exports.enum(FEEDBACK_DATA_SHARING_PREFERENCES);
var upsertIssueFeedbackVoteSchema = external_exports.object({
  targetType: feedbackTargetTypeSchema,
  targetId: external_exports.string().uuid(),
  vote: feedbackVoteValueSchema,
  reason: external_exports.string().trim().max(1e3).optional(),
  allowSharing: external_exports.boolean().optional()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/instance.js
function presetSchema(presets, label) {
  return external_exports.number().refine((v) => presets.includes(v), { message: `${label} must be one of: ${presets.join(", ")}` });
}
var backupRetentionPolicySchema = external_exports.object({
  dailyDays: presetSchema(DAILY_RETENTION_PRESETS, "dailyDays").default(DEFAULT_BACKUP_RETENTION.dailyDays),
  weeklyWeeks: presetSchema(WEEKLY_RETENTION_PRESETS, "weeklyWeeks").default(DEFAULT_BACKUP_RETENTION.weeklyWeeks),
  monthlyMonths: presetSchema(MONTHLY_RETENTION_PRESETS, "monthlyMonths").default(DEFAULT_BACKUP_RETENTION.monthlyMonths)
});
var instanceGeneralSettingsSchema = external_exports.object({
  censorUsernameInLogs: external_exports.boolean().default(false),
  keyboardShortcuts: external_exports.boolean().default(false),
  feedbackDataSharingPreference: feedbackDataSharingPreferenceSchema.default(DEFAULT_FEEDBACK_DATA_SHARING_PREFERENCE),
  backupRetention: backupRetentionPolicySchema.default(DEFAULT_BACKUP_RETENTION)
}).strict();
var patchInstanceGeneralSettingsSchema = instanceGeneralSettingsSchema.partial();
var instanceExperimentalSettingsSchema = external_exports.object({
  enableEnvironments: external_exports.boolean().default(false),
  enableIsolatedWorkspaces: external_exports.boolean().default(false),
  autoRestartDevServerWhenIdle: external_exports.boolean().default(false),
  enableIssueGraphLivenessAutoRecovery: external_exports.boolean().default(false),
  issueGraphLivenessAutoRecoveryLookbackHours: external_exports.number().int().min(MIN_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS).max(MAX_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS).default(DEFAULT_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS)
}).strict();
var patchInstanceExperimentalSettingsSchema = instanceExperimentalSettingsSchema.partial();
var issueGraphLivenessAutoRecoveryRequestSchema = external_exports.object({
  lookbackHours: external_exports.number().int().min(MIN_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS).max(MAX_ISSUE_GRAPH_LIVENESS_AUTO_RECOVERY_LOOKBACK_HOURS).optional()
}).strict();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/budget.js
var upsertBudgetPolicySchema = external_exports.object({
  scopeType: external_exports.enum(BUDGET_SCOPE_TYPES),
  scopeId: external_exports.string().uuid(),
  metric: external_exports.enum(BUDGET_METRICS).optional().default("billed_cents"),
  windowKind: external_exports.enum(BUDGET_WINDOW_KINDS).optional().default("calendar_month_utc"),
  amount: external_exports.number().int().nonnegative(),
  warnPercent: external_exports.number().int().min(1).max(99).optional().default(80),
  hardStopEnabled: external_exports.boolean().optional().default(true),
  notifyEnabled: external_exports.boolean().optional().default(true),
  isActive: external_exports.boolean().optional().default(true)
});
var resolveBudgetIncidentSchema = external_exports.object({
  action: external_exports.enum(BUDGET_INCIDENT_RESOLUTION_ACTIONS),
  amount: external_exports.number().int().nonnegative().optional(),
  decisionNote: external_exports.string().optional().nullable()
}).superRefine((value, ctx) => {
  if (value.action === "raise_budget_and_resume" && typeof value.amount !== "number") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "amount is required when raising a budget",
      path: ["amount"]
    });
  }
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/company.js
var logoAssetIdSchema = external_exports.string().uuid().nullable().optional();
var brandColorSchema = external_exports.string().regex(/^#[0-9a-fA-F]{6}$/).nullable().optional();
var feedbackDataSharingTermsVersionSchema = external_exports.string().min(1).nullable().optional();
var attachmentMaxBytesSchema = external_exports.number().int().min(1).max(MAX_COMPANY_ATTACHMENT_MAX_BYTES);
var createCompanySchema = external_exports.object({
  name: external_exports.string().min(1),
  description: external_exports.string().optional().nullable(),
  budgetMonthlyCents: external_exports.number().int().nonnegative().optional().default(0),
  attachmentMaxBytes: attachmentMaxBytesSchema.optional()
});
var updateCompanySchema = createCompanySchema.partial().extend({
  status: external_exports.enum(COMPANY_STATUSES).optional(),
  spentMonthlyCents: external_exports.number().int().nonnegative().optional(),
  requireBoardApprovalForNewAgents: external_exports.boolean().optional(),
  feedbackDataSharingEnabled: external_exports.boolean().optional(),
  feedbackDataSharingConsentAt: external_exports.coerce.date().nullable().optional(),
  feedbackDataSharingConsentByUserId: external_exports.string().min(1).nullable().optional(),
  feedbackDataSharingTermsVersion: feedbackDataSharingTermsVersionSchema,
  brandColor: brandColorSchema,
  logoAssetId: logoAssetIdSchema,
  attachmentMaxBytes: attachmentMaxBytesSchema.optional()
});
var updateCompanyBrandingSchema = external_exports.object({
  name: external_exports.string().min(1).optional(),
  description: external_exports.string().nullable().optional(),
  brandColor: brandColorSchema,
  logoAssetId: logoAssetIdSchema
}).strict().refine((value) => value.name !== void 0 || value.description !== void 0 || value.brandColor !== void 0 || value.logoAssetId !== void 0, "At least one branding field must be provided");

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/environment.js
var environmentDriverSchema = external_exports.enum(ENVIRONMENT_DRIVERS);
var environmentStatusSchema = external_exports.enum(ENVIRONMENT_STATUSES);
var environmentLeaseStatusSchema = external_exports.enum(ENVIRONMENT_LEASE_STATUSES);
var environmentLeaseCleanupStatusSchema = external_exports.enum(ENVIRONMENT_LEASE_CLEANUP_STATUSES);
var environmentFields = {
  name: external_exports.string().min(1),
  description: external_exports.string().optional().nullable(),
  driver: environmentDriverSchema,
  status: environmentStatusSchema.optional().default("active"),
  config: external_exports.record(external_exports.unknown()).optional().default({}),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
};
var createEnvironmentSchema = external_exports.object(environmentFields).strict();
var updateEnvironmentSchema = external_exports.object({
  name: external_exports.string().min(1).optional(),
  description: external_exports.string().optional().nullable(),
  driver: environmentDriverSchema.optional(),
  status: environmentStatusSchema.optional(),
  config: external_exports.record(external_exports.unknown()).optional(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();
var probeEnvironmentConfigSchema = external_exports.object({
  name: external_exports.string().min(1).optional(),
  description: external_exports.string().optional().nullable(),
  driver: environmentDriverSchema,
  config: external_exports.record(external_exports.unknown()).optional().default({}),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/company-skill.js
var companySkillSourceTypeSchema = external_exports.enum(["local_path", "github", "url", "catalog", "skills_sh"]);
var companySkillTrustLevelSchema = external_exports.enum(["markdown_only", "assets", "scripts_executables"]);
var companySkillCompatibilitySchema = external_exports.enum(["compatible", "unknown", "invalid"]);
var companySkillSourceBadgeSchema = external_exports.enum(["paperclip", "github", "local", "url", "catalog", "skills_sh"]);
var companySkillFileInventoryEntrySchema = external_exports.object({
  path: external_exports.string().min(1),
  kind: external_exports.enum(["skill", "markdown", "reference", "script", "asset", "other"])
});
var companySkillSchema = external_exports.object({
  id: external_exports.string().uuid(),
  companyId: external_exports.string().uuid(),
  key: external_exports.string().min(1),
  slug: external_exports.string().min(1),
  name: external_exports.string().min(1),
  description: external_exports.string().nullable(),
  markdown: external_exports.string(),
  sourceType: companySkillSourceTypeSchema,
  sourceLocator: external_exports.string().nullable(),
  sourceRef: external_exports.string().nullable(),
  trustLevel: companySkillTrustLevelSchema,
  compatibility: companySkillCompatibilitySchema,
  fileInventory: external_exports.array(companySkillFileInventoryEntrySchema).default([]),
  metadata: external_exports.record(external_exports.unknown()).nullable(),
  createdAt: external_exports.coerce.date(),
  updatedAt: external_exports.coerce.date()
});
var companySkillListItemSchema = companySkillSchema.extend({
  attachedAgentCount: external_exports.number().int().nonnegative(),
  editable: external_exports.boolean(),
  editableReason: external_exports.string().nullable(),
  sourceLabel: external_exports.string().nullable(),
  sourceBadge: companySkillSourceBadgeSchema
});
var companySkillUsageAgentSchema = external_exports.object({
  id: external_exports.string().uuid(),
  name: external_exports.string().min(1),
  urlKey: external_exports.string().min(1),
  adapterType: external_exports.string().min(1),
  desired: external_exports.boolean(),
  actualState: external_exports.string().nullable().describe("Runtime adapter skill state when explicitly fetched; company skill detail reads return null without probing agent runtimes.")
});
var companySkillDetailSchema = companySkillSchema.extend({
  attachedAgentCount: external_exports.number().int().nonnegative(),
  usedByAgents: external_exports.array(companySkillUsageAgentSchema).default([]),
  editable: external_exports.boolean(),
  editableReason: external_exports.string().nullable(),
  sourceLabel: external_exports.string().nullable(),
  sourceBadge: companySkillSourceBadgeSchema
});
var companySkillUpdateStatusSchema = external_exports.object({
  supported: external_exports.boolean(),
  reason: external_exports.string().nullable(),
  trackingRef: external_exports.string().nullable(),
  currentRef: external_exports.string().nullable(),
  latestRef: external_exports.string().nullable(),
  hasUpdate: external_exports.boolean()
});
var companySkillImportSchema = external_exports.object({
  source: external_exports.string().min(1)
});
var companySkillProjectScanRequestSchema = external_exports.object({
  projectIds: external_exports.array(external_exports.string().uuid()).optional(),
  workspaceIds: external_exports.array(external_exports.string().uuid()).optional()
});
var companySkillProjectScanSkippedSchema = external_exports.object({
  projectId: external_exports.string().uuid(),
  projectName: external_exports.string().min(1),
  workspaceId: external_exports.string().uuid().nullable(),
  workspaceName: external_exports.string().nullable(),
  path: external_exports.string().nullable(),
  reason: external_exports.string().min(1)
});
var companySkillProjectScanConflictSchema = external_exports.object({
  slug: external_exports.string().min(1),
  key: external_exports.string().min(1),
  projectId: external_exports.string().uuid(),
  projectName: external_exports.string().min(1),
  workspaceId: external_exports.string().uuid(),
  workspaceName: external_exports.string().min(1),
  path: external_exports.string().min(1),
  existingSkillId: external_exports.string().uuid(),
  existingSkillKey: external_exports.string().min(1),
  existingSourceLocator: external_exports.string().nullable(),
  reason: external_exports.string().min(1)
});
var companySkillProjectScanResultSchema = external_exports.object({
  scannedProjects: external_exports.number().int().nonnegative(),
  scannedWorkspaces: external_exports.number().int().nonnegative(),
  discovered: external_exports.number().int().nonnegative(),
  imported: external_exports.array(companySkillSchema),
  updated: external_exports.array(companySkillSchema),
  skipped: external_exports.array(companySkillProjectScanSkippedSchema),
  conflicts: external_exports.array(companySkillProjectScanConflictSchema),
  warnings: external_exports.array(external_exports.string())
});
var companySkillCreateSchema = external_exports.object({
  name: external_exports.string().min(1),
  slug: external_exports.string().min(1).nullable().optional(),
  description: external_exports.string().nullable().optional(),
  markdown: external_exports.string().nullable().optional()
});
var companySkillFileDetailSchema = external_exports.object({
  skillId: external_exports.string().uuid(),
  path: external_exports.string().min(1),
  kind: external_exports.enum(["skill", "markdown", "reference", "script", "asset", "other"]),
  content: external_exports.string(),
  language: external_exports.string().nullable(),
  markdown: external_exports.boolean(),
  editable: external_exports.boolean()
});
var companySkillFileUpdateSchema = external_exports.object({
  path: external_exports.string().min(1),
  content: external_exports.string()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/adapter-skills.js
var agentSkillStateSchema = external_exports.enum([
  "available",
  "configured",
  "installed",
  "missing",
  "stale",
  "external"
]);
var agentSkillOriginSchema = external_exports.enum([
  "company_managed",
  "paperclip_required",
  "user_installed",
  "external_unknown"
]);
var agentSkillSyncModeSchema = external_exports.enum([
  "unsupported",
  "persistent",
  "ephemeral"
]);
var agentSkillEntrySchema = external_exports.object({
  key: external_exports.string().min(1),
  runtimeName: external_exports.string().min(1).nullable(),
  desired: external_exports.boolean(),
  managed: external_exports.boolean(),
  required: external_exports.boolean().optional(),
  requiredReason: external_exports.string().nullable().optional(),
  state: agentSkillStateSchema,
  origin: agentSkillOriginSchema.optional(),
  originLabel: external_exports.string().nullable().optional(),
  locationLabel: external_exports.string().nullable().optional(),
  readOnly: external_exports.boolean().optional(),
  sourcePath: external_exports.string().nullable().optional(),
  targetPath: external_exports.string().nullable().optional(),
  detail: external_exports.string().nullable().optional()
});
var agentSkillSnapshotSchema = external_exports.object({
  adapterType: external_exports.string().min(1),
  supported: external_exports.boolean(),
  mode: agentSkillSyncModeSchema,
  desiredSkills: external_exports.array(external_exports.string().min(1)),
  entries: external_exports.array(agentSkillEntrySchema),
  warnings: external_exports.array(external_exports.string())
});
var agentSkillSyncSchema = external_exports.object({
  desiredSkills: external_exports.array(external_exports.string().min(1))
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/text.js
function normalizeEscapedLineBreaks(value) {
  return value.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\\r/g, "\n");
}
var multilineTextSchema = external_exports.string().transform(normalizeEscapedLineBreaks);

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/issue.js
var ISSUE_EXECUTION_WORKSPACE_PREFERENCES = [
  "inherit",
  "shared_workspace",
  "isolated_workspace",
  "operator_branch",
  "reuse_existing",
  "agent_default"
];
var executionWorkspaceStrategySchema = external_exports.object({
  type: external_exports.enum(["project_primary", "git_worktree", "adapter_managed", "cloud_sandbox"]).optional(),
  baseRef: external_exports.string().optional().nullable(),
  branchTemplate: external_exports.string().optional().nullable(),
  worktreeParentDir: external_exports.string().optional().nullable(),
  provisionCommand: external_exports.string().optional().nullable(),
  teardownCommand: external_exports.string().optional().nullable()
}).strict();
var issueExecutionWorkspaceSettingsSchema = external_exports.object({
  mode: external_exports.enum(ISSUE_EXECUTION_WORKSPACE_PREFERENCES).optional(),
  environmentId: external_exports.string().uuid().optional().nullable(),
  workspaceStrategy: executionWorkspaceStrategySchema.optional().nullable(),
  workspaceRuntime: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();
var issueAssigneeAdapterOverridesSchema = external_exports.object({
  adapterConfig: external_exports.record(external_exports.unknown()).optional(),
  useProjectWorkspace: external_exports.boolean().optional()
}).strict();
var issueExecutionStagePrincipalBaseSchema = external_exports.object({
  type: external_exports.enum(["agent", "user"]),
  agentId: external_exports.string().uuid().optional().nullable(),
  userId: external_exports.string().optional().nullable()
});
var issueExecutionStagePrincipalSchema = issueExecutionStagePrincipalBaseSchema.superRefine((value, ctx) => {
  if (value.type === "agent") {
    if (!value.agentId) {
      ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "Agent participants require agentId", path: ["agentId"] });
    }
    if (value.userId) {
      ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "Agent participants cannot set userId", path: ["userId"] });
    }
    return;
  }
  if (!value.userId) {
    ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "User participants require userId", path: ["userId"] });
  }
  if (value.agentId) {
    ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "User participants cannot set agentId", path: ["agentId"] });
  }
});
var issueExecutionStageParticipantSchema = issueExecutionStagePrincipalBaseSchema.extend({
  id: external_exports.string().uuid().optional()
}).superRefine((value, ctx) => {
  if (value.type === "agent") {
    if (!value.agentId) {
      ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "Agent participants require agentId", path: ["agentId"] });
    }
    if (value.userId) {
      ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "Agent participants cannot set userId", path: ["userId"] });
    }
    return;
  }
  if (!value.userId) {
    ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "User participants require userId", path: ["userId"] });
  }
  if (value.agentId) {
    ctx.addIssue({ code: external_exports.ZodIssueCode.custom, message: "User participants cannot set agentId", path: ["agentId"] });
  }
});
var issueExecutionStageSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  type: external_exports.enum(ISSUE_EXECUTION_STAGE_TYPES),
  approvalsNeeded: external_exports.literal(1).optional().default(1),
  participants: external_exports.array(issueExecutionStageParticipantSchema).default([])
});
var issueExecutionPolicySchema = external_exports.object({
  mode: external_exports.enum(ISSUE_EXECUTION_POLICY_MODES).optional().default("normal"),
  commentRequired: external_exports.boolean().optional().default(true),
  stages: external_exports.array(issueExecutionStageSchema).default([])
});
var issueReviewRequestSchema = external_exports.object({
  instructions: external_exports.string().trim().min(1).max(2e4)
}).strict();
var issueExecutionStateSchema = external_exports.object({
  status: external_exports.enum(ISSUE_EXECUTION_STATE_STATUSES),
  currentStageId: external_exports.string().uuid().nullable(),
  currentStageIndex: external_exports.number().int().nonnegative().nullable(),
  currentStageType: external_exports.enum(ISSUE_EXECUTION_STAGE_TYPES).nullable(),
  currentParticipant: issueExecutionStagePrincipalSchema.nullable(),
  returnAssignee: issueExecutionStagePrincipalSchema.nullable(),
  reviewRequest: issueReviewRequestSchema.nullable().optional().default(null),
  completedStageIds: external_exports.array(external_exports.string().uuid()).default([]),
  lastDecisionId: external_exports.string().uuid().nullable(),
  lastDecisionOutcome: external_exports.enum(ISSUE_EXECUTION_DECISION_OUTCOMES).nullable()
});
var issueRequestDepthInputSchema = external_exports.number().int().nonnegative().transform((value) => clampIssueRequestDepth(value));
var createIssueSchema = external_exports.object({
  projectId: external_exports.string().uuid().optional().nullable(),
  projectWorkspaceId: external_exports.string().uuid().optional().nullable(),
  goalId: external_exports.string().uuid().optional().nullable(),
  parentId: external_exports.string().uuid().optional().nullable(),
  blockedByIssueIds: external_exports.array(external_exports.string().uuid()).optional(),
  inheritExecutionWorkspaceFromIssueId: external_exports.string().uuid().optional().nullable(),
  title: external_exports.string().min(1),
  description: multilineTextSchema.optional().nullable(),
  status: external_exports.enum(ISSUE_STATUSES).optional().default("backlog"),
  priority: external_exports.enum(ISSUE_PRIORITIES).optional().default("medium"),
  assigneeAgentId: external_exports.string().uuid().optional().nullable(),
  assigneeUserId: external_exports.string().optional().nullable(),
  requestDepth: issueRequestDepthInputSchema.optional().default(0),
  billingCode: external_exports.string().optional().nullable(),
  assigneeAdapterOverrides: issueAssigneeAdapterOverridesSchema.optional().nullable(),
  executionPolicy: issueExecutionPolicySchema.optional().nullable(),
  executionWorkspaceId: external_exports.string().uuid().optional().nullable(),
  executionWorkspacePreference: external_exports.enum(ISSUE_EXECUTION_WORKSPACE_PREFERENCES).optional().nullable(),
  executionWorkspaceSettings: issueExecutionWorkspaceSettingsSchema.optional().nullable(),
  labelIds: external_exports.array(external_exports.string().uuid()).optional()
});
var createChildIssueSchema = createIssueSchema.omit({
  parentId: true,
  inheritExecutionWorkspaceFromIssueId: true
}).extend({
  acceptanceCriteria: external_exports.array(external_exports.string().trim().min(1).max(500)).max(20).optional(),
  blockParentUntilDone: external_exports.boolean().optional().default(false)
});
var createIssueLabelSchema = external_exports.object({
  name: external_exports.string().trim().min(1).max(48),
  color: external_exports.string().regex(/^#(?:[0-9a-fA-F]{6})$/, "Color must be a 6-digit hex value")
});
var updateIssueSchema = createIssueSchema.partial().extend({
  requestDepth: issueRequestDepthInputSchema.optional(),
  assigneeAgentId: external_exports.string().trim().min(1).optional().nullable(),
  comment: multilineTextSchema.pipe(external_exports.string().min(1)).optional(),
  reviewRequest: issueReviewRequestSchema.optional().nullable(),
  reopen: external_exports.boolean().optional(),
  resume: external_exports.boolean().optional(),
  interrupt: external_exports.boolean().optional(),
  hiddenAt: external_exports.string().datetime().nullable().optional()
});
var checkoutIssueSchema = external_exports.object({
  agentId: external_exports.string().uuid(),
  expectedStatuses: external_exports.array(external_exports.enum(ISSUE_STATUSES)).nonempty()
});
var addIssueCommentSchema = external_exports.object({
  body: multilineTextSchema.pipe(external_exports.string().min(1)),
  reopen: external_exports.boolean().optional(),
  resume: external_exports.boolean().optional(),
  interrupt: external_exports.boolean().optional()
});
var issueThreadInteractionStatusSchema = external_exports.enum(ISSUE_THREAD_INTERACTION_STATUSES);
var issueThreadInteractionKindSchema = external_exports.enum(ISSUE_THREAD_INTERACTION_KINDS);
var issueThreadInteractionContinuationPolicySchema = external_exports.enum(ISSUE_THREAD_INTERACTION_CONTINUATION_POLICIES);
var issueDocumentKeySchema = external_exports.string().trim().min(1).max(64).regex(/^[a-z0-9][a-z0-9_-]*$/, "Document key must be lowercase letters, numbers, _ or -");
var suggestedTaskDraftSchema = external_exports.object({
  clientKey: external_exports.string().trim().min(1).max(120),
  parentClientKey: external_exports.string().trim().min(1).max(120).nullable().optional(),
  parentId: external_exports.string().uuid().nullable().optional(),
  title: external_exports.string().trim().min(1).max(240),
  description: multilineTextSchema.pipe(external_exports.string().trim().max(2e4)).nullable().optional(),
  priority: external_exports.enum(ISSUE_PRIORITIES).nullable().optional(),
  assigneeAgentId: external_exports.string().uuid().nullable().optional(),
  assigneeUserId: external_exports.string().trim().min(1).nullable().optional(),
  projectId: external_exports.string().uuid().nullable().optional(),
  goalId: external_exports.string().uuid().nullable().optional(),
  billingCode: external_exports.string().trim().max(120).nullable().optional(),
  labels: external_exports.array(external_exports.string().trim().min(1).max(48)).max(20).optional(),
  hiddenInPreview: external_exports.boolean().optional()
}).superRefine((value, ctx) => {
  if (value.assigneeAgentId && value.assigneeUserId) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "Suggested tasks can only target one assignee",
      path: ["assigneeAgentId"]
    });
  }
});
var suggestTasksPayloadSchema = external_exports.object({
  version: external_exports.literal(1),
  defaultParentId: external_exports.string().uuid().nullable().optional(),
  tasks: external_exports.array(suggestedTaskDraftSchema).min(1).max(50)
}).superRefine((value, ctx) => {
  const seenClientKeys = /* @__PURE__ */ new Set();
  for (const [index, task] of value.tasks.entries()) {
    if (seenClientKeys.has(task.clientKey)) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "clientKey must be unique within one interaction",
        path: ["tasks", index, "clientKey"]
      });
      continue;
    }
    seenClientKeys.add(task.clientKey);
  }
});
var suggestTasksResultCreatedTaskSchema = external_exports.object({
  clientKey: external_exports.string().trim().min(1).max(120),
  issueId: external_exports.string().uuid(),
  identifier: external_exports.string().trim().min(1).nullable().optional(),
  title: external_exports.string().trim().min(1).nullable().optional(),
  parentIssueId: external_exports.string().uuid().nullable().optional(),
  parentIdentifier: external_exports.string().trim().min(1).nullable().optional()
});
var suggestTasksResultSchema = external_exports.object({
  version: external_exports.literal(1),
  createdTasks: external_exports.array(suggestTasksResultCreatedTaskSchema).max(50).optional(),
  skippedClientKeys: external_exports.array(external_exports.string().trim().min(1).max(120)).max(50).optional(),
  rejectionReason: external_exports.string().trim().max(4e3).nullable().optional()
});
var askUserQuestionsQuestionOptionSchema = external_exports.object({
  id: external_exports.string().trim().min(1).max(120),
  label: external_exports.string().trim().min(1).max(120),
  description: external_exports.string().trim().max(500).nullable().optional()
});
var askUserQuestionsQuestionSchema = external_exports.object({
  id: external_exports.string().trim().min(1).max(120),
  prompt: external_exports.string().trim().min(1).max(500),
  helpText: external_exports.string().trim().max(1e3).nullable().optional(),
  selectionMode: external_exports.enum(["single", "multi"]),
  required: external_exports.boolean().optional(),
  options: external_exports.array(askUserQuestionsQuestionOptionSchema).min(1).max(10)
});
var askUserQuestionsPayloadSchema = external_exports.object({
  version: external_exports.literal(1),
  title: external_exports.string().trim().max(240).nullable().optional(),
  submitLabel: external_exports.string().trim().max(120).nullable().optional(),
  questions: external_exports.array(askUserQuestionsQuestionSchema).min(1).max(10)
}).superRefine((value, ctx) => {
  const seenQuestionIds = /* @__PURE__ */ new Set();
  for (const [questionIndex, question] of value.questions.entries()) {
    if (seenQuestionIds.has(question.id)) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Question ids must be unique within one interaction",
        path: ["questions", questionIndex, "id"]
      });
    }
    seenQuestionIds.add(question.id);
    const seenOptionIds = /* @__PURE__ */ new Set();
    for (const [optionIndex, option] of question.options.entries()) {
      if (seenOptionIds.has(option.id)) {
        ctx.addIssue({
          code: external_exports.ZodIssueCode.custom,
          message: "Option ids must be unique within one question",
          path: ["questions", questionIndex, "options", optionIndex, "id"]
        });
      }
      seenOptionIds.add(option.id);
    }
  }
});
var askUserQuestionsAnswerSchema = external_exports.object({
  questionId: external_exports.string().trim().min(1).max(120),
  optionIds: external_exports.array(external_exports.string().trim().min(1).max(120)).max(20)
});
var askUserQuestionsResultSchema = external_exports.object({
  version: external_exports.literal(1),
  answers: external_exports.array(askUserQuestionsAnswerSchema).max(20),
  summaryMarkdown: external_exports.string().max(2e4).nullable().optional()
});
var requestConfirmationHrefSchema = external_exports.string().trim().min(1).max(2e3).refine((value) => {
  const lower = value.toLowerCase();
  return !lower.startsWith("javascript:") && !lower.startsWith("data:") && !value.startsWith("//");
}, "href must not use javascript:, data:, or protocol-relative URLs");
var requestConfirmationTargetBaseSchema = external_exports.object({
  label: external_exports.string().trim().min(1).max(120).nullable().optional(),
  href: requestConfirmationHrefSchema.nullable().optional()
});
var requestConfirmationIssueDocumentTargetSchema = requestConfirmationTargetBaseSchema.extend({
  type: external_exports.literal("issue_document"),
  issueId: external_exports.string().uuid().nullable().optional(),
  documentId: external_exports.string().uuid().nullable().optional(),
  key: issueDocumentKeySchema,
  revisionId: external_exports.string().uuid(),
  revisionNumber: external_exports.number().int().positive().nullable().optional()
});
var requestConfirmationCustomTargetSchema = requestConfirmationTargetBaseSchema.extend({
  type: external_exports.literal("custom"),
  key: external_exports.string().trim().min(1).max(120),
  revisionId: external_exports.string().trim().min(1).max(255).nullable().optional(),
  revisionNumber: external_exports.number().int().positive().nullable().optional()
});
var requestConfirmationTargetSchema = external_exports.discriminatedUnion("type", [
  requestConfirmationIssueDocumentTargetSchema,
  requestConfirmationCustomTargetSchema
]);
var requestConfirmationPayloadSchema = external_exports.object({
  version: external_exports.literal(1),
  prompt: external_exports.string().trim().min(1).max(1e3),
  acceptLabel: external_exports.string().trim().min(1).max(80).nullable().optional(),
  rejectLabel: external_exports.string().trim().min(1).max(80).nullable().optional(),
  rejectRequiresReason: external_exports.boolean().optional(),
  rejectReasonLabel: external_exports.string().trim().min(1).max(160).nullable().optional(),
  allowDeclineReason: external_exports.boolean().optional().default(true),
  declineReasonPlaceholder: external_exports.string().trim().min(1).max(240).nullable().optional(),
  detailsMarkdown: external_exports.string().max(2e4).nullable().optional(),
  supersedeOnUserComment: external_exports.boolean().optional(),
  target: requestConfirmationTargetSchema.nullable().optional()
});
var requestConfirmationResultSchema = external_exports.object({
  version: external_exports.literal(1),
  outcome: external_exports.enum(["accepted", "rejected", "superseded_by_comment", "stale_target"]),
  reason: external_exports.string().trim().max(4e3).nullable().optional(),
  commentId: external_exports.string().uuid().nullable().optional(),
  staleTarget: requestConfirmationTargetSchema.nullable().optional()
});
var createIssueThreadInteractionSchema = external_exports.discriminatedUnion("kind", [
  external_exports.object({
    kind: external_exports.literal("suggest_tasks"),
    idempotencyKey: external_exports.string().trim().max(255).nullable().optional(),
    sourceCommentId: external_exports.string().uuid().nullable().optional(),
    sourceRunId: external_exports.string().uuid().nullable().optional(),
    title: external_exports.string().trim().max(240).nullable().optional(),
    summary: external_exports.string().trim().max(1e3).nullable().optional(),
    continuationPolicy: issueThreadInteractionContinuationPolicySchema.optional().default("wake_assignee"),
    payload: suggestTasksPayloadSchema
  }),
  external_exports.object({
    kind: external_exports.literal("ask_user_questions"),
    idempotencyKey: external_exports.string().trim().max(255).nullable().optional(),
    sourceCommentId: external_exports.string().uuid().nullable().optional(),
    sourceRunId: external_exports.string().uuid().nullable().optional(),
    title: external_exports.string().trim().max(240).nullable().optional(),
    summary: external_exports.string().trim().max(1e3).nullable().optional(),
    continuationPolicy: issueThreadInteractionContinuationPolicySchema.optional().default("wake_assignee"),
    payload: askUserQuestionsPayloadSchema
  }),
  external_exports.object({
    kind: external_exports.literal("request_confirmation"),
    idempotencyKey: external_exports.string().trim().max(255).nullable().optional(),
    sourceCommentId: external_exports.string().uuid().nullable().optional(),
    sourceRunId: external_exports.string().uuid().nullable().optional(),
    title: external_exports.string().trim().max(240).nullable().optional(),
    summary: external_exports.string().trim().max(1e3).nullable().optional(),
    continuationPolicy: issueThreadInteractionContinuationPolicySchema.optional().default("none"),
    payload: requestConfirmationPayloadSchema
  })
]);
var acceptIssueThreadInteractionSchema = external_exports.object({
  selectedClientKeys: external_exports.array(external_exports.string().trim().min(1).max(120)).min(1).max(50).optional()
}).superRefine((value, ctx) => {
  const seenClientKeys = /* @__PURE__ */ new Set();
  for (const [index, clientKey] of (value.selectedClientKeys ?? []).entries()) {
    if (seenClientKeys.has(clientKey)) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "selectedClientKeys must be unique",
        path: ["selectedClientKeys", index]
      });
      continue;
    }
    seenClientKeys.add(clientKey);
  }
});
var rejectIssueThreadInteractionSchema = external_exports.object({
  reason: external_exports.string().trim().max(4e3).optional()
});
var respondIssueThreadInteractionSchema = external_exports.object({
  answers: external_exports.array(askUserQuestionsAnswerSchema).max(20),
  summaryMarkdown: multilineTextSchema.pipe(external_exports.string().max(2e4)).nullable().optional()
});
var linkIssueApprovalSchema = external_exports.object({
  approvalId: external_exports.string().uuid()
});
var createIssueAttachmentMetadataSchema = external_exports.object({
  issueCommentId: external_exports.string().uuid().optional().nullable()
});
var ISSUE_DOCUMENT_FORMATS = ["markdown"];
var issueDocumentFormatSchema = external_exports.enum(ISSUE_DOCUMENT_FORMATS);
var upsertIssueDocumentSchema = external_exports.object({
  title: external_exports.string().trim().max(200).nullable().optional(),
  format: issueDocumentFormatSchema,
  body: multilineTextSchema.pipe(external_exports.string().max(524288)),
  changeSummary: external_exports.string().trim().max(500).nullable().optional(),
  baseRevisionId: external_exports.string().uuid().nullable().optional()
});
var restoreIssueDocumentRevisionSchema = external_exports.object({});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/routine.js
var routineVariableValueSchema = external_exports.union([external_exports.string(), external_exports.number().finite(), external_exports.boolean()]);
var routineVariableSchema = external_exports.object({
  name: external_exports.string().trim().regex(/^[A-Za-z][A-Za-z0-9_]*$/),
  label: external_exports.string().trim().max(120).optional().nullable(),
  type: external_exports.enum(ROUTINE_VARIABLE_TYPES).optional().default("text"),
  defaultValue: routineVariableValueSchema.optional().nullable(),
  required: external_exports.boolean().optional().default(true),
  options: external_exports.array(external_exports.string().trim().min(1).max(120)).max(50).optional().default([])
}).superRefine((value, ctx) => {
  if (value.type === "select" && value.options.length === 0) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      path: ["options"],
      message: "Select variables require at least one option"
    });
  }
  if (value.type !== "select" && value.options.length > 0) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      path: ["options"],
      message: "Only select variables can define options"
    });
  }
  if (value.type === "select" && value.defaultValue != null) {
    if (typeof value.defaultValue !== "string" || !value.options.includes(value.defaultValue)) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        path: ["defaultValue"],
        message: "Select variable defaults must match one of the allowed options"
      });
    }
  }
});
var createRoutineSchema = external_exports.object({
  projectId: external_exports.string().uuid().optional().nullable(),
  goalId: external_exports.string().uuid().optional().nullable(),
  parentIssueId: external_exports.string().uuid().optional().nullable(),
  title: external_exports.string().trim().min(1).max(200),
  description: external_exports.string().optional().nullable(),
  assigneeAgentId: external_exports.string().uuid().optional().nullable(),
  priority: external_exports.enum(ISSUE_PRIORITIES).optional().default("medium"),
  status: external_exports.enum(ROUTINE_STATUSES).optional().default("active"),
  concurrencyPolicy: external_exports.enum(ROUTINE_CONCURRENCY_POLICIES).optional().default("coalesce_if_active"),
  catchUpPolicy: external_exports.enum(ROUTINE_CATCH_UP_POLICIES).optional().default("skip_missed"),
  variables: external_exports.array(routineVariableSchema).optional().default([])
});
var updateRoutineSchema = createRoutineSchema.partial();
var baseTriggerSchema = external_exports.object({
  label: external_exports.string().trim().max(120).optional().nullable(),
  enabled: external_exports.boolean().optional().default(true)
});
var createRoutineTriggerSchema = external_exports.discriminatedUnion("kind", [
  baseTriggerSchema.extend({
    kind: external_exports.literal("schedule"),
    cronExpression: external_exports.string().trim().min(1),
    timezone: external_exports.string().trim().min(1).default("UTC")
  }),
  baseTriggerSchema.extend({
    kind: external_exports.literal("webhook"),
    signingMode: external_exports.enum(ROUTINE_TRIGGER_SIGNING_MODES).optional().default("bearer"),
    replayWindowSec: external_exports.number().int().min(30).max(86400).optional().default(300)
  }),
  baseTriggerSchema.extend({
    kind: external_exports.literal("api")
  })
]);
var updateRoutineTriggerSchema = external_exports.object({
  label: external_exports.string().trim().max(120).optional().nullable(),
  enabled: external_exports.boolean().optional(),
  cronExpression: external_exports.string().trim().min(1).optional().nullable(),
  timezone: external_exports.string().trim().min(1).optional().nullable(),
  signingMode: external_exports.enum(ROUTINE_TRIGGER_SIGNING_MODES).optional().nullable(),
  replayWindowSec: external_exports.number().int().min(30).max(86400).optional().nullable()
});
var runRoutineSchema = external_exports.object({
  triggerId: external_exports.string().uuid().optional().nullable(),
  payload: external_exports.record(external_exports.unknown()).optional().nullable(),
  variables: external_exports.record(routineVariableValueSchema).optional().nullable(),
  projectId: external_exports.string().uuid().optional().nullable(),
  assigneeAgentId: external_exports.string().uuid().optional().nullable(),
  idempotencyKey: external_exports.string().trim().max(255).optional().nullable(),
  source: external_exports.enum(["manual", "api"]).optional().default("manual"),
  executionWorkspaceId: external_exports.string().uuid().optional().nullable(),
  executionWorkspacePreference: external_exports.enum(ISSUE_EXECUTION_WORKSPACE_PREFERENCES).optional().nullable(),
  executionWorkspaceSettings: issueExecutionWorkspaceSettingsSchema.optional().nullable()
});
var rotateRoutineTriggerSecretSchema = external_exports.object({});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/company-portability.js
var portabilityIncludeSchema = external_exports.object({
  company: external_exports.boolean().optional(),
  agents: external_exports.boolean().optional(),
  projects: external_exports.boolean().optional(),
  issues: external_exports.boolean().optional(),
  skills: external_exports.boolean().optional()
}).partial();
var portabilityEnvInputSchema = external_exports.object({
  key: external_exports.string().min(1),
  description: external_exports.string().nullable(),
  agentSlug: external_exports.string().min(1).nullable(),
  projectSlug: external_exports.string().min(1).nullable(),
  kind: external_exports.enum(["secret", "plain"]),
  requirement: external_exports.enum(["required", "optional"]),
  defaultValue: external_exports.string().nullable(),
  portability: external_exports.enum(["portable", "system_dependent"])
});
var portabilityFileEntrySchema = external_exports.union([
  external_exports.string(),
  external_exports.object({
    encoding: external_exports.literal("base64"),
    data: external_exports.string(),
    contentType: external_exports.string().min(1).optional().nullable()
  })
]);
var portabilityCompanyManifestEntrySchema = external_exports.object({
  path: external_exports.string().min(1),
  name: external_exports.string().min(1),
  description: external_exports.string().nullable(),
  brandColor: external_exports.string().nullable(),
  logoPath: external_exports.string().nullable(),
  attachmentMaxBytes: external_exports.number().int().min(1).max(MAX_COMPANY_ATTACHMENT_MAX_BYTES).nullable().default(null),
  requireBoardApprovalForNewAgents: external_exports.boolean(),
  feedbackDataSharingEnabled: external_exports.boolean().default(false),
  feedbackDataSharingConsentAt: external_exports.string().datetime().nullable().default(null),
  feedbackDataSharingConsentByUserId: external_exports.string().nullable().default(null),
  feedbackDataSharingTermsVersion: external_exports.string().nullable().default(null)
});
var portabilitySidebarOrderSchema = external_exports.object({
  agents: external_exports.array(external_exports.string().min(1)).default([]),
  projects: external_exports.array(external_exports.string().min(1)).default([])
});
var portabilityAgentManifestEntrySchema = external_exports.object({
  slug: external_exports.string().min(1),
  name: external_exports.string().min(1),
  path: external_exports.string().min(1),
  skills: external_exports.array(external_exports.string().min(1)).default([]),
  role: external_exports.string().min(1),
  title: external_exports.string().nullable(),
  icon: external_exports.string().nullable(),
  capabilities: external_exports.string().nullable(),
  reportsToSlug: external_exports.string().min(1).nullable(),
  adapterType: external_exports.string().min(1),
  adapterConfig: external_exports.record(external_exports.unknown()),
  runtimeConfig: external_exports.record(external_exports.unknown()),
  permissions: external_exports.record(external_exports.unknown()),
  budgetMonthlyCents: external_exports.number().int().nonnegative(),
  metadata: external_exports.record(external_exports.unknown()).nullable()
});
var portabilitySkillManifestEntrySchema = external_exports.object({
  key: external_exports.string().min(1),
  slug: external_exports.string().min(1),
  name: external_exports.string().min(1),
  path: external_exports.string().min(1),
  description: external_exports.string().nullable(),
  sourceType: external_exports.string().min(1),
  sourceLocator: external_exports.string().nullable(),
  sourceRef: external_exports.string().nullable(),
  trustLevel: external_exports.string().nullable(),
  compatibility: external_exports.string().nullable(),
  metadata: external_exports.record(external_exports.unknown()).nullable(),
  fileInventory: external_exports.array(external_exports.object({
    path: external_exports.string().min(1),
    kind: external_exports.string().min(1)
  })).default([])
});
var portabilityProjectManifestEntrySchema = external_exports.object({
  slug: external_exports.string().min(1),
  name: external_exports.string().min(1),
  path: external_exports.string().min(1),
  description: external_exports.string().nullable(),
  ownerAgentSlug: external_exports.string().min(1).nullable(),
  leadAgentSlug: external_exports.string().min(1).nullable(),
  targetDate: external_exports.string().nullable(),
  color: external_exports.string().nullable(),
  status: external_exports.string().nullable(),
  executionWorkspacePolicy: external_exports.record(external_exports.unknown()).nullable(),
  workspaces: external_exports.array(external_exports.object({
    key: external_exports.string().min(1),
    name: external_exports.string().min(1),
    sourceType: external_exports.string().nullable(),
    repoUrl: external_exports.string().nullable(),
    repoRef: external_exports.string().nullable(),
    defaultRef: external_exports.string().nullable(),
    visibility: external_exports.string().nullable(),
    setupCommand: external_exports.string().nullable(),
    cleanupCommand: external_exports.string().nullable(),
    metadata: external_exports.record(external_exports.unknown()).nullable(),
    isPrimary: external_exports.boolean()
  })).default([]),
  metadata: external_exports.record(external_exports.unknown()).nullable()
});
var portabilityIssueRoutineTriggerManifestEntrySchema = external_exports.object({
  kind: external_exports.string().min(1),
  label: external_exports.string().nullable(),
  enabled: external_exports.boolean(),
  cronExpression: external_exports.string().nullable(),
  timezone: external_exports.string().nullable(),
  signingMode: external_exports.string().nullable(),
  replayWindowSec: external_exports.number().int().nullable()
});
var portabilityIssueRoutineManifestEntrySchema = external_exports.object({
  concurrencyPolicy: external_exports.string().nullable(),
  catchUpPolicy: external_exports.string().nullable(),
  variables: external_exports.array(routineVariableSchema).nullable().optional(),
  triggers: external_exports.array(portabilityIssueRoutineTriggerManifestEntrySchema).default([])
});
var portabilityIssueManifestEntrySchema = external_exports.object({
  slug: external_exports.string().min(1),
  identifier: external_exports.string().min(1).nullable(),
  title: external_exports.string().min(1),
  path: external_exports.string().min(1),
  projectSlug: external_exports.string().min(1).nullable(),
  projectWorkspaceKey: external_exports.string().min(1).nullable(),
  assigneeAgentSlug: external_exports.string().min(1).nullable(),
  description: external_exports.string().nullable(),
  recurring: external_exports.boolean().default(false),
  routine: portabilityIssueRoutineManifestEntrySchema.nullable(),
  legacyRecurrence: external_exports.record(external_exports.unknown()).nullable(),
  status: external_exports.string().nullable(),
  priority: external_exports.string().nullable(),
  labelIds: external_exports.array(external_exports.string().min(1)).default([]),
  billingCode: external_exports.string().nullable(),
  executionWorkspaceSettings: external_exports.record(external_exports.unknown()).nullable(),
  assigneeAdapterOverrides: external_exports.record(external_exports.unknown()).nullable(),
  metadata: external_exports.record(external_exports.unknown()).nullable()
});
var portabilityManifestSchema = external_exports.object({
  schemaVersion: external_exports.number().int().positive(),
  generatedAt: external_exports.string().datetime(),
  source: external_exports.object({
    companyId: external_exports.string().uuid(),
    companyName: external_exports.string().min(1)
  }).nullable(),
  includes: external_exports.object({
    company: external_exports.boolean(),
    agents: external_exports.boolean(),
    projects: external_exports.boolean(),
    issues: external_exports.boolean(),
    skills: external_exports.boolean()
  }),
  company: portabilityCompanyManifestEntrySchema.nullable(),
  sidebar: portabilitySidebarOrderSchema.nullable(),
  agents: external_exports.array(portabilityAgentManifestEntrySchema),
  skills: external_exports.array(portabilitySkillManifestEntrySchema).default([]),
  projects: external_exports.array(portabilityProjectManifestEntrySchema).default([]),
  issues: external_exports.array(portabilityIssueManifestEntrySchema).default([]),
  envInputs: external_exports.array(portabilityEnvInputSchema).default([])
});
var portabilitySourceSchema = external_exports.discriminatedUnion("type", [
  external_exports.object({
    type: external_exports.literal("inline"),
    rootPath: external_exports.string().min(1).optional().nullable(),
    files: external_exports.record(portabilityFileEntrySchema)
  }),
  external_exports.object({
    type: external_exports.literal("github"),
    url: external_exports.string().url()
  })
]);
var portabilityTargetSchema = external_exports.discriminatedUnion("mode", [
  external_exports.object({
    mode: external_exports.literal("new_company"),
    newCompanyName: external_exports.string().min(1).optional().nullable()
  }),
  external_exports.object({
    mode: external_exports.literal("existing_company"),
    companyId: external_exports.string().uuid()
  })
]);
var portabilityAgentSelectionSchema = external_exports.union([
  external_exports.literal("all"),
  external_exports.array(external_exports.string().min(1))
]);
var portabilityCollisionStrategySchema = external_exports.enum(["rename", "skip", "replace"]);
var companyPortabilityExportSchema = external_exports.object({
  include: portabilityIncludeSchema.optional(),
  agents: external_exports.array(external_exports.string().min(1)).optional(),
  skills: external_exports.array(external_exports.string().min(1)).optional(),
  projects: external_exports.array(external_exports.string().min(1)).optional(),
  issues: external_exports.array(external_exports.string().min(1)).optional(),
  projectIssues: external_exports.array(external_exports.string().min(1)).optional(),
  selectedFiles: external_exports.array(external_exports.string().min(1)).optional(),
  expandReferencedSkills: external_exports.boolean().optional(),
  sidebarOrder: portabilitySidebarOrderSchema.partial().optional()
});
var companyPortabilityPreviewSchema = external_exports.object({
  source: portabilitySourceSchema,
  include: portabilityIncludeSchema.optional(),
  target: portabilityTargetSchema,
  agents: portabilityAgentSelectionSchema.optional(),
  collisionStrategy: portabilityCollisionStrategySchema.optional(),
  nameOverrides: external_exports.record(external_exports.string().min(1), external_exports.string().min(1)).optional(),
  selectedFiles: external_exports.array(external_exports.string().min(1)).optional()
});
var portabilityAdapterOverrideSchema = external_exports.object({
  adapterType: external_exports.string().min(1),
  adapterConfig: external_exports.record(external_exports.unknown()).optional()
});
var companyPortabilityImportSchema = companyPortabilityPreviewSchema.extend({
  adapterOverrides: external_exports.record(external_exports.string().min(1), portabilityAdapterOverrideSchema).optional()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/secret.js
var envBindingPlainSchema = external_exports.object({
  type: external_exports.literal("plain"),
  value: external_exports.string()
});
var envBindingSecretRefSchema = external_exports.object({
  type: external_exports.literal("secret_ref"),
  secretId: external_exports.string().uuid(),
  version: external_exports.union([external_exports.literal("latest"), external_exports.number().int().positive()]).optional()
});
var envBindingSchema = external_exports.union([
  external_exports.string(),
  envBindingPlainSchema,
  envBindingSecretRefSchema
]);
var envConfigSchema = external_exports.record(envBindingSchema);
var createSecretSchema = external_exports.object({
  name: external_exports.string().min(1),
  provider: external_exports.enum(SECRET_PROVIDERS).optional(),
  value: external_exports.string().min(1),
  description: external_exports.string().optional().nullable(),
  externalRef: external_exports.string().optional().nullable()
});
var rotateSecretSchema = external_exports.object({
  value: external_exports.string().min(1),
  externalRef: external_exports.string().optional().nullable()
});
var updateSecretSchema = external_exports.object({
  name: external_exports.string().min(1).optional(),
  description: external_exports.string().optional().nullable(),
  externalRef: external_exports.string().optional().nullable()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/agent.js
var agentPermissionsSchema = external_exports.object({
  canCreateAgents: external_exports.boolean().optional().default(false)
});
var agentInstructionsBundleModeSchema = external_exports.enum(["managed", "external"]);
var updateAgentInstructionsBundleSchema = external_exports.object({
  mode: agentInstructionsBundleModeSchema.optional(),
  rootPath: external_exports.string().trim().min(1).nullable().optional(),
  entryFile: external_exports.string().trim().min(1).optional(),
  clearLegacyPromptTemplate: external_exports.boolean().optional().default(false)
});
var upsertAgentInstructionsFileSchema = external_exports.object({
  path: external_exports.string().trim().min(1),
  content: external_exports.string(),
  clearLegacyPromptTemplate: external_exports.boolean().optional().default(false)
});
var adapterConfigSchema = external_exports.record(external_exports.unknown()).superRefine((value, ctx) => {
  const envValue = value.env;
  if (envValue === void 0)
    return;
  const parsed = envConfigSchema.safeParse(envValue);
  if (!parsed.success) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "adapterConfig.env must be a map of valid env bindings",
      path: ["env"]
    });
  }
});
var createAgentInstructionsBundleSchema = external_exports.object({
  entryFile: external_exports.string().trim().min(1).optional(),
  files: external_exports.record(external_exports.string()).refine((files) => Object.keys(files).length > 0, {
    message: "instructionsBundle.files must contain at least one file"
  })
});
var createAgentSchema = external_exports.object({
  name: external_exports.string().min(1),
  role: external_exports.enum(AGENT_ROLES).optional().default("general"),
  title: external_exports.string().optional().nullable(),
  icon: external_exports.enum(AGENT_ICON_NAMES).optional().nullable(),
  reportsTo: external_exports.string().uuid().optional().nullable(),
  capabilities: external_exports.string().optional().nullable(),
  desiredSkills: external_exports.array(external_exports.string().min(1)).optional(),
  adapterType: agentAdapterTypeSchema,
  adapterConfig: adapterConfigSchema.optional().default({}),
  instructionsBundle: createAgentInstructionsBundleSchema.optional(),
  runtimeConfig: external_exports.record(external_exports.unknown()).optional().default({}),
  defaultEnvironmentId: external_exports.string().uuid().optional().nullable(),
  budgetMonthlyCents: external_exports.number().int().nonnegative().optional().default(0),
  permissions: agentPermissionsSchema.optional(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
});
var createAgentHireSchema = createAgentSchema.extend({
  sourceIssueId: external_exports.string().uuid().optional().nullable(),
  sourceIssueIds: external_exports.array(external_exports.string().uuid()).optional()
});
var updateAgentSchema = createAgentSchema.omit({ permissions: true }).partial().extend({
  permissions: external_exports.never().optional(),
  replaceAdapterConfig: external_exports.boolean().optional(),
  status: external_exports.enum(AGENT_STATUSES).optional(),
  spentMonthlyCents: external_exports.number().int().nonnegative().optional()
});
var updateAgentInstructionsPathSchema = external_exports.object({
  path: external_exports.string().trim().min(1).nullable(),
  adapterConfigKey: external_exports.string().trim().min(1).optional()
});
var createAgentKeySchema = external_exports.object({
  name: external_exports.string().min(1).default("default")
});
var agentMineInboxQuerySchema = external_exports.object({
  userId: external_exports.string().trim().min(1),
  status: external_exports.string().trim().min(1).optional().default(INBOX_MINE_ISSUE_STATUS_FILTER)
});
var wakeAgentSchema = external_exports.object({
  source: external_exports.enum(["timer", "assignment", "on_demand", "automation"]).optional().default("on_demand"),
  triggerDetail: external_exports.enum(["manual", "ping", "callback", "system"]).optional(),
  reason: external_exports.string().optional().nullable(),
  payload: external_exports.record(external_exports.unknown()).optional().nullable(),
  idempotencyKey: external_exports.string().optional().nullable(),
  forceFreshSession: external_exports.preprocess((value) => value === null ? void 0 : value, external_exports.boolean().optional().default(false))
});
var resetAgentSessionSchema = external_exports.object({
  taskKey: external_exports.string().min(1).optional().nullable()
});
var testAdapterEnvironmentSchema = external_exports.object({
  adapterConfig: adapterConfigSchema.optional().default({})
});
var updateAgentPermissionsSchema = external_exports.object({
  canCreateAgents: external_exports.boolean(),
  canAssignTasks: external_exports.boolean()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/project.js
var executionWorkspaceStrategySchema2 = external_exports.object({
  type: external_exports.enum(["project_primary", "git_worktree", "adapter_managed", "cloud_sandbox"]).optional(),
  baseRef: external_exports.string().optional().nullable(),
  branchTemplate: external_exports.string().optional().nullable(),
  worktreeParentDir: external_exports.string().optional().nullable(),
  provisionCommand: external_exports.string().optional().nullable(),
  teardownCommand: external_exports.string().optional().nullable()
}).strict();
var projectExecutionWorkspacePolicySchema = external_exports.object({
  enabled: external_exports.boolean(),
  defaultMode: external_exports.enum(["shared_workspace", "isolated_workspace", "operator_branch", "adapter_default"]).optional(),
  allowIssueOverride: external_exports.boolean().optional(),
  defaultProjectWorkspaceId: external_exports.string().uuid().optional().nullable(),
  environmentId: external_exports.string().uuid().optional().nullable(),
  workspaceStrategy: executionWorkspaceStrategySchema2.optional().nullable(),
  workspaceRuntime: external_exports.record(external_exports.unknown()).optional().nullable(),
  branchPolicy: external_exports.record(external_exports.unknown()).optional().nullable(),
  pullRequestPolicy: external_exports.record(external_exports.unknown()).optional().nullable(),
  runtimePolicy: external_exports.record(external_exports.unknown()).optional().nullable(),
  cleanupPolicy: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();
var projectWorkspaceRuntimeConfigSchema = external_exports.object({
  workspaceRuntime: external_exports.record(external_exports.unknown()).optional().nullable(),
  desiredState: external_exports.enum(["running", "stopped", "manual"]).optional().nullable(),
  serviceStates: external_exports.record(external_exports.enum(["running", "stopped", "manual"])).optional().nullable()
}).strict();
var projectWorkspaceSourceTypeSchema = external_exports.enum(["local_path", "git_repo", "remote_managed", "non_git_path"]);
var projectWorkspaceVisibilitySchema = external_exports.enum(["default", "advanced"]);
var projectWorkspaceFields = {
  name: external_exports.string().min(1).optional(),
  sourceType: projectWorkspaceSourceTypeSchema.optional(),
  cwd: external_exports.string().min(1).optional().nullable(),
  repoUrl: external_exports.string().url().optional().nullable(),
  repoRef: external_exports.string().optional().nullable(),
  defaultRef: external_exports.string().optional().nullable(),
  visibility: projectWorkspaceVisibilitySchema.optional(),
  setupCommand: external_exports.string().optional().nullable(),
  cleanupCommand: external_exports.string().optional().nullable(),
  remoteProvider: external_exports.string().optional().nullable(),
  remoteWorkspaceRef: external_exports.string().optional().nullable(),
  sharedWorkspaceKey: external_exports.string().optional().nullable(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable(),
  runtimeConfig: projectWorkspaceRuntimeConfigSchema.optional().nullable()
};
function validateProjectWorkspace(value, ctx) {
  const sourceType = value.sourceType ?? "local_path";
  const hasCwd = typeof value.cwd === "string" && value.cwd.trim().length > 0;
  const hasRepo = typeof value.repoUrl === "string" && value.repoUrl.trim().length > 0;
  const hasRemoteRef = typeof value.remoteWorkspaceRef === "string" && value.remoteWorkspaceRef.trim().length > 0;
  if (sourceType === "remote_managed") {
    if (!hasRemoteRef && !hasRepo) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Remote-managed workspace requires remoteWorkspaceRef or repoUrl.",
        path: ["remoteWorkspaceRef"]
      });
    }
    return;
  }
  if (!hasCwd && !hasRepo) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "Workspace requires at least one of cwd or repoUrl.",
      path: ["cwd"]
    });
  }
}
var createProjectWorkspaceSchema = external_exports.object({
  ...projectWorkspaceFields,
  isPrimary: external_exports.boolean().optional().default(false)
}).superRefine(validateProjectWorkspace);
var updateProjectWorkspaceSchema = external_exports.object({
  ...projectWorkspaceFields,
  isPrimary: external_exports.boolean().optional()
}).partial();
var projectFields = {
  /** @deprecated Use goalIds instead */
  goalId: external_exports.string().uuid().optional().nullable(),
  goalIds: external_exports.array(external_exports.string().uuid()).optional(),
  name: external_exports.string().min(1),
  description: external_exports.string().optional().nullable(),
  status: external_exports.enum(PROJECT_STATUSES).optional().default("backlog"),
  leadAgentId: external_exports.string().uuid().optional().nullable(),
  targetDate: external_exports.string().optional().nullable(),
  color: external_exports.string().optional().nullable(),
  env: envConfigSchema.optional().nullable(),
  executionWorkspacePolicy: projectExecutionWorkspacePolicySchema.optional().nullable(),
  archivedAt: external_exports.string().datetime().optional().nullable()
};
var createProjectSchema = external_exports.object({
  ...projectFields,
  workspace: createProjectWorkspaceSchema.optional()
});
var updateProjectSchema = external_exports.object(projectFields).partial();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/issue-tree-control.js
var issueTreeControlModeSchema = external_exports.enum(ISSUE_TREE_CONTROL_MODES);
var issueTreeHoldReleasePolicySchema = external_exports.object({
  strategy: external_exports.enum(ISSUE_TREE_HOLD_RELEASE_POLICY_STRATEGIES).default("manual"),
  note: external_exports.string().trim().min(1).max(500).optional().nullable()
}).strict();
var previewIssueTreeControlSchema = external_exports.object({
  mode: issueTreeControlModeSchema,
  releasePolicy: issueTreeHoldReleasePolicySchema.optional().nullable()
}).strict();
var createIssueTreeHoldSchema = external_exports.object({
  mode: issueTreeControlModeSchema,
  reason: external_exports.string().trim().min(1).max(1e3).optional().nullable(),
  releasePolicy: issueTreeHoldReleasePolicySchema.optional().nullable(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();
var releaseIssueTreeHoldSchema = external_exports.object({
  reason: external_exports.string().trim().min(1).max(1e3).optional().nullable(),
  releasePolicy: issueTreeHoldReleasePolicySchema.optional().nullable(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable()
}).strict();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/work-product.js
var issueWorkProductTypeSchema = external_exports.enum([
  "preview_url",
  "runtime_service",
  "pull_request",
  "branch",
  "commit",
  "artifact",
  "document"
]);
var issueWorkProductStatusSchema = external_exports.enum([
  "active",
  "ready_for_review",
  "approved",
  "changes_requested",
  "merged",
  "closed",
  "failed",
  "archived",
  "draft"
]);
var issueWorkProductReviewStateSchema = external_exports.enum([
  "none",
  "needs_board_review",
  "approved",
  "changes_requested"
]);
var createIssueWorkProductSchema = external_exports.object({
  projectId: external_exports.string().uuid().optional().nullable(),
  executionWorkspaceId: external_exports.string().uuid().optional().nullable(),
  runtimeServiceId: external_exports.string().uuid().optional().nullable(),
  type: issueWorkProductTypeSchema,
  provider: external_exports.string().min(1),
  externalId: external_exports.string().optional().nullable(),
  title: external_exports.string().min(1),
  url: external_exports.string().url().optional().nullable(),
  status: issueWorkProductStatusSchema.default("active"),
  reviewState: issueWorkProductReviewStateSchema.optional().default("none"),
  isPrimary: external_exports.boolean().optional().default(false),
  healthStatus: external_exports.enum(["unknown", "healthy", "unhealthy"]).optional().default("unknown"),
  summary: external_exports.string().optional().nullable(),
  metadata: external_exports.record(external_exports.unknown()).optional().nullable(),
  createdByRunId: external_exports.string().uuid().optional().nullable()
});
var updateIssueWorkProductSchema = createIssueWorkProductSchema.partial();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/goal.js
var createGoalSchema = external_exports.object({
  title: external_exports.string().min(1),
  description: external_exports.string().optional().nullable(),
  level: external_exports.enum(GOAL_LEVELS).optional().default("task"),
  status: external_exports.enum(GOAL_STATUSES).optional().default("planned"),
  parentId: external_exports.string().uuid().optional().nullable(),
  ownerAgentId: external_exports.string().uuid().optional().nullable()
});
var updateGoalSchema = createGoalSchema.partial();

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/approval.js
var createApprovalSchema = external_exports.object({
  type: external_exports.enum(APPROVAL_TYPES),
  requestedByAgentId: external_exports.string().uuid().optional().nullable(),
  payload: external_exports.record(external_exports.unknown()),
  issueIds: external_exports.array(external_exports.string().uuid()).optional()
});
var resolveApprovalSchema = external_exports.object({
  decisionNote: multilineTextSchema.optional().nullable()
});
var requestApprovalRevisionSchema = external_exports.object({
  decisionNote: multilineTextSchema.optional().nullable()
});
var resubmitApprovalSchema = external_exports.object({
  payload: external_exports.record(external_exports.unknown()).optional()
});
var addApprovalCommentSchema = external_exports.object({
  body: multilineTextSchema.pipe(external_exports.string().min(1))
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/cost.js
var createCostEventSchema = external_exports.object({
  agentId: external_exports.string().uuid(),
  issueId: external_exports.string().uuid().optional().nullable(),
  projectId: external_exports.string().uuid().optional().nullable(),
  goalId: external_exports.string().uuid().optional().nullable(),
  heartbeatRunId: external_exports.string().uuid().optional().nullable(),
  billingCode: external_exports.string().optional().nullable(),
  provider: external_exports.string().min(1),
  biller: external_exports.string().min(1).optional(),
  billingType: external_exports.enum(BILLING_TYPES).optional().default("unknown"),
  model: external_exports.string().min(1),
  inputTokens: external_exports.number().int().nonnegative().optional().default(0),
  cachedInputTokens: external_exports.number().int().nonnegative().optional().default(0),
  outputTokens: external_exports.number().int().nonnegative().optional().default(0),
  costCents: external_exports.number().int().nonnegative(),
  occurredAt: external_exports.string().datetime()
}).transform((value) => ({
  ...value,
  biller: value.biller ?? value.provider
}));
var updateBudgetSchema = external_exports.object({
  budgetMonthlyCents: external_exports.number().int().nonnegative()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/finance.js
var createFinanceEventSchema = external_exports.object({
  agentId: external_exports.string().uuid().optional().nullable(),
  issueId: external_exports.string().uuid().optional().nullable(),
  projectId: external_exports.string().uuid().optional().nullable(),
  goalId: external_exports.string().uuid().optional().nullable(),
  heartbeatRunId: external_exports.string().uuid().optional().nullable(),
  costEventId: external_exports.string().uuid().optional().nullable(),
  billingCode: external_exports.string().optional().nullable(),
  description: external_exports.string().max(500).optional().nullable(),
  eventKind: external_exports.enum(FINANCE_EVENT_KINDS),
  direction: external_exports.enum(FINANCE_DIRECTIONS).optional().default("debit"),
  biller: external_exports.string().min(1),
  provider: external_exports.string().min(1).optional().nullable(),
  executionAdapterType: external_exports.enum(AGENT_ADAPTER_TYPES).optional().nullable(),
  pricingTier: external_exports.string().min(1).optional().nullable(),
  region: external_exports.string().min(1).optional().nullable(),
  model: external_exports.string().min(1).optional().nullable(),
  quantity: external_exports.number().int().nonnegative().optional().nullable(),
  unit: external_exports.enum(FINANCE_UNITS).optional().nullable(),
  amountCents: external_exports.number().int().nonnegative(),
  currency: external_exports.string().length(3).optional().default("USD"),
  estimated: external_exports.boolean().optional().default(false),
  externalInvoiceId: external_exports.string().optional().nullable(),
  metadataJson: external_exports.record(external_exports.string(), external_exports.unknown()).optional().nullable(),
  occurredAt: external_exports.string().datetime()
}).transform((value) => ({
  ...value,
  currency: value.currency.toUpperCase()
}));

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/asset.js
var createAssetImageMetadataSchema = external_exports.object({
  namespace: external_exports.string().trim().min(1).max(120).regex(/^[a-zA-Z0-9/_-]+$/).optional()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/access.js
var createCompanyInviteSchema = external_exports.object({
  allowedJoinTypes: external_exports.enum(INVITE_JOIN_TYPES).default("both"),
  humanRole: external_exports.enum(HUMAN_COMPANY_MEMBERSHIP_ROLES).optional().nullable(),
  defaultsPayload: external_exports.record(external_exports.string(), external_exports.unknown()).optional().nullable(),
  agentMessage: external_exports.string().max(4e3).optional().nullable()
});
var createOpenClawInvitePromptSchema = external_exports.object({
  agentMessage: external_exports.string().max(4e3).optional().nullable()
});
var acceptInviteSchema = external_exports.object({
  requestType: external_exports.enum(JOIN_REQUEST_TYPES),
  agentName: external_exports.string().min(1).max(120).optional(),
  adapterType: optionalAgentAdapterTypeSchema,
  capabilities: external_exports.string().max(4e3).optional().nullable(),
  agentDefaultsPayload: external_exports.record(external_exports.string(), external_exports.unknown()).optional().nullable(),
  // OpenClaw join compatibility fields accepted at top level.
  responsesWebhookUrl: external_exports.string().max(4e3).optional().nullable(),
  responsesWebhookMethod: external_exports.string().max(32).optional().nullable(),
  responsesWebhookHeaders: external_exports.record(external_exports.string(), external_exports.unknown()).optional().nullable(),
  paperclipApiUrl: external_exports.string().max(4e3).optional().nullable(),
  webhookAuthHeader: external_exports.string().max(4e3).optional().nullable()
});
var listJoinRequestsQuerySchema = external_exports.object({
  status: external_exports.enum(JOIN_REQUEST_STATUSES).optional(),
  requestType: external_exports.enum(JOIN_REQUEST_TYPES).optional()
});
var listCompanyInvitesQuerySchema = external_exports.object({
  state: external_exports.enum(["active", "revoked", "accepted", "expired"]).optional(),
  limit: external_exports.coerce.number().int().min(1).max(100).optional().default(20),
  offset: external_exports.coerce.number().int().min(0).optional().default(0)
});
var claimJoinRequestApiKeySchema = external_exports.object({
  claimSecret: external_exports.string().min(16).max(256)
});
var boardCliAuthAccessLevelSchema = external_exports.enum([
  "board",
  "instance_admin_required"
]);
var createCliAuthChallengeSchema = external_exports.object({
  command: external_exports.string().min(1).max(240),
  clientName: external_exports.string().max(120).optional().nullable(),
  requestedAccess: boardCliAuthAccessLevelSchema.default("board"),
  requestedCompanyId: external_exports.string().uuid().optional().nullable()
});
var resolveCliAuthChallengeSchema = external_exports.object({
  token: external_exports.string().min(16).max(256)
});
var updateMemberPermissionsSchema = external_exports.object({
  grants: external_exports.array(external_exports.object({
    permissionKey: external_exports.enum(PERMISSION_KEYS),
    scope: external_exports.record(external_exports.string(), external_exports.unknown()).optional().nullable()
  }))
});
var editableMembershipStatuses = ["pending", "active", "suspended"];
var updateCompanyMemberSchema = external_exports.object({
  membershipRole: external_exports.enum(HUMAN_COMPANY_MEMBERSHIP_ROLES).optional().nullable(),
  status: external_exports.enum(editableMembershipStatuses).optional()
}).refine((value) => value.membershipRole !== void 0 || value.status !== void 0, {
  message: "membershipRole or status is required"
});
var updateCompanyMemberWithPermissionsSchema = external_exports.object({
  membershipRole: external_exports.enum(HUMAN_COMPANY_MEMBERSHIP_ROLES).optional().nullable(),
  status: external_exports.enum(editableMembershipStatuses).optional(),
  grants: updateMemberPermissionsSchema.shape.grants.default([])
}).refine((value) => value.membershipRole !== void 0 || value.status !== void 0, {
  message: "membershipRole or status is required"
});
var archiveCompanyMemberSchema = external_exports.object({
  reassignment: external_exports.object({
    assigneeAgentId: external_exports.string().uuid().optional().nullable(),
    assigneeUserId: external_exports.string().uuid().optional().nullable()
  }).optional().nullable()
}).superRefine((value, ctx) => {
  if (value.reassignment?.assigneeAgentId && value.reassignment.assigneeUserId) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "Choose either an agent or user reassignment target",
      path: ["reassignment"]
    });
  }
});
var updateUserCompanyAccessSchema = external_exports.object({
  companyIds: external_exports.array(external_exports.string().uuid()).default([])
});
var searchAdminUsersQuerySchema = external_exports.object({
  query: external_exports.string().trim().max(120).optional().default("")
});
var profileImageAssetPathPattern = /^\/api\/assets\/[^/?#]+\/content(?:\?[^#]*)?(?:#.*)?$/;
function isValidProfileImage(value) {
  if (profileImageAssetPathPattern.test(value))
    return true;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}
var profileImageSchema = external_exports.string().trim().min(1).max(4e3).refine(isValidProfileImage, { message: "Invalid profile image URL" });
var currentUserProfileSchema = external_exports.object({
  id: external_exports.string().min(1),
  email: external_exports.string().email().nullable(),
  name: external_exports.string().min(1).max(120).nullable(),
  image: profileImageSchema.nullable()
});
var authSessionSchema = external_exports.object({
  session: external_exports.object({
    id: external_exports.string().min(1),
    userId: external_exports.string().min(1)
  }),
  user: currentUserProfileSchema
});
var updateCurrentUserProfileSchema = external_exports.object({
  name: external_exports.string().trim().min(1).max(120),
  image: external_exports.union([profileImageSchema, external_exports.literal(""), external_exports.null()]).optional().transform((value) => value === "" ? null : value)
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/validators/plugin.js
var jsonSchemaSchema = external_exports.record(external_exports.unknown()).refine((val) => {
  if (Object.keys(val).length === 0)
    return true;
  return typeof val.type === "string" || val.$ref !== void 0 || val.oneOf !== void 0 || val.anyOf !== void 0 || val.allOf !== void 0;
}, { message: "Must be a valid JSON Schema object (requires at least a 'type', '$ref', or composition keyword)" });
var CRON_FIELD_PATTERN = /^(\*(?:\/[0-9]+)?|[0-9]+(?:-[0-9]+)?(?:\/[0-9]+)?)(?:,(\*(?:\/[0-9]+)?|[0-9]+(?:-[0-9]+)?(?:\/[0-9]+)?))*$/;
function isValidCronExpression(expression) {
  const trimmed = expression.trim();
  if (!trimmed)
    return false;
  const fields = trimmed.split(/\s+/);
  if (fields.length !== 5)
    return false;
  return fields.every((f) => CRON_FIELD_PATTERN.test(f));
}
var pluginJobDeclarationSchema = external_exports.object({
  jobKey: external_exports.string().min(1),
  displayName: external_exports.string().min(1),
  description: external_exports.string().optional(),
  schedule: external_exports.string().refine((val) => isValidCronExpression(val), { message: "schedule must be a valid 5-field cron expression (e.g. '*/15 * * * *')" }).optional()
});
var pluginWebhookDeclarationSchema = external_exports.object({
  endpointKey: external_exports.string().min(1),
  displayName: external_exports.string().min(1),
  description: external_exports.string().optional()
});
var pluginToolDeclarationSchema = external_exports.object({
  name: external_exports.string().min(1),
  displayName: external_exports.string().min(1),
  description: external_exports.string().min(1),
  parametersSchema: jsonSchemaSchema
});
var pluginEnvironmentDriverDeclarationSchema = external_exports.object({
  driverKey: external_exports.string().min(1).regex(/^[a-z0-9][a-z0-9._-]*$/, "Environment driver key must start with a lowercase alphanumeric and contain only lowercase letters, digits, dots, hyphens, or underscores"),
  kind: external_exports.enum(["environment_driver", "sandbox_provider"]).optional(),
  displayName: external_exports.string().min(1).max(100),
  description: external_exports.string().max(500).optional(),
  configSchema: jsonSchemaSchema
});
var pluginUiSlotDeclarationSchema = external_exports.object({
  type: external_exports.enum(PLUGIN_UI_SLOT_TYPES),
  id: external_exports.string().min(1),
  displayName: external_exports.string().min(1),
  exportName: external_exports.string().min(1),
  entityTypes: external_exports.array(external_exports.enum(PLUGIN_UI_SLOT_ENTITY_TYPES)).optional(),
  routePath: external_exports.string().regex(/^[a-z0-9][a-z0-9-]*$/, {
    message: "routePath must be a lowercase single-segment slug (letters, numbers, hyphens)"
  }).optional(),
  order: external_exports.number().int().optional()
}).superRefine((value, ctx) => {
  const entityScopedTypes = ["detailTab", "taskDetailView", "contextMenuItem", "commentAnnotation", "commentContextMenuItem", "projectSidebarItem"];
  if (entityScopedTypes.includes(value.type) && (!value.entityTypes || value.entityTypes.length === 0)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: `${value.type} slots require at least one entityType`,
      path: ["entityTypes"]
    });
  }
  if (value.type === "projectSidebarItem" && value.entityTypes && !value.entityTypes.includes("project")) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: 'projectSidebarItem slots require entityTypes to include "project"',
      path: ["entityTypes"]
    });
  }
  if (value.type === "commentAnnotation" && value.entityTypes && !value.entityTypes.includes("comment")) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: 'commentAnnotation slots require entityTypes to include "comment"',
      path: ["entityTypes"]
    });
  }
  if (value.type === "commentContextMenuItem" && value.entityTypes && !value.entityTypes.includes("comment")) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: 'commentContextMenuItem slots require entityTypes to include "comment"',
      path: ["entityTypes"]
    });
  }
  if (value.routePath && value.type !== "page") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "routePath is only supported for page slots",
      path: ["routePath"]
    });
  }
  if (value.routePath && PLUGIN_RESERVED_COMPANY_ROUTE_SEGMENTS.includes(value.routePath)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: `routePath "${value.routePath}" is reserved by the host`,
      path: ["routePath"]
    });
  }
});
var entityScopedLauncherPlacementZones = [
  "detailTab",
  "taskDetailView",
  "contextMenuItem",
  "commentAnnotation",
  "commentContextMenuItem",
  "projectSidebarItem"
];
var launcherBoundsByEnvironment = {
  hostInline: ["inline", "compact", "default"],
  hostOverlay: ["compact", "default", "wide", "full"],
  hostRoute: ["default", "wide", "full"],
  external: [],
  iframe: ["compact", "default", "wide", "full"]
};
var pluginLauncherActionDeclarationSchema = external_exports.object({
  type: external_exports.enum(PLUGIN_LAUNCHER_ACTIONS),
  target: external_exports.string().min(1),
  params: external_exports.record(external_exports.unknown()).optional()
}).superRefine((value, ctx) => {
  if (value.type === "performAction" && value.target.includes("/")) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "performAction launchers must target an action key, not a route or URL",
      path: ["target"]
    });
  }
  if (value.type === "navigate" && /^https?:\/\//.test(value.target)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "navigate launchers must target a host route, not an absolute URL",
      path: ["target"]
    });
  }
});
var pluginLauncherRenderDeclarationSchema = external_exports.object({
  environment: external_exports.enum(PLUGIN_LAUNCHER_RENDER_ENVIRONMENTS),
  bounds: external_exports.enum(PLUGIN_LAUNCHER_BOUNDS).optional()
}).superRefine((value, ctx) => {
  if (!value.bounds) {
    return;
  }
  const supportedBounds = launcherBoundsByEnvironment[value.environment];
  if (!supportedBounds.includes(value.bounds)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: `bounds "${value.bounds}" is not supported for render environment "${value.environment}"`,
      path: ["bounds"]
    });
  }
});
var pluginLauncherDeclarationSchema = external_exports.object({
  id: external_exports.string().min(1),
  displayName: external_exports.string().min(1),
  description: external_exports.string().optional(),
  placementZone: external_exports.enum(PLUGIN_LAUNCHER_PLACEMENT_ZONES),
  exportName: external_exports.string().min(1).optional(),
  entityTypes: external_exports.array(external_exports.enum(PLUGIN_UI_SLOT_ENTITY_TYPES)).optional(),
  order: external_exports.number().int().optional(),
  action: pluginLauncherActionDeclarationSchema,
  render: pluginLauncherRenderDeclarationSchema.optional()
}).superRefine((value, ctx) => {
  if (entityScopedLauncherPlacementZones.some((zone) => zone === value.placementZone) && (!value.entityTypes || value.entityTypes.length === 0)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: `${value.placementZone} launchers require at least one entityType`,
      path: ["entityTypes"]
    });
  }
  if (value.placementZone === "projectSidebarItem" && value.entityTypes && !value.entityTypes.includes("project")) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: 'projectSidebarItem launchers require entityTypes to include "project"',
      path: ["entityTypes"]
    });
  }
  if (value.action.type === "performAction" && value.render) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "performAction launchers cannot declare render hints",
      path: ["render"]
    });
  }
  if (["openModal", "openDrawer", "openPopover"].includes(value.action.type) && !value.render) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: `${value.action.type} launchers require render metadata`,
      path: ["render"]
    });
  }
  if (value.action.type === "openModal" && value.render?.environment === "hostInline") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "openModal launchers cannot use the hostInline render environment",
      path: ["render", "environment"]
    });
  }
  if (value.action.type === "openDrawer" && value.render && !["hostOverlay", "iframe"].includes(value.render.environment)) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "openDrawer launchers must use hostOverlay or iframe render environments",
      path: ["render", "environment"]
    });
  }
  if (value.action.type === "openPopover" && value.render?.environment === "hostRoute") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "openPopover launchers cannot use the hostRoute render environment",
      path: ["render", "environment"]
    });
  }
});
var pluginDatabaseDeclarationSchema = external_exports.object({
  namespaceSlug: external_exports.string().regex(/^[a-z0-9][a-z0-9_]*$/, {
    message: "namespaceSlug must be lowercase letters, digits, or underscores and start with a letter or digit"
  }).max(40).optional(),
  migrationsDir: external_exports.string().min(1).refine((value) => !value.startsWith("/") && !value.includes("..") && !/[\\]/.test(value), { message: "migrationsDir must be a relative package path without '..' or backslashes" }),
  coreReadTables: external_exports.array(external_exports.enum(PLUGIN_DATABASE_CORE_READ_TABLES)).optional()
});
var pluginApiRouteDeclarationSchema = external_exports.object({
  routeKey: external_exports.string().min(1).max(100).regex(/^[a-z0-9][a-z0-9._:-]*$/, {
    message: "routeKey must be lowercase letters, digits, dots, colons, underscores, or hyphens"
  }),
  method: external_exports.enum(PLUGIN_API_ROUTE_METHODS),
  path: external_exports.string().min(1).regex(/^\/[a-zA-Z0-9:_./-]*$/, {
    message: "path must start with / and contain only path-safe literal or :param segments"
  }).refine((value) => !value.includes("..") && !value.includes("//") && value !== "/api" && !value.startsWith("/api/") && value !== "/plugins" && !value.startsWith("/plugins/"), { message: "path must stay inside the plugin api namespace" }),
  auth: external_exports.enum(PLUGIN_API_ROUTE_AUTH_MODES),
  capability: external_exports.literal("api.routes.register"),
  checkoutPolicy: external_exports.enum(PLUGIN_API_ROUTE_CHECKOUT_POLICIES).optional(),
  companyResolution: external_exports.discriminatedUnion("from", [
    external_exports.object({ from: external_exports.literal("body"), key: external_exports.string().min(1) }),
    external_exports.object({ from: external_exports.literal("query"), key: external_exports.string().min(1) }),
    external_exports.object({ from: external_exports.literal("issue"), param: external_exports.string().min(1) })
  ]).optional()
});
var pluginManifestV1Schema = external_exports.object({
  id: external_exports.string().min(1).regex(/^[a-z0-9][a-z0-9._-]*$/, "Plugin id must start with a lowercase alphanumeric and contain only lowercase letters, digits, dots, hyphens, or underscores"),
  apiVersion: external_exports.literal(1),
  version: external_exports.string().min(1).regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/, "Version must follow semver (e.g. 1.0.0 or 1.0.0-beta.1)"),
  displayName: external_exports.string().min(1).max(100),
  description: external_exports.string().min(1).max(500),
  author: external_exports.string().min(1).max(200),
  categories: external_exports.array(external_exports.enum(PLUGIN_CATEGORIES)).min(1),
  minimumHostVersion: external_exports.string().regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/, "minimumHostVersion must follow semver (e.g. 1.0.0)").optional(),
  minimumPaperclipVersion: external_exports.string().regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/, "minimumPaperclipVersion must follow semver (e.g. 1.0.0)").optional(),
  capabilities: external_exports.array(external_exports.enum(PLUGIN_CAPABILITIES)).min(1),
  entrypoints: external_exports.object({
    worker: external_exports.string().min(1),
    ui: external_exports.string().min(1).optional()
  }),
  instanceConfigSchema: jsonSchemaSchema.optional(),
  jobs: external_exports.array(pluginJobDeclarationSchema).optional(),
  webhooks: external_exports.array(pluginWebhookDeclarationSchema).optional(),
  tools: external_exports.array(pluginToolDeclarationSchema).optional(),
  database: pluginDatabaseDeclarationSchema.optional(),
  apiRoutes: external_exports.array(pluginApiRouteDeclarationSchema).optional(),
  environmentDrivers: external_exports.array(pluginEnvironmentDriverDeclarationSchema).optional(),
  launchers: external_exports.array(pluginLauncherDeclarationSchema).optional(),
  ui: external_exports.object({
    slots: external_exports.array(pluginUiSlotDeclarationSchema).min(1).optional(),
    launchers: external_exports.array(pluginLauncherDeclarationSchema).optional()
  }).optional()
}).superRefine((manifest, ctx) => {
  const hasUiSlots = (manifest.ui?.slots?.length ?? 0) > 0;
  const hasUiLaunchers = (manifest.ui?.launchers?.length ?? 0) > 0;
  if ((hasUiSlots || hasUiLaunchers) && !manifest.entrypoints.ui) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "entrypoints.ui is required when ui.slots or ui.launchers are declared",
      path: ["entrypoints", "ui"]
    });
  }
  if (manifest.minimumHostVersion && manifest.minimumPaperclipVersion && manifest.minimumHostVersion !== manifest.minimumPaperclipVersion) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "minimumHostVersion and minimumPaperclipVersion must match when both are declared",
      path: ["minimumHostVersion"]
    });
  }
  if (manifest.tools && manifest.tools.length > 0) {
    if (!manifest.capabilities.includes("agent.tools.register")) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Capability 'agent.tools.register' is required when tools are declared",
        path: ["capabilities"]
      });
    }
  }
  if (manifest.environmentDrivers && manifest.environmentDrivers.length > 0) {
    if (!manifest.capabilities.includes("environment.drivers.register")) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Capability 'environment.drivers.register' is required when environmentDrivers are declared",
        path: ["capabilities"]
      });
    }
  }
  if (manifest.jobs && manifest.jobs.length > 0) {
    if (!manifest.capabilities.includes("jobs.schedule")) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Capability 'jobs.schedule' is required when jobs are declared",
        path: ["capabilities"]
      });
    }
  }
  if (manifest.webhooks && manifest.webhooks.length > 0) {
    if (!manifest.capabilities.includes("webhooks.receive")) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Capability 'webhooks.receive' is required when webhooks are declared",
        path: ["capabilities"]
      });
    }
  }
  if (manifest.apiRoutes && manifest.apiRoutes.length > 0) {
    if (!manifest.capabilities.includes("api.routes.register")) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: "Capability 'api.routes.register' is required when apiRoutes are declared",
        path: ["capabilities"]
      });
    }
  }
  if (manifest.database) {
    const requiredCapabilities = [
      "database.namespace.migrate",
      "database.namespace.read"
    ];
    for (const capability of requiredCapabilities) {
      if (!manifest.capabilities.includes(capability)) {
        ctx.addIssue({
          code: external_exports.ZodIssueCode.custom,
          message: `Capability '${capability}' is required when database migrations are declared`,
          path: ["capabilities"]
        });
      }
    }
    const coreReadTables = manifest.database.coreReadTables ?? [];
    const duplicates = coreReadTables.filter((table, i) => coreReadTables.indexOf(table) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate database coreReadTables: ${[...new Set(duplicates)].join(", ")}`,
        path: ["database", "coreReadTables"]
      });
    }
  }
  if (manifest.jobs) {
    const jobKeys = manifest.jobs.map((j) => j.jobKey);
    const duplicates = jobKeys.filter((key, i) => jobKeys.indexOf(key) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate job keys: ${[...new Set(duplicates)].join(", ")}`,
        path: ["jobs"]
      });
    }
  }
  if (manifest.webhooks) {
    const endpointKeys = manifest.webhooks.map((w) => w.endpointKey);
    const duplicates = endpointKeys.filter((key, i) => endpointKeys.indexOf(key) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate webhook endpoint keys: ${[...new Set(duplicates)].join(", ")}`,
        path: ["webhooks"]
      });
    }
  }
  if (manifest.apiRoutes) {
    const routeKeys = manifest.apiRoutes.map((route) => route.routeKey);
    const duplicateKeys = routeKeys.filter((key, i) => routeKeys.indexOf(key) !== i);
    if (duplicateKeys.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate api route keys: ${[...new Set(duplicateKeys)].join(", ")}`,
        path: ["apiRoutes"]
      });
    }
    const routeSignatures = manifest.apiRoutes.map((route) => `${route.method} ${route.path}`);
    const duplicateRoutes = routeSignatures.filter((sig, i) => routeSignatures.indexOf(sig) !== i);
    if (duplicateRoutes.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate api routes: ${[...new Set(duplicateRoutes)].join(", ")}`,
        path: ["apiRoutes"]
      });
    }
  }
  if (manifest.tools) {
    const toolNames = manifest.tools.map((t) => t.name);
    const duplicates = toolNames.filter((name, i) => toolNames.indexOf(name) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate tool names: ${[...new Set(duplicates)].join(", ")}`,
        path: ["tools"]
      });
    }
  }
  if (manifest.environmentDrivers) {
    const driverKeys = manifest.environmentDrivers.map((d) => d.driverKey);
    const duplicates = driverKeys.filter((key, i) => driverKeys.indexOf(key) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate environment driver keys: ${[...new Set(duplicates)].join(", ")}`,
        path: ["environmentDrivers"]
      });
    }
  }
  if (manifest.ui) {
    if (manifest.ui.slots) {
      const slotIds = manifest.ui.slots.map((s) => s.id);
      const duplicates = slotIds.filter((id, i) => slotIds.indexOf(id) !== i);
      if (duplicates.length > 0) {
        ctx.addIssue({
          code: external_exports.ZodIssueCode.custom,
          message: `Duplicate UI slot ids: ${[...new Set(duplicates)].join(", ")}`,
          path: ["ui", "slots"]
        });
      }
    }
  }
  const allLaunchers = [
    ...manifest.launchers ?? [],
    ...manifest.ui?.launchers ?? []
  ];
  if (allLaunchers.length > 0) {
    const launcherIds = allLaunchers.map((launcher) => launcher.id);
    const duplicates = launcherIds.filter((id, i) => launcherIds.indexOf(id) !== i);
    if (duplicates.length > 0) {
      ctx.addIssue({
        code: external_exports.ZodIssueCode.custom,
        message: `Duplicate launcher ids: ${[...new Set(duplicates)].join(", ")}`,
        path: manifest.ui?.launchers ? ["ui", "launchers"] : ["launchers"]
      });
    }
  }
});
var installPluginSchema = external_exports.object({
  packageName: external_exports.string().min(1),
  version: external_exports.string().min(1).optional(),
  /** Set by loader for local-path installs so the worker can be resolved. */
  packagePath: external_exports.string().min(1).optional()
});
var upsertPluginConfigSchema = external_exports.object({
  configJson: external_exports.record(external_exports.unknown())
});
var patchPluginConfigSchema = external_exports.object({
  configJson: external_exports.record(external_exports.unknown())
});
var updatePluginStatusSchema = external_exports.object({
  status: external_exports.enum(PLUGIN_STATUSES),
  lastError: external_exports.string().nullable().optional()
});
var uninstallPluginSchema = external_exports.object({
  removeData: external_exports.boolean().optional().default(false)
});
var pluginStateScopeKeySchema = external_exports.object({
  scopeKind: external_exports.enum(PLUGIN_STATE_SCOPE_KINDS),
  scopeId: external_exports.string().min(1).optional(),
  namespace: external_exports.string().min(1).optional(),
  stateKey: external_exports.string().min(1)
});
var setPluginStateSchema = external_exports.object({
  scopeKind: external_exports.enum(PLUGIN_STATE_SCOPE_KINDS),
  scopeId: external_exports.string().min(1).optional(),
  namespace: external_exports.string().min(1).optional(),
  stateKey: external_exports.string().min(1),
  /** JSON-serializable value to store. */
  value: external_exports.unknown()
});
var listPluginStateSchema = external_exports.object({
  scopeKind: external_exports.enum(PLUGIN_STATE_SCOPE_KINDS).optional(),
  scopeId: external_exports.string().min(1).optional(),
  namespace: external_exports.string().min(1).optional()
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/api.js
var API_PREFIX = "/api";
var API = {
  health: `${API_PREFIX}/health`,
  companies: `${API_PREFIX}/companies`,
  agents: `${API_PREFIX}/agents`,
  projects: `${API_PREFIX}/projects`,
  issues: `${API_PREFIX}/issues`,
  issueTreeControl: `${API_PREFIX}/issues/:issueId/tree-control`,
  issueTreeHolds: `${API_PREFIX}/issues/:issueId/tree-holds`,
  goals: `${API_PREFIX}/goals`,
  approvals: `${API_PREFIX}/approvals`,
  secrets: `${API_PREFIX}/secrets`,
  costs: `${API_PREFIX}/costs`,
  activity: `${API_PREFIX}/activity`,
  dashboard: `${API_PREFIX}/dashboard`,
  sidebarBadges: `${API_PREFIX}/sidebar-badges`,
  sidebarPreferences: `${API_PREFIX}/sidebar-preferences`,
  invites: `${API_PREFIX}/invites`,
  joinRequests: `${API_PREFIX}/join-requests`,
  members: `${API_PREFIX}/members`,
  admin: `${API_PREFIX}/admin`
};

// ../pla748-cad/node_modules/@paperclipai/shared/dist/routine-variables.js
var HUMAN_TIMESTAMP_FORMATTER = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "long",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
  hour12: true,
  timeZone: "UTC",
  timeZoneName: "short"
});

// ../pla748-cad/node_modules/@paperclipai/shared/dist/config-schema.js
var configMetaSchema = external_exports.object({
  version: external_exports.literal(1),
  updatedAt: external_exports.string(),
  source: external_exports.enum(["onboard", "configure", "doctor"])
});
var llmConfigSchema = external_exports.object({
  provider: external_exports.enum(["claude", "openai"]),
  apiKey: external_exports.string().optional()
});
var databaseBackupConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  intervalMinutes: external_exports.number().int().min(1).max(7 * 24 * 60).default(60),
  retentionDays: external_exports.number().int().min(1).max(3650).default(7),
  dir: external_exports.string().default("~/.paperclip/instances/default/data/backups")
});
var databaseConfigSchema = external_exports.object({
  mode: external_exports.enum(["embedded-postgres", "postgres"]).default("embedded-postgres"),
  connectionString: external_exports.string().optional(),
  embeddedPostgresDataDir: external_exports.string().default("~/.paperclip/instances/default/db"),
  embeddedPostgresPort: external_exports.number().int().min(1).max(65535).default(54329),
  backup: databaseBackupConfigSchema.default({
    enabled: true,
    intervalMinutes: 60,
    retentionDays: 7,
    dir: "~/.paperclip/instances/default/data/backups"
  })
});
var loggingConfigSchema = external_exports.object({
  mode: external_exports.enum(["file", "cloud"]),
  logDir: external_exports.string().default("~/.paperclip/instances/default/logs")
});
var serverConfigSchema = external_exports.object({
  deploymentMode: external_exports.enum(DEPLOYMENT_MODES).default("local_trusted"),
  exposure: external_exports.enum(DEPLOYMENT_EXPOSURES).default("private"),
  bind: external_exports.enum(BIND_MODES).optional(),
  customBindHost: external_exports.string().optional(),
  host: external_exports.string().default("127.0.0.1"),
  port: external_exports.number().int().min(1).max(65535).default(3100),
  allowedHostnames: external_exports.array(external_exports.string().min(1)).default([]),
  serveUi: external_exports.boolean().default(true)
});
var authConfigSchema = external_exports.object({
  baseUrlMode: external_exports.enum(AUTH_BASE_URL_MODES).default("auto"),
  publicBaseUrl: external_exports.string().url().optional(),
  disableSignUp: external_exports.boolean().default(false)
});
var storageLocalDiskConfigSchema = external_exports.object({
  baseDir: external_exports.string().default("~/.paperclip/instances/default/data/storage")
});
var storageS3ConfigSchema = external_exports.object({
  bucket: external_exports.string().min(1).default("paperclip"),
  region: external_exports.string().min(1).default("us-east-1"),
  endpoint: external_exports.string().optional(),
  prefix: external_exports.string().default(""),
  forcePathStyle: external_exports.boolean().default(false)
});
var storageConfigSchema = external_exports.object({
  provider: external_exports.enum(STORAGE_PROVIDERS).default("local_disk"),
  localDisk: storageLocalDiskConfigSchema.default({
    baseDir: "~/.paperclip/instances/default/data/storage"
  }),
  s3: storageS3ConfigSchema.default({
    bucket: "paperclip",
    region: "us-east-1",
    prefix: "",
    forcePathStyle: false
  })
});
var secretsLocalEncryptedConfigSchema = external_exports.object({
  keyFilePath: external_exports.string().default("~/.paperclip/instances/default/secrets/master.key")
});
var secretsConfigSchema = external_exports.object({
  provider: external_exports.enum(SECRET_PROVIDERS).default("local_encrypted"),
  strictMode: external_exports.boolean().default(false),
  localEncrypted: secretsLocalEncryptedConfigSchema.default({
    keyFilePath: "~/.paperclip/instances/default/secrets/master.key"
  })
});
var telemetryConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true)
}).default({});
var paperclipConfigSchema = external_exports.object({
  $meta: configMetaSchema,
  llm: llmConfigSchema.optional(),
  database: databaseConfigSchema,
  logging: loggingConfigSchema,
  server: serverConfigSchema,
  telemetry: telemetryConfigSchema,
  auth: authConfigSchema.default({
    baseUrlMode: "auto",
    disableSignUp: false
  }),
  storage: storageConfigSchema.default({
    provider: "local_disk",
    localDisk: {
      baseDir: "~/.paperclip/instances/default/data/storage"
    },
    s3: {
      bucket: "paperclip",
      region: "us-east-1",
      prefix: "",
      forcePathStyle: false
    }
  }),
  secrets: secretsConfigSchema.default({
    provider: "local_encrypted",
    strictMode: false,
    localEncrypted: {
      keyFilePath: "~/.paperclip/instances/default/secrets/master.key"
    }
  })
}).superRefine((value, ctx) => {
  if (value.server.deploymentMode === "local_trusted" && value.server.exposure !== "private") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "server.exposure must be private when deploymentMode is local_trusted",
      path: ["server", "exposure"]
    });
  }
  for (const message of validateConfiguredBindMode({
    deploymentMode: value.server.deploymentMode,
    deploymentExposure: value.server.exposure,
    bind: value.server.bind,
    host: value.server.host,
    customBindHost: value.server.customBindHost
  })) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message,
      path: message.includes("customBindHost") ? ["server", "customBindHost"] : ["server", "bind"]
    });
  }
  if (value.auth.baseUrlMode === "explicit" && !value.auth.publicBaseUrl) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "auth.publicBaseUrl is required when auth.baseUrlMode is explicit",
      path: ["auth", "publicBaseUrl"]
    });
  }
  if (value.server.exposure === "public" && value.auth.baseUrlMode !== "explicit") {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "auth.baseUrlMode must be explicit when deploymentMode=authenticated and exposure=public",
      path: ["auth", "baseUrlMode"]
    });
  }
  if (value.server.exposure === "public" && !value.auth.publicBaseUrl) {
    ctx.addIssue({
      code: external_exports.ZodIssueCode.custom,
      message: "auth.publicBaseUrl is required when deploymentMode=authenticated and exposure=public",
      path: ["auth", "publicBaseUrl"]
    });
  }
});

// src/worker.ts
import * as path3 from "node:path";

// src/cad-worker-client.ts
import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { existsSync, readFileSync, statSync } from "node:fs";
import { tmpdir as tmpdir2 } from "node:os";
import { join as join3, dirname } from "node:path";
import { fileURLToPath as fileURLToPath2 } from "node:url";
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";

// src/manifest.ts
var SECCOMP_FILTER_SHA256_PIN = "__PLA114_SECCOMP_FILTER_SHA256__";
var SECCOMP_LOADER_SHA256_PIN = "0fc1b58d38895fb2dc7be1464b1230344530aa7f168af9478fa47153e20f8be0";

// src/cad-intake.ts
import * as path2 from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
var MAX_INPUT_FILE_BYTES = 50 * 1024 * 1024;
var MAX_INPUT_FILES = 3;
var MAX_TOTAL_INPUT_BYTES = 120 * 1024 * 1024;
var MAX_REPO_PATH_LEN = 512;
var DEFAULT_INTAKE_CAPS = {
  maxFileBytes: MAX_INPUT_FILE_BYTES,
  maxTotalBytes: MAX_TOTAL_INPUT_BYTES
};
var INTAKE_ALLOWED_PREFIXES = ["user-uploads/", "artifacts/"];
var IntakeError = class extends Error {
  kind;
  httpStatus;
  constructor(kind, message, httpStatus) {
    super(message);
    this.name = "IntakeError";
    this.kind = kind;
    this.httpStatus = httpStatus;
  }
};
var BASENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
function assertSafeIntakePath(repoPath) {
  if (typeof repoPath !== "string" || repoPath.length === 0) {
    return "repoPath must be a non-empty string";
  }
  if (repoPath.length > MAX_REPO_PATH_LEN) {
    return `repoPath exceeds ${MAX_REPO_PATH_LEN} characters`;
  }
  if (repoPath.includes("\0")) return "repoPath must not contain NUL";
  if (repoPath.includes("\\")) return "repoPath must use forward slashes ('/'), not backslashes";
  if (repoPath.startsWith("/")) return "repoPath must be relative (no leading '/')";
  if (repoPath.endsWith("/")) return "repoPath must reference a file, not a directory (no trailing '/')";
  const normalized = path2.posix.normalize(repoPath);
  if (normalized !== repoPath) {
    return "repoPath would normalize differently (path traversal blocked)";
  }
  if (repoPath.split("/").some((seg) => seg === "..")) {
    return "repoPath must not contain '..' segments";
  }
  if (!INTAKE_ALLOWED_PREFIXES.some((p) => normalized.startsWith(p))) {
    return `repoPath must be under one of: ${INTAKE_ALLOWED_PREFIXES.join(", ")}`;
  }
  const base = path2.posix.basename(normalized);
  if (!base || base === "." || base === "..") {
    return "repoPath must reference a file, not a directory";
  }
  if (!BASENAME_RE.test(base)) {
    return "repoPath basename has disallowed characters (allowed: A-Za-z0-9._-, no leading dot)";
  }
  return null;
}
function parseInputArtifacts(raw) {
  if (raw === void 0 || raw === null) return { repoPaths: [] };
  if (!Array.isArray(raw)) return { error: "inputArtifacts must be an array" };
  if (raw.length === 0) return { repoPaths: [] };
  if (raw.length > MAX_INPUT_FILES) {
    return { error: `inputArtifacts may contain at most ${MAX_INPUT_FILES} files` };
  }
  const repoPaths = [];
  const seenBasenames = /* @__PURE__ */ new Set();
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i];
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return { error: `inputArtifacts[${i}] must be an object { repoPath }` };
    }
    const keys = Object.keys(item);
    if (keys.some((k) => k !== "repoPath")) {
      return { error: `inputArtifacts[${i}] has unexpected keys (only 'repoPath' allowed)` };
    }
    const repoPath = item.repoPath;
    const err = assertSafeIntakePath(repoPath);
    if (err) return { error: `inputArtifacts[${i}].${err}` };
    const base = path2.posix.basename(repoPath);
    if (seenBasenames.has(base)) {
      return { error: `inputArtifacts[${i}] basename '${base}' collides with an earlier entry` };
    }
    seenBasenames.add(base);
    repoPaths.push(repoPath);
  }
  return { repoPaths };
}
function parseGitHubUrl(repoUrl) {
  let u;
  try {
    u = new URL(repoUrl);
  } catch {
    throw new IntakeError("prerequisite_missing", `Cannot parse artifact repo URL: ${repoUrl}`);
  }
  if (u.protocol !== "https:" || u.host !== "github.com") {
    throw new IntakeError(
      "prerequisite_missing",
      `artifactRepoUrl must be an https://github.com/<owner>/<repo>(.git) URL. Got: ${repoUrl}`
    );
  }
  const segs = u.pathname.replace(/^\/+/, "").replace(/\.git\/?$/, "").replace(/\/+$/, "").split("/");
  if (segs.length !== 2 || !segs[0] || !segs[1]) {
    throw new IntakeError("prerequisite_missing", `Cannot parse owner/repo from ${repoUrl}`);
  }
  return [segs[0], segs[1]];
}
function encodeRepoPathForUrl(repoPath) {
  return repoPath.split("/").map(encodeURIComponent).join("/");
}
var FETCH_TIMEOUT_MS = 3e4;
async function fetchInputArtifact(pat, repoUrl, branch, repoPath, fetchImpl = fetch, caps = DEFAULT_INTAKE_CAPS) {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const encodedPath = encodeRepoPathForUrl(repoPath);
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}?ref=${encodeURIComponent(branch)}`;
  const headers = {
    Authorization: `Bearer ${pat}`,
    // raw media type → bytes, not the base64-in-JSON envelope.
    Accept: "application/vnd.github.raw",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "paperclip-plugin-cad/intake"
  };
  let resp;
  try {
    resp = await fetchImpl(url, { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new IntakeError("network", `Network error fetching input '${repoPath}': ${err.message}`);
  }
  if (resp.status === 404) {
    throw new IntakeError("not_found", `Input artifact not found (404): ${repoPath}`, 404);
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new IntakeError(
      "auth",
      `Not authorized (${resp.status}) reading input '${repoPath}'. Verify the export PAT has read access to the artifact repo.`,
      resp.status
    );
  }
  if (!resp.ok) {
    throw new IntakeError("network", `Unexpected ${resp.status} fetching input '${repoPath}'. Retry later.`, resp.status);
  }
  const clHeader = resp.headers.get("content-length");
  if (clHeader !== null) {
    const cl = Number(clHeader);
    if (Number.isFinite(cl) && cl > caps.maxFileBytes) {
      throw new IntakeError(
        "too_large",
        `Input '${repoPath}' is ${cl} bytes, over the ${caps.maxFileBytes}-byte per-file cap.`
      );
    }
  }
  const bytes = Buffer.from(await resp.arrayBuffer());
  if (bytes.byteLength > caps.maxFileBytes) {
    throw new IntakeError(
      "too_large",
      `Input '${repoPath}' is ${bytes.byteLength} bytes, over the ${caps.maxFileBytes}-byte per-file cap.`
    );
  }
  return { basename: path2.posix.basename(repoPath), bytes };
}
async function fetchInputArtifacts(pat, repoUrl, branch, repoPaths, fetchImpl = fetch, caps = DEFAULT_INTAKE_CAPS) {
  const files = [];
  let total = 0;
  for (const repoPath of repoPaths) {
    const file = await fetchInputArtifact(pat, repoUrl, branch, repoPath, fetchImpl, caps);
    total += file.bytes.byteLength;
    if (total > caps.maxTotalBytes) {
      throw new IntakeError(
        "too_large",
        `Combined input size ${total} bytes exceeds the ${caps.maxTotalBytes}-byte total cap.`
      );
    }
    files.push(file);
  }
  return files;
}
async function stageInputFiles(workdir, files) {
  if (!files.length) return;
  const inputsDir = path2.join(workdir, "inputs");
  await mkdir(inputsDir, { recursive: true });
  const inputsResolved = path2.resolve(inputsDir);
  for (const f of files) {
    const base = path2.basename(f.basename);
    if (!base || base === "." || base === "..") {
      throw new IntakeError("validation", `refusing to stage input with unsafe basename '${f.basename}'`);
    }
    const dest = path2.join(inputsDir, base);
    const destResolved = path2.resolve(dest);
    if (destResolved !== path2.join(inputsResolved, base)) {
      throw new IntakeError("validation", `refusing to stage input outside inputs/ dir: '${f.basename}'`);
    }
    await writeFile(dest, f.bytes);
  }
}

// src/stub-cad-worker.ts
import { tmpdir } from "node:os";
import { join as join2 } from "node:path";
var CadWorkerInternalError = class extends Error {
  code = "worker_internal";
  constructor(message) {
    super(message);
    this.name = "CadWorkerInternalError";
  }
};
var ARTIFACT_STAGING_DIR = join2(tmpdir(), "paperclip-cad-staging");

// src/cad-worker-client.ts
var GRACE_SECONDS = 5;
var BWRAP_OVERHEAD_GRACE_MS = 100;
var MAX_TIMEOUT_SECONDS = 300;
var DEFAULT_TIMEOUT_SECONDS = 30;
var __filename = fileURLToPath2(import.meta.url);
var __dirname = dirname(__filename);
var WORKER_PY = join3(__dirname, "cad_worker.py");
var SECCOMP_FILTER_PATH = join3(__dirname, "..", "worker", "seccomp_filter.bpf");
var SECCOMP_LOADER_PATH = join3(__dirname, "..", "worker", "seccomp_load.py");
var SANDBOX_ROOT = "/sandbox";
var SANDBOX_FILTER_PATH = `${SANDBOX_ROOT}/seccomp_filter.bpf`;
var SANDBOX_LOADER_PATH = `${SANDBOX_ROOT}/seccomp_load.py`;
var SANDBOX_WORKER_PATH = `${SANDBOX_ROOT}/cad_worker.py`;
var PREEXEC_PATH = join3(__dirname, "..", "worker", "cad_preexec");
function defaultRlimits(timeoutSeconds) {
  return {
    asBytes: 2 * 1024 ** 3,
    nproc: 64,
    nofile: 256,
    fsizeBytes: 256 * 1024 ** 2,
    cpuSeconds: timeoutSeconds + 5,
    coreBytes: 0
  };
}
function which(bin) {
  try {
    const out = execSync(`command -v ${bin}`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}
function bwrapVersionOf(bwrapPath) {
  try {
    const out = execSync(`${bwrapPath} --version`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    const m = /(\d+)\.(\d+)/.exec(out);
    if (!m) return null;
    return { major: Number(m[1]), minor: Number(m[2]) };
  } catch {
    return null;
  }
}
function selectSpawnMode(env = process.env, platform = process.platform) {
  const unsafeDev = env.CAD_WORKER_UNSAFE_DEV === "1";
  const isProd = env.NODE_ENV === "production";
  if (unsafeDev && !isProd) {
    return { mode: "dev_direct" };
  }
  if (platform !== "linux") {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: requires Linux + bwrap. Set CAD_WORKER_UNSAFE_DEV=1 (NODE_ENV must NOT be 'production') to run with the in-process layer only on developer machines."
    );
  }
  const bwrapPath = which("bwrap");
  if (!bwrapPath) {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: 'bwrap' not on PATH. Install bubblewrap on the deploy host (apt-get install bubblewrap). Set CAD_WORKER_UNSAFE_DEV=1 (non-production only) to run direct."
    );
  }
  if (!existsSync(SECCOMP_FILTER_PATH)) {
    throw new CadWorkerInternalError(
      `Option B sandbox unavailable: seccomp filter blob not found at ${SECCOMP_FILTER_PATH}. Build it with \`make -C worker seccomp_filter.bpf\` (requires libseccomp-dev).`
    );
  }
  if (!existsSync(SECCOMP_LOADER_PATH)) {
    throw new CadWorkerInternalError(
      `Option B sandbox unavailable: python seccomp loader not found at ${SECCOMP_LOADER_PATH}. This file ships in worker/ alongside the filter source.`
    );
  }
  const v = bwrapVersionOf(bwrapPath);
  const native = false;
  if (!native && !existsSync(PREEXEC_PATH)) {
    throw new CadWorkerInternalError(
      `bwrap ${v?.major}.${v?.minor} predates --rlimit-* (need 0.6+). Build the preexec wrapper with \`make -C worker cad_preexec\`, or upgrade bubblewrap on the deploy host.`
    );
  }
  const decision = {
    mode: "bwrap+seccomp",
    bwrapPath,
    bwrapVersion: v ?? void 0,
    bwrapHasNativeRlimits: native,
    seccompFilterPath: SECCOMP_FILTER_PATH,
    seccompLoaderPath: SECCOMP_LOADER_PATH,
    preexecPath: native ? void 0 : PREEXEC_PATH
  };
  verifySeccompPins(decision);
  return decision;
}
var SHA256_HEX_LEN = 64;
var SHA256_HEX_RE = /^[0-9a-f]{64}$/i;
function readSidecarSha(name) {
  const sidecarPath = join3(__dirname, "..", "dist", `${name}.sha256`);
  if (!existsSync(sidecarPath)) return void 0;
  const raw = readFileSync(sidecarPath, "utf8").trim();
  return SHA256_HEX_RE.test(raw) ? raw.toLowerCase() : void 0;
}
function resolveDefaultPins() {
  const filterConst = SECCOMP_FILTER_SHA256_PIN.length === SHA256_HEX_LEN ? SECCOMP_FILTER_SHA256_PIN : void 0;
  const loaderConst = SECCOMP_LOADER_SHA256_PIN.length === SHA256_HEX_LEN ? SECCOMP_LOADER_SHA256_PIN : void 0;
  return {
    filterSha256: filterConst ?? readSidecarSha("seccomp_filter.bpf") ?? SECCOMP_FILTER_SHA256_PIN,
    loaderSha256: loaderConst ?? readSidecarSha("seccomp_load.py") ?? SECCOMP_LOADER_SHA256_PIN
  };
}
function verifySeccompPins(decision, pins = resolveDefaultPins()) {
  if (decision.mode !== "bwrap+seccomp") return;
  const checks = [
    {
      name: "seccomp_filter.bpf",
      pin: pins.filterSha256,
      path: decision.seccompFilterPath ?? ""
    },
    {
      name: "seccomp_load.py",
      pin: pins.loaderSha256,
      path: decision.seccompLoaderPath ?? ""
    }
  ];
  for (const c of checks) {
    if (c.pin.length !== SHA256_HEX_LEN) {
      throw new CadWorkerInternalError(
        `[PLA-114 \xA75.2] ${c.name}: build manifest unsubstituted \u2014 pin length ${c.pin.length} \u2260 ${SHA256_HEX_LEN} (placeholder __PLA114_SECCOMP_*_SHA256__ still present?). Run \`npm run build\` so esbuild substitutes the digests.`
      );
    }
    if (!SHA256_HEX_RE.test(c.pin)) {
      throw new CadWorkerInternalError(
        `[PLA-114 \xA75.2] ${c.name}: build manifest pin is not a sha256 hex string: ${c.pin}`
      );
    }
    if (!c.path) {
      throw new CadWorkerInternalError(
        `[PLA-114 \xA75.2] ${c.name}: SpawnModeDecision is missing the path field \u2014 cannot verify pin.`
      );
    }
    let actual;
    try {
      actual = createHash("sha256").update(readFileSync(c.path)).digest("hex");
    } catch (err) {
      throw new CadWorkerInternalError(
        `[PLA-114 \xA75.2] ${c.name}: failed to read for sha256 verification (path=${c.path}): ${err.message}`
      );
    }
    if (actual.toLowerCase() !== c.pin.toLowerCase()) {
      throw new CadWorkerInternalError(
        `[PLA-114 \xA75.2] ${c.name}: sha256 mismatch \u2014 manifest pin=${c.pin} actual=${actual} path=${c.path}. Refusing to launch worker; the kernel sandbox layer would be silently inert under this state (substitution-attack defense).`
      );
    }
  }
}
var PYTHON_BOOTSTRAP = "import sys; sys.path.insert(0, '/sandbox'); from seccomp_load import lock_down; lock_down('/sandbox/seccomp_filter.bpf'); import cad_worker; cad_worker.main()";
function buildSpawnInvocation(opts) {
  const pythonBin = opts.pythonBin ?? "python3";
  const env = {
    PATH: "/usr/bin:/bin",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1"
  };
  if (opts.decision.mode === "dev_direct") {
    return {
      command: pythonBin,
      args: [WORKER_PY],
      env,
      stdio: ["pipe", "pipe", "pipe"]
    };
  }
  const bwrap = opts.decision.bwrapPath;
  const venvPython = pythonBin;
  const filterBlob = opts.decision.seccompFilterPath;
  const loaderShim = opts.decision.seccompLoaderPath;
  const args = [
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--setenv",
    "PATH",
    "/usr/bin:/bin",
    "--setenv",
    "HOME",
    "/tmp",
    "--setenv",
    "LANG",
    "C.UTF-8",
    "--setenv",
    "PYTHONDONTWRITEBYTECODE",
    "1",
    "--setenv",
    "PYTHONHASHSEED",
    "random",
    "--setenv",
    "PYTHONUNBUFFERED",
    "1",
    "--uid",
    "65534",
    "--gid",
    "65534",
    "--hostname",
    "cad-worker",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/lib",
    "/lib",
    "--ro-bind",
    "/lib64",
    "/lib64",
    "--ro-bind",
    "/bin",
    "/bin",
    "--ro-bind",
    "/etc/ld.so.cache",
    "/etc/ld.so.cache",
    // Trusted bootstrap files mounted under /sandbox. The loader shim and
    // filter blob are both content-pinned by the build manifest (§5.2).
    "--ro-bind",
    filterBlob,
    SANDBOX_FILTER_PATH,
    "--ro-bind",
    loaderShim,
    SANDBOX_LOADER_PATH,
    "--ro-bind",
    WORKER_PY,
    SANDBOX_WORKER_PATH,
    "--tmpfs",
    "/tmp",
    "--bind",
    opts.workdir,
    opts.workdir,
    "--chdir",
    opts.workdir,
    "--cap-drop",
    "ALL"
  ];
  if (opts.decision.bwrapHasNativeRlimits) {
    args.push(
      "--rlimit-as",
      String(opts.rlimits.asBytes),
      "--rlimit-nproc",
      String(opts.rlimits.nproc),
      "--rlimit-nofile",
      String(opts.rlimits.nofile),
      "--rlimit-fsize",
      String(opts.rlimits.fsizeBytes),
      "--rlimit-cpu",
      String(opts.rlimits.cpuSeconds),
      "--rlimit-core",
      String(opts.rlimits.coreBytes)
    );
    args.push("--", venvPython, "-c", PYTHON_BOOTSTRAP);
  } else {
    const preexec = opts.decision.preexecPath;
    args.push("--ro-bind", preexec, preexec);
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_AS", String(opts.rlimits.asBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NPROC", String(opts.rlimits.nproc));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NOFILE", String(opts.rlimits.nofile));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_FSIZE", String(opts.rlimits.fsizeBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CPU", String(opts.rlimits.cpuSeconds));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CORE", String(opts.rlimits.coreBytes));
    args.push("--", preexec, venvPython, "-c", PYTHON_BOOTSTRAP);
  }
  const stdio = ["pipe", "pipe", "pipe"];
  return {
    command: bwrap,
    args,
    env,
    stdio
  };
}
async function invokeWorker(job, timeoutSeconds, decision = selectSpawnMode(), pythonBin = "python3") {
  const rlimits = defaultRlimits(timeoutSeconds);
  const invocation = buildSpawnInvocation({
    decision,
    workdir: job.workdir,
    pythonBin,
    rlimits
  });
  return new Promise((resolve2) => {
    const child = spawn(invocation.command, invocation.args, {
      stdio: invocation.stdio,
      env: invocation.env
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let killTimer = null;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      if (killTimer !== null) clearTimeout(killTimer);
      resolve2(result);
    };
    const overheadMs = decision.mode === "bwrap+seccomp" ? BWRAP_OVERHEAD_GRACE_MS : 0;
    killTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGKILL");
      } catch {
      }
      resolve2({
        ok: false,
        error: "worker_timeout",
        message: `CAD script timed out after ${timeoutSeconds}s`
      });
    }, timeoutSeconds * 1e3 + overheadMs + GRACE_SECONDS * 1e3);
    if (child.stdout) {
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString("utf8");
      });
    }
    if (child.stderr) {
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });
    }
    child.on("close", (code, signal) => {
      if (settled) return;
      if (killTimer !== null) clearTimeout(killTimer);
      if (signal === "SIGSYS") {
        settle({
          ok: false,
          error: "sandbox_violation",
          message: `Worker killed by seccomp (SIGSYS). stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      if (signal === "SIGKILL" && /seccomp/i.test(stderr)) {
        settle({
          ok: false,
          error: "sandbox_violation",
          message: `Worker killed by kernel (SIGKILL with seccomp audit line). stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      const line = stdout.trim();
      if (!line) {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker produced no output on stdout. code=${code} signal=${signal} stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      const newlineIdx = line.indexOf("\n");
      const firstLine = newlineIdx === -1 ? line : line.slice(0, newlineIdx);
      try {
        const parsed = JSON.parse(firstLine);
        if (!parsed.ok) {
          parsed.exitSignal = signal;
          parsed.exitCode = code;
        }
        settle(parsed);
      } catch {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker output was not valid JSON: ${firstLine.slice(0, 200)}`,
          exitSignal: signal,
          exitCode: code
        });
      }
    });
    child.on("error", (err) => {
      settle({
        ok: false,
        error: "worker_internal",
        message: `Failed to spawn worker process: ${err.message}`
      });
    });
    const jobJson = JSON.stringify(job);
    if (child.stdin) {
      child.stdin.write(jobJson, "utf8", () => {
        child.stdin?.end();
      });
    }
  });
}
async function renderCadQuery(script, format, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS, decision = selectSpawnMode(), inputFiles) {
  const effectiveTimeout = Math.min(
    Math.max(1, timeoutSeconds),
    MAX_TIMEOUT_SECONDS
  );
  const workdir = await mkdtemp(join3(tmpdir2(), "cad-worker-"));
  if (inputFiles?.length) await stageInputFiles(workdir, inputFiles);
  return invokeWorker({ script, format, workdir }, effectiveTimeout, decision);
}

// src/worker.ts
var DEFAULT_ARTIFACT_REPO_URL = "https://github.com/claudegoogl-sudo/cad-artifacts.git";
var DEFAULT_ARTIFACT_BRANCH = "main";
var artifactStagingMap = /* @__PURE__ */ new Map();
var MAX_RETAINED_INPUT_BYTES = 2 * MAX_TOTAL_INPUT_BYTES;
function entryInputBytes(entry) {
  let n = 0;
  for (const f of entry.inputs ?? []) n += f.bytes.byteLength;
  return n;
}
function enforceRetainedInputCap(map = artifactStagingMap, cap = MAX_RETAINED_INPUT_BYTES) {
  let total = 0;
  for (const entry of map.values()) total += entryInputBytes(entry);
  if (total <= cap) return;
  for (const entry of map.values()) {
    if (total <= cap) break;
    const freed = entryInputBytes(entry);
    if (freed === 0) continue;
    entry.inputs = void 0;
    total -= freed;
  }
}
var MAX_STAGING_ENTRIES = 256;
function enforceStagingEntryCap(map = artifactStagingMap, cap = MAX_STAGING_ENTRIES) {
  if (map.size <= cap) return;
  for (const key of map.keys()) {
    if (map.size <= cap) break;
    map.delete(key);
  }
}
var MAX_SCRIPT_BYTES = 256 * 1024;
function stagingMapKey(companyId, agentId, artifactId) {
  return `${companyId}:${agentId}:${artifactId}`;
}
var PushError = class extends Error {
  kind;
  httpStatus;
  constructor(kind, message, httpStatus) {
    super(message);
    this.name = "PushError";
    this.kind = kind;
    this.httpStatus = httpStatus;
  }
};
function validationError(message) {
  return { error: "validation_error", data: { code: "validation_error", statusCode: 400, message } };
}
function workerInternalError(message) {
  return { data: { code: "worker_internal", statusCode: 500, message } };
}
async function emitMetrics(ctx, tool, durationMs, isError) {
  await ctx.metrics?.write("tool.calls", 1, { tool });
  await ctx.metrics?.write("tool.duration_ms", durationMs, { tool });
  if (isError) await ctx.metrics?.write("tool.errors", 1, { tool });
}
function logCompletion(ctx, tool, runCtx, durationMs, status) {
  ctx.logger.info("tool call complete", {
    correlationId: runCtx.runId,
    tool,
    agentId: runCtx.agentId,
    status,
    durationMs
  });
}
var TICKET_ID_RE = /^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$/;
var TOOL_CALL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
var FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
function validateTicketId(value) {
  if (!TICKET_ID_RE.test(value)) {
    return "paperclipTicketId must match ^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$ (e.g. PLA-56)";
  }
  return null;
}
function validateToolCallId(value) {
  if (!TOOL_CALL_ID_RE.test(value)) {
    return "toolCallId must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";
  }
  return null;
}
function validateFilename(value) {
  if (value.startsWith(".") || value.includes("..")) {
    return "filename must not start with '.' or contain '..'";
  }
  if (!FILENAME_RE.test(value)) {
    return "filename must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
  }
  return null;
}
function assertSafeRepoPath(repoPath) {
  const normalized = path3.posix.normalize(repoPath);
  if (normalized !== repoPath) return "internal: repoPath would normalize differently (path traversal blocked)";
  if (!normalized.startsWith("artifacts/")) return "internal: repoPath must start with 'artifacts/'";
  return null;
}
function encodeRepoPathForUrl2(repoPath) {
  return repoPath.split("/").map(encodeURIComponent).join("/");
}
var FETCH_TIMEOUT_MS2 = 3e4;
function fetchSignal() {
  return AbortSignal.timeout(FETCH_TIMEOUT_MS2);
}
function githubHeaders(pat) {
  return {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "paperclip-plugin-cad/0.1.0"
  };
}
function parseGitHubUrl2(repoUrl) {
  let u;
  try {
    u = new URL(repoUrl);
  } catch {
    throw new PushError("prerequisite_missing", `Cannot parse GitHub URL: ${repoUrl}`);
  }
  if (u.protocol !== "https:" || u.host !== "github.com") {
    throw new PushError(
      "prerequisite_missing",
      `artifactRepoUrl must be an https://github.com/<owner>/<repo>(.git) URL. Got: ${repoUrl}`
    );
  }
  const segs = u.pathname.replace(/^\/+/, "").replace(/\.git\/?$/, "").replace(/\/+$/, "").split("/");
  if (segs.length !== 2 || !segs[0] || !segs[1]) {
    throw new PushError("prerequisite_missing", `Cannot parse owner/repo from ${repoUrl}`);
  }
  return [segs[0], segs[1]];
}
async function checkRepoPrerequisite(pat, repoUrl) {
  const [owner, repo] = parseGitHubUrl2(repoUrl);
  const headers = githubHeaders(pat);
  let resp;
  try {
    resp = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
      { headers, signal: fetchSignal() }
    );
  } catch (err) {
    throw new PushError("network", `Network error reaching ${owner}/${repo}: ${err.message}`);
  }
  if (resp.status === 404) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not found (404): ${owner}/${repo}. Operator must pre-create the repo and grant PAT access. See PLA-56 AC#1.`,
      404
    );
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not accessible (${resp.status}): ${owner}/${repo}. Verify PAT has repo scope. See PLA-56 AC#1.`,
      resp.status
    );
  }
  if (!resp.ok) {
    throw new PushError("network", `Unexpected ${resp.status} checking ${owner}/${repo}. Retry later.`, resp.status);
  }
}
async function checkArtifactExists(pat, repoUrl, repoPath) {
  let owner, repo;
  try {
    [owner, repo] = parseGitHubUrl2(repoUrl);
  } catch {
    return null;
  }
  const headers = githubHeaders(pat);
  const encodedPath = encodeRepoPathForUrl2(repoPath);
  const ownerEnc = encodeURIComponent(owner);
  const repoEnc = encodeURIComponent(repo);
  let contentsResp;
  try {
    contentsResp = await fetch(
      `https://api.github.com/repos/${ownerEnc}/${repoEnc}/contents/${encodedPath}`,
      { headers, signal: fetchSignal() }
    );
  } catch {
    return null;
  }
  if (!contentsResp.ok) return null;
  const contentsData = await contentsResp.json();
  try {
    const commitResp = await fetch(
      `https://api.github.com/repos/${ownerEnc}/${repoEnc}/commits?path=${encodeURIComponent(repoPath)}&per_page=1`,
      { headers, signal: fetchSignal() }
    );
    if (commitResp.ok) {
      const commits = await commitResp.json();
      const sha = commits[0]?.sha;
      if (sha) return { commitSha: sha, permalink: `https://github.com/${owner}/${repo}/blob/${sha}/${repoPath}` };
    }
  } catch {
  }
  return {
    commitSha: contentsData.sha ?? "unknown",
    permalink: contentsData.html_url ?? `https://github.com/${owner}/${repo}/blob/main/${repoPath}`
  };
}
async function pushArtifactToGitHub(pat, repoUrl, branch, localFile, repoPath, message) {
  const [owner, repo] = parseGitHubUrl2(repoUrl);
  const { readFile } = await import("node:fs/promises");
  const contentBase64 = (await readFile(localFile)).toString("base64");
  const encodedPath = encodeRepoPathForUrl2(repoPath);
  const apiBase = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}`;
  const headers = githubHeaders(pat);
  let existingSha;
  let getResp;
  try {
    getResp = await fetch(apiBase, { headers, signal: fetchSignal() });
  } catch (err) {
    throw new PushError("network", `Network error fetching ${repoPath}: ${err.message}`);
  }
  if (getResp.ok) {
    existingSha = (await getResp.json()).sha;
  } else if (getResp.status === 401 || getResp.status === 403) {
    throw new PushError("auth", `Auth failed (${getResp.status}) reading ${repoPath}. Rotate PAT.`, getResp.status);
  } else if (getResp.status >= 500) {
    throw new PushError("network", `API ${getResp.status} reading ${repoPath}. Retry.`, getResp.status);
  }
  const body = { message, content: contentBase64, branch };
  if (existingSha) body.sha = existingSha;
  let putResp;
  try {
    putResp = await fetch(apiBase, { method: "PUT", headers, body: JSON.stringify(body), signal: fetchSignal() });
  } catch (err) {
    throw new PushError("network", `Network error pushing ${repoPath}: ${err.message}`);
  }
  if (!putResp.ok) {
    const s = putResp.status;
    if (s === 401 || s === 403) throw new PushError("auth", `Push auth failed (${s}). Rotate PAT.`, s);
    if (s === 409 || s === 422) throw new PushError("conflict", `Conflict (${s}) on ${repoPath}.`, s);
    if (s >= 500) throw new PushError("network", `API ${s} pushing ${repoPath}. Retry.`, s);
    throw new PushError("network", `API error ${s}: ${await putResp.text()}`, s);
  }
  const result = await putResp.json();
  const commitSha = result.commit?.sha ?? "";
  return { commitSha, permalink: `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}` };
}
async function renderCadScript(script, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS, inputFiles) {
  const result = await renderCadQuery(script, "step", timeoutSeconds, void 0, inputFiles);
  if (!result.ok) throw new Error(`[${result.error}] ${result.message}`);
  return result.artifactPath;
}
async function exportToFormat(entry, format) {
  if (format === "step") return entry.stepPath;
  const result = await renderCadQuery(entry.script, format, DEFAULT_TIMEOUT_SECONDS, void 0, entry.inputs);
  if (!result.ok) throw new Error(`[${result.error}] Export to ${format} failed: ${result.message}`);
  return result.artifactPath;
}
var plugin = definePlugin({
  async setup(ctx) {
    ctx.logger.info("CAD plugin worker starting");
    const anyCtx = ctx;
    ctx.tools.register(
      "cad.run_script",
      {
        displayName: "CAD Run Script",
        description: "Execute a CadQuery Python script. Returns { artifactId, summary }.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string", maxLength: MAX_SCRIPT_BYTES, description: "CadQuery Python script (max 256 KiB)." },
            timeout: { type: "integer", minimum: 1, maximum: 300, description: "Timeout (seconds, default 30)." },
            inputArtifacts: {
              type: "array",
              maxItems: MAX_INPUT_FILES,
              items: {
                type: "object",
                properties: {
                  repoPath: {
                    type: "string",
                    description: "Path of an uploaded scan in the cad-artifacts repo (under user-uploads/ or artifacts/). Fetched by the host and staged into the sandbox at inputs/<basename>; read it via StlAPI_Reader('inputs/<basename>')."
                  }
                },
                required: ["repoPath"],
                additionalProperties: false
              },
              description: "Optional scan/mesh files to stage into the sandbox before the script runs (PLA-1089). Per-file 50 MiB cap, 120 MiB total, max 3 files."
            }
          },
          required: ["script"],
          additionalProperties: false
        }
      },
      async (params, runCtxRaw) => {
        const runCtx = runCtxRaw ?? {};
        const tool = "cad.run_script";
        const t0 = Date.now();
        if (typeof params !== "object" || params === null) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("params must be an object");
        }
        const p = params;
        if (typeof p.script !== "string" || p.script.length === 0) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("script is required and must be a non-empty string");
        }
        if (Buffer.byteLength(p.script, "utf8") > MAX_SCRIPT_BYTES) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError(`script exceeds maximum size of ${MAX_SCRIPT_BYTES} bytes`);
        }
        if (p.timeout !== void 0) {
          const t = p.timeout;
          if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 300) {
            const ms2 = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms2, true);
            logCompletion(ctx, tool, runCtx, ms2, "error");
            return validationError("timeout must be an integer between 1 and 300");
          }
        }
        const script = p.script;
        const timeoutSeconds = typeof p.timeout === "number" ? p.timeout : DEFAULT_TIMEOUT_SECONDS;
        if (typeof runCtx.companyId !== "string" || runCtx.companyId.length === 0 || typeof runCtx.agentId !== "string" || runCtx.agentId.length === 0) {
          ctx.logger.warn("cad.run_script: missing tenant context on runCtx");
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("missing tenant context (companyId/agentId) on runCtx");
        }
        let inputFiles = [];
        const parsedInputs = parseInputArtifacts(p.inputArtifacts);
        if ("error" in parsedInputs) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError(parsedInputs.error);
        }
        if (parsedInputs.repoPaths.length > 0) {
          const config = await ctx.config.get();
          if (!config.githubPatSecretId) {
            const ms2 = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms2, true);
            logCompletion(ctx, tool, runCtx, ms2, "error");
            return { data: { error: "prerequisite_missing", message: "inputArtifacts requires githubPatSecretId to be configured." } };
          }
          const repoUrl = config.artifactRepoUrl ?? DEFAULT_ARTIFACT_REPO_URL;
          const branch = config.artifactRepoBranch ?? DEFAULT_ARTIFACT_BRANCH;
          ctx.logger.info("cad.run_script: fetching inputArtifacts", { count: parsedInputs.repoPaths.length });
          const pat = await ctx.secrets.resolve(config.githubPatSecretId);
          try {
            inputFiles = await fetchInputArtifacts(pat, repoUrl, branch, parsedInputs.repoPaths);
          } catch (err) {
            if (err instanceof IntakeError) {
              ctx.logger.warn("cad.run_script: intake fetch failed", { kind: err.kind, httpStatus: err.httpStatus });
              const ms2 = Date.now() - t0;
              await emitMetrics(anyCtx, tool, ms2, true);
              logCompletion(ctx, tool, runCtx, ms2, "error");
              return { data: { error: err.kind, message: err.message } };
            }
            throw err;
          }
        }
        ctx.logger.info("cad.run_script: rendering", { scriptLength: script.length, timeoutSeconds, inputCount: inputFiles.length });
        let stepPath;
        try {
          stepPath = await renderCadScript(script, timeoutSeconds, inputFiles);
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Unknown worker error";
          ctx.logger.warn("cad.run_script: worker error", { error: msg });
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return workerInternalError(msg);
        }
        const artifactId = `cad-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        artifactStagingMap.set(
          stagingMapKey(runCtx.companyId, runCtx.agentId, artifactId),
          { script, stepPath, inputs: inputFiles.length > 0 ? inputFiles : void 0 }
        );
        enforceStagingEntryCap();
        enforceRetainedInputCap();
        ctx.logger.info("cad.run_script: staged", { artifactId });
        const ms = Date.now() - t0;
        await emitMetrics(anyCtx, tool, ms, false);
        logCompletion(ctx, tool, runCtx, ms, "ok");
        return {
          content: `Artifact staged: ${artifactId}`,
          data: { artifactId, summary: `CadQuery script executed successfully (${script.length} chars)` }
        };
      }
    );
    ctx.tools.register(
      "cad.export",
      {
        displayName: "CAD Export",
        description: "Export a staged CAD artifact to the configured GitHub artifact repo. Returns { commitSha, permalink, artifactPath }. Idempotent per toolCallId.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactId: { type: "string", description: "Artifact ID from cad.run_script." },
            format: {
              type: "string",
              // PLA-443 — keep enum in lockstep with manifest.ts; DR laser-fab
              // ask added 2D vector outputs (dxf, svg) routed to CadQuery's
              // ExportTypes.DXF / ExportTypes.SVG in cad_worker.py.
              enum: ["step", "stl", "3mf", "dxf", "svg"],
              description: "Output format."
            },
            paperclipTicketId: {
              type: "string",
              pattern: "^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$",
              description: "Paperclip ticket ID (e.g. PLA-56) for path/commit message."
            },
            toolCallId: {
              type: "string",
              pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
              description: "Tool-call ID for deterministic path and idempotency."
            },
            filename: {
              type: "string",
              pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
              description: "Optional filename override. Default: artifact.<format>."
            }
          },
          required: ["artifactId", "format", "paperclipTicketId", "toolCallId"],
          additionalProperties: false
        }
      },
      async (params, runCtxRaw) => {
        const runCtx = runCtxRaw ?? {};
        const tool = "cad.export";
        const t0 = Date.now();
        if (typeof params !== "object" || params === null) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("params must be an object");
        }
        const p = params;
        if (typeof p.artifactId !== "string" || p.artifactId.length === 0) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("artifactId is required and must be a non-empty string");
        }
        const validFormats = ["step", "stl", "3mf", "dxf", "svg"];
        if (typeof p.format !== "string" || !validFormats.includes(p.format)) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError(`format must be one of: ${validFormats.join(", ")}`);
        }
        const { artifactId, format, paperclipTicketId, toolCallId, filename } = p;
        if (paperclipTicketId !== void 0) {
          if (typeof paperclipTicketId !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("paperclipTicketId must be a string");
          }
          const tErr = validateTicketId(paperclipTicketId);
          if (tErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(tErr);
          }
        }
        if (toolCallId !== void 0) {
          if (typeof toolCallId !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("toolCallId must be a string");
          }
          const cErr = validateToolCallId(toolCallId);
          if (cErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(cErr);
          }
        }
        if (filename !== void 0) {
          if (typeof filename !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("filename must be a string");
          }
          const fErr = validateFilename(filename);
          if (fErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(fErr);
          }
        }
        ctx.logger.info("cad.export: starting", { artifactId, format });
        const hasTenantCtx = typeof runCtx.companyId === "string" && runCtx.companyId.length > 0 && typeof runCtx.agentId === "string" && runCtx.agentId.length > 0;
        const stagingEntry = hasTenantCtx ? artifactStagingMap.get(stagingMapKey(runCtx.companyId, runCtx.agentId, artifactId)) : void 0;
        if (!stagingEntry) {
          ctx.logger.warn("cad.export: unknown artifactId", { artifactId });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(`No staged artifact for artifactId: ${artifactId}. Call cad.run_script first.`);
        }
        if (!paperclipTicketId || !toolCallId) {
          try {
            const filePath = await exportToFormat(stagingEntry, format);
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, false);
            logCompletion(ctx, tool, runCtx, ms, "ok");
            return { data: { filePath, artifactId, format } };
          } catch (err) {
            const msg = err instanceof Error ? err.message : "Export failed";
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return workerInternalError(msg);
          }
        }
        const config = await ctx.config.get();
        if (!config.githubPatSecretId) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return { data: { error: "prerequisite_missing", message: "githubPatSecretId not configured." } };
        }
        const repoUrl = config.artifactRepoUrl ?? DEFAULT_ARTIFACT_REPO_URL;
        const branch = config.artifactRepoBranch ?? DEFAULT_ARTIFACT_BRANCH;
        const ticketIdStr = paperclipTicketId;
        const toolCallIdStr = toolCallId;
        const filenameRaw = filename;
        const resolvedFilename = filenameRaw ?? `artifact.${format}`;
        const repoPath = `artifacts/${ticketIdStr}/${toolCallIdStr}/${resolvedFilename}`;
        const pathErr = assertSafeRepoPath(repoPath);
        if (pathErr) {
          ctx.logger.warn("cad.export: repoPath assertion failed", { pathErr });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError(pathErr);
        }
        ctx.logger.info("cad.export: resolving GitHub PAT");
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);
        try {
          await checkRepoPrerequisite(pat, repoUrl);
        } catch (err) {
          if (err instanceof PushError && err.kind === "prerequisite_missing") {
            ctx.logger.warn("cad.export: prerequisite failed", { repoUrl, httpStatus: err.httpStatus });
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return { data: { error: "prerequisite_missing", message: err.message } };
          }
          throw err;
        }
        ctx.logger.info("cad.export: idempotency check", { repoPath });
        const existing = await checkArtifactExists(pat, repoUrl, repoPath);
        if (existing) {
          ctx.logger.info("cad.export: already exists", { repoPath, commitSha: existing.commitSha });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, false);
          logCompletion(ctx, tool, runCtx, ms, "ok");
          return {
            content: `Artifact already present at ${repoPath} (${existing.commitSha})`,
            data: { commitSha: existing.commitSha, permalink: existing.permalink, artifactPath: repoPath }
          };
        }
        let localFile;
        try {
          localFile = await exportToFormat(stagingEntry, format);
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Export failed";
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(msg);
        }
        const commitMessage = `CAD artifact: ticket=${ticketIdStr} tool=cad.export call=${toolCallIdStr}`;
        const doPush = () => pushArtifactToGitHub(pat, repoUrl, branch, localFile, repoPath, commitMessage);
        ctx.logger.info("cad.export: pushing", { repoPath, branch });
        try {
          let pushResult;
          try {
            pushResult = await doPush();
          } catch (firstErr) {
            if (firstErr instanceof PushError && firstErr.kind === "conflict") {
              ctx.logger.warn("cad.export: conflict, retrying once", { repoPath });
              pushResult = await doPush();
            } else {
              throw firstErr;
            }
          }
          ctx.logger.info("cad.export: committed", { repoPath, commitSha: pushResult.commitSha });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, false);
          logCompletion(ctx, tool, runCtx, ms, "ok");
          return {
            content: `Artifact committed: ${pushResult.permalink}`,
            data: { commitSha: pushResult.commitSha, permalink: pushResult.permalink, artifactPath: repoPath }
          };
        } catch (err) {
          if (err instanceof PushError) {
            ctx.logger.warn("cad.export: push failed", { kind: err.kind, httpStatus: err.httpStatus });
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return { data: { error: err.kind, message: err.message } };
          }
          throw err;
        }
      }
    );
    ctx.logger.info("CAD plugin worker setup complete");
  },
  async onHealth() {
    return { status: "ok", message: "CAD plugin worker is running" };
  }
});
var worker_default = plugin;
runWorker(plugin, import.meta.url);
export {
  MAX_RETAINED_INPUT_BYTES,
  MAX_SCRIPT_BYTES,
  MAX_STAGING_ENTRIES,
  worker_default as default,
  enforceRetainedInputCap,
  enforceStagingEntryCap
};
//# sourceMappingURL=worker.js.map
