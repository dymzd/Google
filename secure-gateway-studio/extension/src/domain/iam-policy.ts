import { canonicalJson } from "./canonical.ts";

export interface IamBinding {
  role?: unknown;
  members?: unknown;
  condition?: unknown;
  [key: string]: unknown;
}

export interface IamPolicy {
  bindings?: unknown;
  version?: unknown;
  etag?: unknown;
  auditConfigs?: unknown;
  [key: string]: unknown;
}

function sameCondition(left: unknown, right: unknown): boolean {
  return canonicalJson(left ?? null) === canonicalJson(right ?? null);
}

interface ParsedBinding {
  binding: IamBinding;
  key: string;
  members: string[];
}

function validateCondition(condition: unknown): void {
  if (condition === undefined) return;
  if (condition === null || typeof condition !== "object" || Array.isArray(condition)) {
    throw new Error("IAM binding contains an invalid condition");
  }
  const candidate = condition as Record<string, unknown>;
  const allowed = new Set(["title", "expression", "description", "location"]);
  if (
    Object.keys(candidate).some((field) => !allowed.has(field)) ||
    typeof candidate.title !== "string" || candidate.title.trim() === "" ||
    typeof candidate.expression !== "string" || candidate.expression.trim() === ""
  ) {
    throw new Error("IAM binding condition lacks a title or expression");
  }
  for (const optional of ["description", "location"] as const) {
    if (candidate[optional] !== undefined && typeof candidate[optional] !== "string") {
      throw new Error(`IAM binding condition contains an invalid ${optional}`);
    }
  }
}

function validateAuditConfigs(value: unknown): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) throw new Error("IAM policy contains invalid auditConfigs");
  const services = new Set<string>();
  for (const raw of value) {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("IAM policy contains an invalid audit config");
    }
    const audit = raw as Record<string, unknown>;
    if (
      Object.keys(audit).some((field) => !["service", "auditLogConfigs"].includes(field)) ||
      typeof audit.service !== "string" || audit.service.trim() === "" ||
      services.has(audit.service) ||
      (audit.auditLogConfigs !== undefined && !Array.isArray(audit.auditLogConfigs))
    ) throw new Error("IAM policy contains an invalid audit config");
    services.add(audit.service);
    const logTypes = new Set<string>();
    for (const rawLog of (audit.auditLogConfigs ?? []) as unknown[]) {
      if (rawLog === null || typeof rawLog !== "object" || Array.isArray(rawLog)) {
        throw new Error("IAM policy contains an invalid audit log config");
      }
      const log = rawLog as Record<string, unknown>;
      if (
        Object.keys(log).some((field) => !["logType", "exemptedMembers"].includes(field)) ||
        typeof log.logType !== "string" ||
        !["ADMIN_READ", "DATA_WRITE", "DATA_READ"].includes(log.logType) ||
        logTypes.has(log.logType) ||
        (log.exemptedMembers !== undefined && !Array.isArray(log.exemptedMembers))
      ) throw new Error("IAM policy contains an invalid audit log config");
      logTypes.add(log.logType);
      if (Array.isArray(log.exemptedMembers)) {
        const members = new Set<string>();
        for (const member of log.exemptedMembers) {
          if (typeof member !== "string" || member.trim() === "" || members.has(member)) {
            throw new Error("IAM audit log config contains an invalid exempted member");
          }
          members.add(member);
        }
      }
    }
  }
}

function parseBindings(policy: IamPolicy): ParsedBinding[] {
  if (policy.bindings !== undefined && !Array.isArray(policy.bindings)) {
    throw new Error("IAM policy contains an invalid bindings collection");
  }
  const keys = new Set<string>();
  return ((policy.bindings ?? []) as unknown[]).map((raw) => {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("IAM policy contains an invalid binding");
    }
    const binding = structuredClone(raw as IamBinding);
    if (
      Object.keys(binding).some((field) => !["role", "members", "condition"].includes(field)) ||
      typeof binding.role !== "string" || binding.role.trim() === ""
    ) {
      throw new Error("IAM binding contains an invalid role");
    }
    if (!Array.isArray(binding.members) || binding.members.length === 0) {
      throw new Error("IAM binding contains an invalid members collection");
    }
    validateCondition(binding.condition);
    const seenMembers = new Set<string>();
    const members = binding.members.map((member) => {
      if (typeof member !== "string" || member.trim() === "") {
        throw new Error("IAM binding contains a non-string member");
      }
      if (seenMembers.has(member)) throw new Error("IAM binding contains duplicate members");
      seenMembers.add(member);
      return member;
    });
    const key = canonicalJson([binding.role, binding.condition ?? null]);
    if (keys.has(key)) throw new Error("IAM policy contains duplicate role/condition bindings");
    keys.add(key);
    return {
      binding,
      key,
      members,
    };
  });
}

/**
 * Validate every binding before a freshly read policy can be merged and sent
 * back to Google. Returning a clone prevents callers from accidentally
 * relying on unvalidated objects from the transport response.
 */
export function validatedIamPolicy(
  policy: IamPolicy,
  options: { requireEtag?: boolean } = { requireEtag: true },
): IamPolicy {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("IAM policy is not an object");
  }
  const allowed = new Set(["version", "bindings", "auditConfigs", "etag"]);
  if (Object.keys(policy).some((field) => !allowed.has(field))) {
    throw new Error("IAM policy contains unknown fields");
  }
  if (
    policy.version !== undefined &&
    (!Number.isInteger(policy.version) || ![0, 1, 3].includes(policy.version as number))
  ) throw new Error("IAM policy contains an invalid version");
  if (
    policy.etag !== undefined &&
    (typeof policy.etag !== "string" || policy.etag.trim() === "")
  ) throw new Error("IAM policy contains an invalid etag");
  if (
    options.requireEtag !== false &&
    (typeof policy.etag !== "string" || policy.etag.trim() === "")
  ) {
    throw new Error("IAM policy is missing an etag");
  }
  validateAuditConfigs(policy.auditConfigs);
  const bindings = parseBindings(policy);
  if (
    bindings.some(({ binding }) => binding.condition !== undefined) &&
    policy.version !== 3
  ) throw new Error("conditional IAM bindings require policy version 3");
  return {
    ...structuredClone(policy),
    bindings: bindings.map(({ binding }) => binding),
  };
}

/** Strict binding-only parser for durable bootstrap ownership pins. */
export function validatedIamBindings(value: unknown): IamBinding[] {
  const policy = validatedIamPolicy(
    { bindings: value },
    { requireEtag: false },
  );
  return structuredClone((policy.bindings ?? []) as IamBinding[]);
}

function memberGroups(bindings: ParsedBinding[]): Map<string, Set<string>> {
  const groups = new Map<string, Set<string>>();
  for (const binding of bindings) {
    const members = groups.get(binding.key) ?? new Set<string>();
    for (const member of binding.members) members.add(member);
    groups.set(binding.key, members);
  }
  return groups;
}

/**
 * Reverse only the role/condition/member delta produced by one IAM mutation.
 *
 * `beforePolicy` and `afterPolicy` are the exact policies checkpointed around
 * Apply. `currentPolicy` is a fresh v3 read at compensation time. Bindings and
 * members introduced by other administrators after Apply are therefore kept;
 * only members added by this run are removed and members removed by this run
 * are restored. Policy metadata and the fresh etag come from `currentPolicy`.
 */
export function revertIamPolicyDelta(options: {
  beforePolicy: IamPolicy;
  afterPolicy: IamPolicy;
  currentPolicy: IamPolicy;
}): IamPolicy {
  const beforePolicy = validatedIamPolicy(options.beforePolicy);
  const afterPolicy = validatedIamPolicy(options.afterPolicy);
  const currentPolicy = validatedIamPolicy(options.currentPolicy);
  const beforeBindings = parseBindings(beforePolicy);
  const afterBindings = parseBindings(afterPolicy);
  const currentBindings = parseBindings(currentPolicy);
  const beforeGroups = memberGroups(beforeBindings);
  const afterGroups = memberGroups(afterBindings);
  const affectedKeys = new Set([...beforeGroups.keys(), ...afterGroups.keys()]);
  let reverted = currentBindings.map(({ binding, key, members }) => ({
    binding,
    key,
    members: [...members],
  }));

  for (const key of affectedKeys) {
    const beforeMembers = beforeGroups.get(key) ?? new Set<string>();
    const afterMembers = afterGroups.get(key) ?? new Set<string>();
    const added = new Set([...afterMembers].filter((member) => !beforeMembers.has(member)));
    const removed = new Set([...beforeMembers].filter((member) => !afterMembers.has(member)));
    if (added.size === 0 && removed.size === 0) continue;

    let target = reverted.find((entry) => entry.key === key);
    for (const entry of reverted) {
      if (entry.key === key) {
        entry.members = entry.members.filter((member) => !added.has(member));
      }
    }
    if (removed.size > 0) {
      if (target === undefined) {
        const template =
          beforeBindings.find((entry) => entry.key === key) ??
          afterBindings.find((entry) => entry.key === key);
        if (template === undefined) {
          throw new Error("IAM delta lacks a binding template");
        }
        target = {
          binding: structuredClone(template.binding),
          key,
          members: [],
        };
        reverted.push(target);
      }
      target.members = [...new Set([...target.members, ...removed])].sort();
    }
    reverted = reverted.filter((entry) => entry.key !== key || entry.members.length > 0);
  }

  return validatedIamPolicy({
    ...structuredClone(currentPolicy),
    bindings: reverted.map(({ binding, members }) => ({ ...binding, members })),
    version: 3,
  });
}

/**
 * Replace only the members this run previously managed for one role/condition.
 *
 * Unrelated roles, conditions, members, etag, and policy metadata are retained
 * byte-for-byte. The result is always policy version 3 because writing a v1
 * representation can silently corrupt conditional bindings.
 */
export function replaceOwnedIamBinding(options: {
  policy: IamPolicy;
  role: string;
  previousCondition?: unknown;
  targetCondition?: unknown;
  previousMembers: ReadonlySet<string>;
  targetMembers: ReadonlySet<string>;
}): IamPolicy {
  const validated = validatedIamPolicy(options.policy);
  const bindings = (validated.bindings ?? []) as IamBinding[];
  const retained: IamBinding[] = [];

  for (const raw of bindings) {
    const binding = structuredClone(raw);
    if (
      binding.role !== options.role ||
      !sameCondition(binding.condition, options.previousCondition)
    ) {
      retained.push(binding);
      continue;
    }
    if (!Array.isArray(binding.members)) {
      throw new Error("IAM binding contains an invalid members collection");
    }
    const members = binding.members.filter((member): member is string => {
      if (typeof member !== "string") {
        throw new Error("IAM binding contains a non-string member");
      }
      return !options.previousMembers.has(member);
    });
    if (members.length > 0) retained.push({ ...binding, members });
  }

  const target = retained.find(
    (binding) =>
      binding.role === options.role &&
      sameCondition(binding.condition, options.targetCondition),
  );
  if (target !== undefined) {
    if (!Array.isArray(target.members)) {
      throw new Error("IAM binding contains an invalid members collection");
    }
    const current = target.members.map((member) => {
      if (typeof member !== "string") {
        throw new Error("IAM binding contains a non-string member");
      }
      return member;
    });
    target.members = [...new Set([...current, ...options.targetMembers])].sort();
  } else if (options.targetMembers.size > 0) {
    retained.push({
      role: options.role,
      members: [...options.targetMembers].sort(),
      ...(options.targetCondition == null ? {} : { condition: options.targetCondition }),
    });
  }

  return validatedIamPolicy({
    ...validated,
    bindings: retained,
    version: 3,
  });
}
