"""化名域（Alias Domains）：遮盖之上的**授权跨请求关联**层。

与遮盖（Guard）的分工：

- 遮盖负责"模型看不到原值"：模型输入、渲染提示、请求/评估/审计中只有普通占位符
  （⟦PHONE#001⟧），原值经加密只落在 ``guard_secrets``。
- 化名域负责"授权后能跨请求统计"：管理员把字段挂到某个化名域后，被遮盖原值在
  域内按**代次**分配随机、不透明、不可离线枚举的别名；聚合任务经授权后按别名
  分组计数。**别名永远不进入模型输入**，也不出现在普通请求查询、审计、证据包/
  下载文件中——只出现在聚合任务的结果里。

核心不变量：

- **同域关联**：同一原值在同一域、同一代次内始终得到同一别名（去重 HMAC 以代次
  随机盐键控，库外无法由原值/摘要枚举）。
- **跨域隔离**：每个域、每个代次各自独立取盐；同一原值在不同域的别名互不相同，
  无法由一个域的别名推断另一个域（也无法推出原值）。
- **换代**：换代生成新的代次盐，新请求使用新代次；旧映射保留，旧统计永远按任务
  保存的代次集合计算。聚合任务在只读快照事务内固定"查询开始时的代次集合"，
  执行期间换代/写入不会让半批新别名混入。
- **停用**：域停用后拒绝一切新聚合查询，也不再为新请求分配别名；历史映射、任务
  与结果保留复查。
- **并发首次分配**：``(域, 代次, 去重HMAC)`` 唯一约束 + 写锁事务保证多人同时为
  首次出现的原值分配别名时只产生一个映射，后到者复用先到者的别名。
- **碰撞稳定改派**：别名码 = HMAC(代次盐, 原值) 对码空间取模；两原值同码时后到者
  确定性线性探测到下一个空闲码位，已有映射永不因碰撞改变。
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import re
import secrets as _secrets
import uuid
from typing import Any, Callable

from .db import get_conn, snapshot_tx, write_tx

_NAME_RE = re.compile(r"^[\w.\-一-龥][\w.\-一-龥 ]{0,63}$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
DEFAULT_ALIAS_SPACE = 1 << 20          # 2^20 ≈ 105 万，业务上碰撞可忽略
MIN_ALIAS_SPACE = 2
MAX_ALIAS_SPACE = 10_000_000


# ---------------------------------------------------------------- 异常


class AliasError(Exception):
    """化名域模块基类。"""


class AliasDomainError(AliasError):
    """400 级配置/入参错误。"""


class AliasNotFound(AliasError):
    """404。"""


class AliasConflict(AliasError):
    """409：并发 CAS 冲突 / 状态不允许操作（含已停用域拒绝新查询）。"""


class AliasUnauthorized(AliasError):
    """403：没有该域有效聚合授权。"""


class AliasSpaceExhausted(AliasError):
    """409：代次别名码空间已用尽（极小空间碰撞验证场景）。"""


# ---------------------------------------------------------------- 基础工具


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _audit(c, actor: str, action: str, entity: str, eid: str, detail: str = ""):
    c.execute("INSERT INTO audit_log(actor,action,entity,entity_id,detail) "
              "VALUES (?,?,?,?,?)", (actor, action, entity, eid, detail))


def _b36(n: int) -> str:
    """非负整数 → 小写 base36。"""
    if n == 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def alias_code_width(alias_space: int) -> int:
    """别名码定宽：同一代次内等宽，字典序与数值序一致。"""
    return max(1, len(_b36(int(alias_space) - 1)))


def format_alias(prefix: str, code: int, space: int) -> str:
    return f"{prefix}{_b36(code).zfill(alias_code_width(space))}"


def _hmac_digest(secret: str, purpose: bytes, raw: str) -> bytes:
    return _hmac.new(secret.encode("utf-8"), purpose + b"|" + raw.encode("utf-8"),
                     hashlib.sha256).digest()


def dedup_hmac(secret: str, raw: str) -> str:
    """原值去重指纹：HMAC-SHA256(代次随机盐, 'dedup'|原值)。

    用**代次随机盐**键控而非裸哈希：库外没有盐就无法对字典/手机号空间做离线枚举；
    代次轮换盐即换，旧 HMAC 与新 HMAC 天然不可关联。
    """
    return _hmac_digest(secret, b"dedup", raw).hex()


def preferred_slot(secret: str, raw: str, space: int) -> int:
    """首选别名码位：HMAC(代次盐, 'slot'|原值) 对码空间取模（确定性）。"""
    return int.from_bytes(_hmac_digest(secret, b"slot", raw), "big") % int(space)


# ============================================================ 域配置 / 换代 / 停用


def _domain_row(c, domain_id: str):
    row = c.execute("SELECT * FROM alias_domains WHERE domain_id=?",
                    (domain_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"化名域不存在: {domain_id}")
    return row


def _validate_fields(fields: Any) -> list[str]:
    if isinstance(fields, str):
        fields = [fields]
    if not isinstance(fields, list) or not fields:
        raise AliasDomainError("关联字段 fields 必须是非空字符串数组")
    out = []
    for f in fields:
        if not isinstance(f, str) or not f.strip():
            raise AliasDomainError("关联字段名不能为空")
        f = f.strip()
        if f != "*" and not re.fullmatch(r"[A-Za-z_][\w.]*", f):
            raise AliasDomainError(f"非法字段名: {f}")
        out.append(f.split(".", 1)[0])
    if len(set(out)) != len(out):
        raise AliasDomainError("关联字段不能重复")
    return out


def create_domain(family_id: str, name: str, fields: list[str], actor: str,
                  description: str = "", alias_prefix: str | None = None,
                  alias_space: int | None = None) -> dict:
    """管理员为模板族的指定字段创建化名域，并开启第 1 代（随机盐）。

    字段以顶层变量名为准（与遮盖规则的字段作用域一致）；``*`` 表示全部被遮盖
    字段。建议字段同时被某条 mask 规则覆盖——化名只分配给**被遮盖**的原值，
    模型输入始终是普通占位符。
    """
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise AliasDomainError("化名域名不能为空且只能含字母数字/中文/._-（≤64 字符）")
    flds = _validate_fields(fields)
    prefix = (alias_prefix or "A").strip()
    if not _PREFIX_RE.match(prefix):
        raise AliasDomainError("别名前缀只能是 1~8 位字母数字")
    space = int(alias_space) if alias_space is not None else DEFAULT_ALIAS_SPACE
    if not (MIN_ALIAS_SPACE <= space <= MAX_ALIAS_SPACE):
        raise AliasDomainError(
            f"别名码空间必须在 [{MIN_ALIAS_SPACE}, {MAX_ALIAS_SPACE}] 之间"
            "（小空间仅供碰撞验证，业务请用默认值）")
    domain_id = _uid("ald")
    gen_id = _uid("alg")
    secret = _secrets.token_hex(32)
    with write_tx() as c:
        fam = c.execute("SELECT 1 FROM families WHERE family_id=?", (family_id,)).fetchone()
        if not fam:
            raise AliasNotFound(f"模板族不存在: {family_id}")
        dup = c.execute("SELECT 1 FROM alias_domains WHERE family_id=? AND name=?",
                        (family_id, name)).fetchone()
        if dup:
            raise AliasConflict(f"该模板族已存在同名化名域: {name}")
        c.execute(
            """INSERT INTO alias_domains(domain_id,family_id,name,description,fields_json,
               status,alias_space,alias_prefix,current_gen,created_by)
               VALUES (?,?,?,?,?, 'active',?, ?, 1, ?)""",
            (domain_id, family_id, name, description,
             json.dumps(flds, ensure_ascii=False), space, prefix, actor))
        c.execute(
            """INSERT INTO alias_generations(generation_id,domain_id,gen,gen_secret,
               status,note,created_by) VALUES (?,?,1,?, 'active','首发代次',?)""",
            (gen_id, domain_id, secret, actor))
        _audit(c, actor, "alias.domain.create", "alias_domain", domain_id,
               f"family={family_id} name={name} fields={flds} space={space} "
               f"prefix={prefix} gen=1/{gen_id}")
    return get_domain(domain_id)


def rotate_domain(domain_id: str, actor: str, note: str = "",
                  expected_gen: int | None = None) -> dict:
    """换代：当前代次置 retired，开启 gen+1（新随机盐）。

    - 换代后新请求/新映射只进新代次；旧映射、旧聚合结果永不重写；
    - 可选 expected_gen 做 CAS，两人同时换代后到者得到 409；
    - 已停用域不能换代。
    """
    with write_tx() as c:
        d = _domain_row(c, domain_id)
        if d["status"] != "active":
            raise AliasConflict(f"化名域 {domain_id} 已停用，不能换代")
        if expected_gen is not None and d["current_gen"] != int(expected_gen):
            raise AliasConflict(
                f"并发冲突：代次已变化（当前 gen={d['current_gen']}，"
                f"提交基于 gen={expected_gen}），请刷新后重试（CAS 失败）")
        new_gen = int(d["current_gen"]) + 1
        new_id = _uid("alg")
        secret = _secrets.token_hex(32)
        cur = c.execute(
            "UPDATE alias_generations SET status='retired', retired_at=datetime('now') "
            "WHERE domain_id=? AND gen=? AND status='active'",
            (domain_id, d["current_gen"]))
        if cur.rowcount != 1:
            raise AliasConflict("并发冲突：当前代次状态已变化（CAS 失败）")
        c.execute(
            """INSERT INTO alias_generations(generation_id,domain_id,gen,gen_secret,
               status,note,created_by) VALUES (?,?,?,?, 'active',?,?)""",
            (new_id, domain_id, new_gen, secret, note, actor))
        c.execute("UPDATE alias_domains SET current_gen=? WHERE domain_id=?",
                  (new_gen, domain_id))
        _audit(c, actor, "alias.domain.rotate", "alias_domain", domain_id,
               f"gen {d['current_gen']} -> {new_gen}/{new_id} note={note}")
    return get_domain(domain_id)


def disable_domain(domain_id: str, actor: str, expected_version: int,
                   reason: str = "") -> dict:
    """停用域（revoke_version CAS，终态）。

    停用后：拒绝一切新聚合查询（409）、invoke 不再为其分配别名；历史映射、
    代次、任务与结果全部保留，可继续复查。不提供重新启用。
    """
    with write_tx() as c:
        d = _domain_row(c, domain_id)
        if d["status"] != "active":
            raise AliasConflict(f"化名域 {domain_id} 已处于停用态")
        cur = c.execute(
            "UPDATE alias_domains SET status='disabled', disabled_at=datetime('now'), "
            "disabled_by=?, revoke_version=revoke_version+1 WHERE domain_id=? "
            "AND status='active' AND revoke_version=?",
            (actor, domain_id, int(expected_version)))
        if cur.rowcount != 1:
            raise AliasConflict("并发冲突：域配置版本号已变化（CAS 失败），请刷新后重试")
        c.execute("UPDATE alias_generations SET status='retired', retired_at=datetime('now') "
                  "WHERE domain_id=? AND status='active'", (domain_id,))
        _audit(c, actor, "alias.domain.disable", "alias_domain", domain_id,
               f"gen={d['current_gen']} reason={reason}（停用后拒绝新查询，历史保留复查）")
    return get_domain(domain_id)


def get_domain(domain_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM alias_domains WHERE domain_id=?",
                             (domain_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"化名域不存在: {domain_id}")
    d = dict(row)
    d["fields"] = json.loads(d.pop("fields_json"))
    return d


def list_domains(family_id: str | None = None, include_disabled: bool = True) -> list[dict]:
    clauses, args = [], []
    if family_id is not None:
        clauses.append("family_id=?")
        args.append(family_id)
    if not include_disabled:
        clauses.append("status='active'")
    q = "SELECT * FROM alias_domains"
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY created_at"
    rows = get_conn().execute(q, tuple(args)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["fields"] = json.loads(d.pop("fields_json"))
        out.append(d)
    return out


def list_generations(domain_id: str) -> list[dict]:
    return [dict(r) for r in get_conn().execute(
        "SELECT generation_id,domain_id,gen,status,note,created_by,created_at,retired_at "
        "FROM alias_generations WHERE domain_id=? ORDER BY gen", (domain_id,)).fetchall()]


def _generation_secret(domain_id: str, gen: int) -> str:
    """代次随机盐（仅供服务端分配/测试使用；绝不通过 JSON/页面导出）。"""
    row = get_conn().execute(
        "SELECT gen_secret FROM alias_generations WHERE domain_id=? AND gen=?",
        (domain_id, gen)).fetchone()
    if not row:
        raise AliasNotFound(f"代次不存在: {domain_id} gen {gen}")
    return row["gen_secret"]


def _current_generation(c, domain_id: str):
    """调用方事务内取域当前代次行（含盐）。域必须 active。"""
    d = _domain_row(c, domain_id)
    if d["status"] != "active":
        return None
    return c.execute(
        "SELECT * FROM alias_generations WHERE domain_id=? AND gen=?",
        (domain_id, d["current_gen"])).fetchone()


def active_context(c, family_id: str) -> list[dict]:
    """invoke 路由事务内固定本请求要用的化名域上下文（域当前代次 + 盐）。

    随后请求执行期间发生换代不影响本请求：本请求只向这里读到的代次落别名。
    已停用域不在上下文内（停用后不再分配新别名）。
    """
    rows = c.execute(
        """SELECT d.domain_id,d.family_id,d.alias_space,d.alias_prefix,d.current_gen,
                  d.fields_json,g.generation_id,g.gen_secret
           FROM alias_domains d JOIN alias_generations g
             ON g.domain_id=d.domain_id AND g.gen=d.current_gen
           WHERE d.family_id=? AND d.status='active' AND g.status='active'""",
        (family_id,)).fetchall()
    out = []
    for r in rows:
        out.append({"domain_id": r["domain_id"], "space": r["alias_space"],
                    "prefix": r["alias_prefix"], "current_gen": r["current_gen"],
                    "generation_id": r["generation_id"], "secret": r["gen_secret"],
                    "fields": json.loads(r["fields_json"])})
    return out


# ============================================================ 别名分配（并发/碰撞）


def _mint_one(c, ctx: dict, raw: str) -> dict:
    """在调用方写事务内为一个原值取得（既有或新建）别名映射。

    并发安全：``(域,代次,dedup_hmac)`` 唯一 + 写锁串行——多人同时为首次出现的
    原值分配时，INSERT 冲突方 SELECT 复用先提交的映射，全局只有一个别名。
    碰撞：首选码位被占则线性探测下一个空闲码位；探测同样撞唯一约束时继续，
    已有映射在任何情况下都不被改写。
    """
    existing = c.execute(
        "SELECT * FROM alias_mappings WHERE domain_id=? AND generation_id=? AND dedup_hmac=?",
        (ctx["domain_id"], ctx["generation_id"], dedup_hmac(ctx["secret"], raw))).fetchone()
    if existing:
        return {"alias_code": existing["alias_code"], "alias_value": existing["alias_value"],
                "created": False}
    space = int(ctx["space"])
    slot = preferred_slot(ctx["secret"], raw, space)
    occupied = {r["alias_code"] for r in c.execute(
        "SELECT alias_code FROM alias_mappings WHERE domain_id=? AND generation_id=?",
        (ctx["domain_id"], ctx["generation_id"])).fetchall()}
    code = slot
    for _ in range(space):
        if code not in occupied:
            break
        code = (code + 1) % space
    else:
        raise AliasSpaceExhausted(
            f"化名域 {ctx['domain_id']} 代次 {ctx['current_gen']} 别名码空间 {space} "
            "已用尽，无法分配新别名（请换代或扩大码空间）")
    alias_value = format_alias(ctx["prefix"], code, space)
    mapping_id = _uid("alm")
    try:
        c.execute(
            """INSERT INTO alias_mappings(mapping_id,domain_id,generation_id,gen,
               dedup_hmac,alias_code,alias_value) VALUES (?,?,?,?,?,?,?)""",
            (mapping_id, ctx["domain_id"], ctx["generation_id"], ctx["current_gen"],
             dedup_hmac(ctx["secret"], raw), code, alias_value))
    except Exception:
        # 并发下唯一约束可能输给另一事务（dedup 唯一=同原值先到；code 唯一=同码先到）：
        # 复用先到原值映射，或继续探测下一空码。写锁串行下通常走不到，这里兜底。
        winner = c.execute(
            "SELECT * FROM alias_mappings WHERE domain_id=? AND generation_id=? AND dedup_hmac=?",
            (ctx["domain_id"], ctx["generation_id"], dedup_hmac(ctx["secret"], raw))).fetchone()
        if winner:
            return {"alias_code": winner["alias_code"], "alias_value": winner["alias_value"],
                    "created": False}
        raise
    return {"alias_code": code, "alias_value": alias_value, "created": True}


def _field_applies(domain_fields: list[str], top_field: str) -> bool:
    return "*" in domain_fields or top_field in domain_fields


def assign_for_request(c, request_id: str, family_id: str, tokens: list[dict],
                       domain_ctx: list[dict], actor: str = "system") -> list[dict]:
    """在 invoke 最终写事务内，把本次被遮盖原值按各域当前代次落别名与落点。

    ``tokens`` 是遮盖扫描的内存记录（含 raw，仅本事务内可见）。只按域关联字段
    过滤（顶层变量名），别名只写化名表，绝不回写 requests/遮盖映射/提示/输出。
    返回每域汇总（不含原值）：[{domain_id, generation_id, gen, distinct, occurrences}]。
    """
    if not domain_ctx or not tokens:
        return []
    # (domain_id) -> {(alias_code): {"alias_value", occurrences}}
    per_domain: dict[str, dict] = {}
    meta: dict[str, dict] = {}
    for ctx in domain_ctx:
        per_domain[ctx["domain_id"]] = {}
        meta[ctx["domain_id"]] = ctx
    minted_first: dict[str, set] = {d: set() for d in per_domain}
    for t in tokens:
        raw = t.get("raw")
        if raw is None:
            continue
        top = t.get("field") or t.get("path", "").split(".", 1)[0]
        for ctx in domain_ctx:
            if not _field_applies(ctx["fields"], top):
                continue
            m = _mint_one(c, ctx, raw)
            bucket = per_domain[ctx["domain_id"]]
            slot = bucket.get(m["alias_code"])
            if slot is None:
                bucket[m["alias_code"]] = {"alias_value": m["alias_value"], "occurrences": 1}
            else:
                slot["occurrences"] += 1
            if m["created"]:
                minted_first[ctx["domain_id"]].add(m["alias_code"])
    summary = []
    for ctx in domain_ctx:
        bucket = per_domain[ctx["domain_id"]]
        for code, item in bucket.items():
            c.execute(
                """INSERT INTO guard_request_aliases(request_id,family_id,domain_id,
                   generation_id,gen,alias_code,alias_value,occurrences)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (request_id, family_id, ctx["domain_id"], ctx["generation_id"],
                 ctx["current_gen"], code, item["alias_value"], item["occurrences"]))
        occ_total = sum(v["occurrences"] for v in bucket.values())
        if occ_total:
            _audit(c, actor, "alias.assign", "alias_domain", ctx["domain_id"],
                   f"request={request_id} gen={ctx['current_gen']} "
                   f"distinct={len(bucket)} occurrences={occ_total} "
                   f"new_mappings={len(minted_first[ctx['domain_id']])}")
        summary.append({"domain_id": ctx["domain_id"],
                        "generation_id": ctx["generation_id"], "gen": ctx["current_gen"],
                        "distinct": len(bucket), "occurrences": occ_total,
                        "new_mappings": len(minted_first[ctx["domain_id"]])})
    return [s for s in summary if s["occurrences"]]


# ============================================================ 聚合授权


def grant_analyst(domain_id: str, reviewer: str, actor: str, reason: str = "") -> dict:
    """授权一名分析人对该化名域发起授权聚合查询。幂等：已有未撤销授权返回原行。"""
    reviewer = (reviewer or "").strip()
    if not reviewer:
        raise AliasDomainError("分析人标识不能为空")
    with write_tx() as c:
        _domain_row(c, domain_id)
        existing = c.execute(
            "SELECT * FROM alias_domain_grants WHERE domain_id=? AND reviewer=? "
            "AND revoked_at IS NULL", (domain_id, reviewer)).fetchone()
        if existing:
            gid = existing["grant_id"]
        else:
            gid = _uid("adg")
            c.execute(
                """INSERT INTO alias_domain_grants(grant_id,domain_id,reviewer,granted_by,reason)
                   VALUES (?,?,?,?,?)""", (gid, domain_id, reviewer, actor, reason))
            _audit(c, actor, "alias.grant", "alias_grant", gid,
                   f"domain={domain_id} reviewer={reviewer}")
    return get_grant(gid)


def revoke_analyst(grant_id: str, expected_version: int, actor: str,
                   reason: str = "") -> dict:
    """撤销聚合授权（expected_version CAS）。撤销后立即不能发起新聚合任务。"""
    with write_tx() as c:
        row = c.execute("SELECT * FROM alias_domain_grants WHERE grant_id=?",
                        (grant_id,)).fetchone()
        if not row:
            raise AliasNotFound(f"聚合授权不存在: {grant_id}")
        if row["revoked_at"]:
            raise AliasConflict(f"授权 {grant_id} 已撤销")
        cur = c.execute(
            "UPDATE alias_domain_grants SET revoked_at=datetime('now'), revoked_by=?, "
            "reason=?, revoke_version=revoke_version+1 WHERE grant_id=? AND revoke_version=? "
            "AND revoked_at IS NULL",
            (actor, reason, grant_id, int(expected_version)))
        if cur.rowcount != 1:
            raise AliasConflict("并发冲突：授权版本号已变化（CAS 失败），请刷新后重试")
        _audit(c, actor, "alias.grant.revoke", "alias_grant", grant_id,
               f"domain={row['domain_id']} reviewer={row['reviewer']}")
    return get_grant(grant_id)


def get_grant(grant_id: str) -> dict:
    r = get_conn().execute("SELECT * FROM alias_domain_grants WHERE grant_id=?",
                           (grant_id,)).fetchone()
    if not r:
        raise AliasNotFound(f"聚合授权不存在: {grant_id}")
    return dict(r)


def list_grants(domain_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM alias_domain_grants"
    args: tuple = ()
    if domain_id:
        q += " WHERE domain_id=?"
        args = (domain_id,)
    return [dict(r) for r in get_conn().execute(
        q + " ORDER BY created_at DESC", args).fetchall()]


def _require_grant(c, domain_id: str, reviewer: str):
    g = c.execute(
        "SELECT * FROM alias_domain_grants WHERE domain_id=? AND reviewer=? "
        "AND revoked_at IS NULL", (domain_id, reviewer)).fetchone()
    if not g:
        raise AliasUnauthorized(
            f"分析人 {reviewer} 未获化名域 {domain_id} 的聚合授权（或授权已撤销），"
            "拒绝发起授权跨请求聚合")
    return g


# ============================================================ 授权聚合（固定代次集合）


def _aggregate_on_conn(c, domain_id: str, gen_ids: set[str],
                       window_from: str | None, window_until: str | None) -> list[dict]:
    """在给定连接（快照连接或普通连接）上按固定代次集合聚合。

    只输出别名与计数：绝不含原值、去重 HMAC 或其他可离线枚举原值的摘要。
    """
    sql = [
        "SELECT gra.gen AS gen, gra.alias_code AS alias_code,",
        "       gra.alias_value AS alias_value,",
        "       SUM(gra.occurrences) AS occurrence_count,",
        "       COUNT(DISTINCT gra.request_id) AS request_count,",
        "       MIN(r.created_at) AS first_seen_at, MAX(r.created_at) AS last_seen_at",
        "FROM guard_request_aliases gra JOIN requests r ON r.request_id=gra.request_id",
        "WHERE gra.domain_id=?",
    ]
    args: list[Any] = [domain_id]
    if gen_ids:
        sql.append("  AND gra.generation_id IN (%s)" % ",".join("?" for _ in gen_ids))
        args.extend(sorted(gen_ids))
    if window_from:
        sql.append("  AND r.created_at >= ?")
        args.append(window_from)
    if window_until:
        sql.append("  AND r.created_at < ?")
        args.append(window_until)
    sql.append("GROUP BY gra.gen, gra.alias_code ORDER BY gra.gen, occurrence_count DESC, "
               "gra.alias_code")
    return [dict(r) for r in c.execute("\n".join(sql), tuple(args)).fetchall()]


def create_aggregation_job(domain_id: str, reviewer: str, actor: str | None = None,
                           window_from: str | None = None,
                           window_until: str | None = None, note: str = "",
                           snapshot_hook: Callable | None = None) -> dict:
    """发起一次授权聚合。

    鉴权与代次集合固定：

    1. 域必须 active（停用域拒绝新查询，409）；分析人必须持有未撤销授权（403）；
    2. 在**只读快照事务**（WAL 同一 read mark）内标定"查询开始时的代次集合"
       （域当前代次及全部历史代次）并完成聚合读取——执行期间换代、新写入对本
       任务不可见，绝不会混入半批新别名；
    3. 结果在随后的写事务落库（只含别名与计数）。

    ``snapshot_hook`` 仅供测试：拿到快照后、聚合前回调（可在另一线程换代+写入，
    验证快照隔离）。
    """
    reviewer = (reviewer or "").strip()
    actor = actor or reviewer
    with write_tx() as c:
        d = _domain_row(c, domain_id)
        if d["status"] != "active":
            raise AliasConflict(
                f"化名域 {domain_id} 已于 {d['disabled_at']} 停用：拒绝新聚合查询；"
                "历史任务与结果仍可复查")
        _require_grant(c, domain_id, reviewer)

    groups: list[dict] = []
    gen_snapshot: dict = {}
    with snapshot_tx() as sc:
        gens = sc.execute(
            "SELECT generation_id,gen,status,created_at FROM alias_generations "
            "WHERE domain_id=? ORDER BY gen", (domain_id,)).fetchall()
        gen_rows = [dict(g) for g in gens]
        cutpoint = sc.execute("SELECT datetime('now') AS t").fetchone()["t"]
        gen_snapshot = {
            "domain_id": domain_id,
            "current_gen": max((g["gen"] for g in gen_rows), default=0),
            "generations": [{"generation_id": g["generation_id"], "gen": g["gen"],
                             "status": g["status"]} for g in gen_rows],
            "cutpoint": cutpoint,
            "window_from": window_from, "window_until": window_until,
        }
        if snapshot_hook is not None:
            snapshot_hook(sc, gen_snapshot)
        gen_ids = {g["generation_id"] for g in gen_rows}
        groups = _aggregate_on_conn(sc, domain_id, gen_ids, window_from, window_until)

    job_id = _uid("alj")
    occ_total = sum(int(g["occurrence_count"]) for g in groups)
    req_total = sum(int(g["request_count"]) for g in groups)
    with write_tx() as c:
        c.execute(
            """INSERT INTO alias_jobs(job_id,domain_id,family_id,created_by,
               gen_snapshot_json,window_from,window_until,status,group_count,
               occurrence_total,request_total,note)
               VALUES (?,?,?,?,?,?,?, 'completed',?,?,?,?)""",
            (job_id, domain_id, d["family_id"], reviewer,
             json.dumps(gen_snapshot, ensure_ascii=False, sort_keys=True),
             window_from, window_until, len(groups), occ_total, req_total, note))
        for g in groups:
            c.execute(
                """INSERT INTO alias_job_results(job_id,domain_id,gen,alias_value,
                   alias_code,occurrence_count,request_count,first_seen_at,last_seen_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (job_id, domain_id, g["gen"], g["alias_value"], g["alias_code"],
                 int(g["occurrence_count"]), int(g["request_count"]),
                 g["first_seen_at"], g["last_seen_at"]))
        _audit(c, actor, "alias.job.create", "alias_job", job_id,
               f"domain={domain_id} reviewer={reviewer} gens={gen_snapshot['generations']} "
               f"cutpoint={cutpoint} window=[{window_from or ''},{window_until or ''}) "
               f"groups={len(groups)} occurrences={occ_total} requests={req_total}")
    return get_job(job_id)


def get_job(job_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM alias_jobs WHERE job_id=?",
                             (job_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"聚合任务不存在: {job_id}")
    d = dict(row)
    d["gen_snapshot"] = json.loads(d.pop("gen_snapshot_json"))
    d["results"] = [dict(r) for r in get_conn().execute(
        "SELECT gen,alias_value,alias_code,occurrence_count,request_count,"
        "first_seen_at,last_seen_at FROM alias_job_results WHERE job_id=? "
        "ORDER BY gen, occurrence_count DESC, alias_code", (job_id,)).fetchall()]
    d["domain"] = get_domain(d["domain_id"])
    return d


def list_jobs(domain_id: str | None = None, limit: int = 100) -> list[dict]:
    q = ("SELECT j.*, d.name AS domain_name FROM alias_jobs j JOIN alias_domains d "
         "ON d.domain_id=j.domain_id")
    args: tuple = ()
    if domain_id:
        q += " WHERE j.domain_id=?"
        args = (domain_id,)
    q += " ORDER BY j.created_at DESC LIMIT ?"
    args = args + (limit,)
    out = []
    for r in get_conn().execute(q, args).fetchall():
        d = dict(r)
        d["gen_snapshot"] = json.loads(d.pop("gen_snapshot_json"))
        out.append(d)
    return out


def review_job(job_id: str) -> dict:
    """历史统计复查：按任务**保存的代次集合与时间窗**在当前库上重算，与落库结果
    逐组比对。

    换代后重算只统计保存代次（gen ≤ 快照 current_gen 且代次 id 在快照集合内）的
    数据，新代次别名不参与——旧统计永远按保存的代次复查；新数据不得改变旧结果。
    复查只暴露别名与计数（与原结果同级），不含原值/HMAC。
    """
    job = get_job(job_id)
    snap = job["gen_snapshot"]
    gen_ids = {g["generation_id"] for g in snap.get("generations", [])}
    recomputed = _aggregate_on_conn(get_conn(), job["domain_id"], gen_ids,
                                    snap.get("window_from"), snap.get("window_until"))
    stored = job["results"]
    key = lambda g: (g["gen"], g["alias_code"])
    rec_by_key = {key(g): g for g in recomputed}
    sto_by_key = {key(g): g for g in stored}
    diffs = []
    for k in sorted(set(rec_by_key) | set(sto_by_key)):
        a, b = rec_by_key.get(k), sto_by_key.get(k)
        if a is None:
            diffs.append({"gen": k[0], "alias_code": k[1], "kind": "missing_on_recompute",
                          "stored": b})
        elif b is None:
            diffs.append({"gen": k[0], "alias_code": k[1], "kind": "new_on_recompute",
                          "recomputed": a})
        elif (int(a["occurrence_count"]) != int(b["occurrence_count"])
              or int(a["request_count"]) != int(b["request_count"])):
            diffs.append({"gen": k[0], "alias_code": k[1], "kind": "count_mismatch",
                          "stored": {"occurrence_count": b["occurrence_count"],
                                     "request_count": b["request_count"]},
                          "recomputed": {"occurrence_count": a["occurrence_count"],
                                         "request_count": a["request_count"]}})
    return {
        "job_id": job_id, "match": not diffs, "diffs": diffs,
        "stored_summary": {"groups": len(stored),
                           "occurrences": job["occurrence_total"],
                           "requests": job["request_total"]},
        "recomputed_summary": {
            "groups": len(recomputed),
            "occurrences": sum(int(g["occurrence_count"]) for g in recomputed),
            "requests": sum(int(g["request_count"]) for g in recomputed)},
        "gen_snapshot": snap,
        "reviewed_at": get_conn().execute(
            "SELECT datetime('now') AS t").fetchone()["t"],
    }


def request_alias_summary(request_id: str) -> list[dict]:
    """调用复查页用：本请求向哪些化名域/代次贡献了多少落点。

    只给域、代次与计数，**不返回别名值**——跨请求别名关联只能走授权聚合页，
    逐请求浏览不得被用来手工关联。
    """
    rows = get_conn().execute(
        """SELECT gra.domain_id,d.name AS domain_name,gra.generation_id,gra.gen,
                  COUNT(*) AS slots,SUM(gra.occurrences) AS occurrences
           FROM guard_request_aliases gra JOIN alias_domains d ON d.domain_id=gra.domain_id
           WHERE gra.request_id=? GROUP BY gra.domain_id ORDER BY gra.domain_id""",
        (request_id,)).fetchall()
    return [dict(r) for r in rows]


def domain_mapping_counts(domain_id: str) -> list[dict]:
    """域配置页用：各代次已有多少不同原值映射（即不同别名数；不含原值）。"""
    rows = get_conn().execute(
        """SELECT g.gen,g.generation_id,g.status,
                  COUNT(m.mapping_id) AS mapping_count
           FROM alias_generations g LEFT JOIN alias_mappings m
             ON m.generation_id=g.generation_id
           WHERE g.domain_id=? GROUP BY g.generation_id ORDER BY g.gen""",
        (domain_id,)).fetchall()
    return [dict(r) for r in rows]
