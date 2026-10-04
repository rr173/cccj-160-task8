"""化名域（Alias Domains）：授权跨请求聚合用的稳定、可换代、可停用别名。

与 Guard 遮盖的分工（对应需求不变量）：

- **模型输入仍用普通占位符**：Guard 的 ``⟦TOKEN#001⟧`` 遮盖结果照常参与渲染与
  推理；化名**绝不**替换占位符，也不出现在渲染提示/模型输出/调用返回里。
- **化名只用于授权后的跨请求聚合**：被遮盖原值若落在某个**活动**化名域配置的
  字段上，请求落库事务内为其在该域当前代次分配（或复用）一个别名，并写
  ``guard_alias_links`` 关联行；聚合任务把不同请求里的同一原值按别名串起来。
- **同域稳定、跨域不可推断**：盲索引与别名槽位都由
  ``HMAC(主密钥, 域id|代|代次随机盐|原值)`` 派生——同域同代同原值永远同别名，
  不同域/不同代的派生材料不同，持库者也无法从一侧推断另一侧。
- **无原值、不可离线枚举**：七张化名表都不存原值；盲索引是键控 HMAC 而非裸
  哈希，没有主密钥（且不知道盐）无法枚举字典反推原值。七张表全部是证据包
  **禁止表**，查询结果/审计/下载文件只有别名标签与聚合计数。
- **换代**：新代次新随机盐、新命名空间；新数据走新代次，旧映射与旧统计按保存
  的代次继续计算。聚合任务在**创建时**固定"域→代次"集合，执行期间换代既被
  代次谓词排除、又被只读快照隔离，不可能混入半批新别名。
- **并发首次分配只产生一个映射**：所有分配在 ``BEGIN IMMEDIATE`` 写锁事务内，
  先按盲索引查既有映射（复用），再以唯一约束兜底；别名槽位偏好散列+线性探测
  稳定改派，**已有映射的槽位永不改变**。
- **停用**：域停用后拒绝新查询（创建/执行）与新分配；历史结果与历史映射保留，
  旧统计可按保存的代次复查。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets as _secrets
import uuid
from typing import Any, Callable

from .db import get_conn, snapshot_tx, write_tx

# ---------------------------------------------------------------- 异常


class AliasError(Exception):
    """化名域模块基类（HTTP 400 级配置错误）。"""


class AliasConflict(AliasError):
    """并发冲突 / 状态不允许（CAS、代次不匹配、任务状态；HTTP 409）。"""


class AliasDenied(AliasError):
    """未授权 / 授权已撤销 / 域已停用的新查询（HTTP 403）。"""


class AliasNotFound(AliasError):
    """404。"""


# ---------------------------------------------------------------- 原语

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
_SLOT_MIN, _SLOT_MAX = 16, 10_000_000


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _audit(c, actor: str, action: str, entity: str, eid: str, detail: str = ""):
    c.execute("INSERT INTO audit_log(actor,action,entity,entity_id,detail) "
              "VALUES (?,?,?,?,?)", (actor, action, entity, eid, detail))


def _hmac_key() -> bytes:
    """化名派生密钥：复用 Guard 主密钥（环境注入或实例随机密钥，均不落业务列），
    再做一次域分隔派生，避免与加密/其他用途的密钥复用。局部导入避免模块循环。"""
    from . import guard
    _, master = guard._master_key()
    return hmac.new(master, b"promptgov-alias-domain-v1", hashlib.sha256).digest()


def _hmac_hex(key: bytes, *parts: str) -> str:
    m = hmac.new(key, b"", hashlib.sha256)
    for p in parts:
        m.update(b"\x1f")
        m.update(p.encode("utf-8"))
    return m.hexdigest()


def blind_index(domain_id: str, generation: int, salt: str, raw: str) -> str:
    """原值的键控盲索引：HMAC(域密钥, 域|代|盐|原值)。

    盐是每代随机、与主密钥一起作为键控材料；即使域 id/代次公开，没有主密钥
    与盐也无法构造，因此持库者不能用候选原值字典离线枚举。
    """
    key = hmac.new(_hmac_key(), domain_id.encode(), hashlib.sha256).digest()
    return _hmac_hex(key, domain_id, str(generation), salt, raw)


def preferred_slot(domain_id: str, generation: int, salt: str, raw: str,
                   nslots: int) -> int:
    """原值的偏好别名槽位（与盲索引不同标签的独立散列），碰撞时线性探测。"""
    h = _hmac_hex(_hmac_key(), "slot", domain_id, str(generation), salt, raw)
    return int(h[:12], 16) % nslots


def _alias_label(code: str, slot: int) -> str:
    return f"{code}-{slot:04d}"


# ---------------------------------------------------------------- 域配置

def _domain_row(c, domain_id: str):
    row = c.execute("SELECT * FROM guard_alias_domains WHERE domain_id=?",
                    (domain_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"化名域不存在: {domain_id}")
    return row


def _norm_fields(fields: Any) -> list[str]:
    if isinstance(fields, str):
        fields = [fields]
    if not isinstance(fields, list) or not fields:
        raise AliasError("关联字段必须是非空字符串数组（契约顶层变量名）")
    out = []
    for f in fields:
        f = str(f or "").strip()
        if not f or not re.fullmatch(r"[\w.\-]+", f):
            raise AliasError(f"非法字段名: {f!r}")
        if "." in f:
            raise AliasError(f"化名域按契约顶层字段关联，不支持点路径: {f}")
        if f == "*":
            raise AliasError("化名域必须指定具体字段，不支持 '*' 全字段")
        if f not in out:
            out.append(f)
    return out


def create_domain(name: str, fields: list[str], actor: str, *,
                  code: str | None = None, note: str = "",
                  alias_slots: int = 4096) -> dict:
    """创建化名域并开启第 1 代（随机盐）。

    活动域的关联字段集合必须两两不相交——同一字段同时属于两个活动域会让
    "同域可关联、跨域不可推断"失去确定含义。已停用域占用的字段可以释放复用。
    """
    name = str(name or "").strip()
    if not name:
        raise AliasError("化名域名称不能为空")
    fields = _norm_fields(fields)
    slots = int(alias_slots)
    if not (_SLOT_MIN <= slots <= _SLOT_MAX):
        raise AliasError(f"别名槽位空间必须在 {_SLOT_MIN}~{_SLOT_MAX} 之间")
    if code:
        code = str(code).strip().upper()
        if not _CODE_RE.fullmatch(code):
            raise AliasError("域代码必须是 2~32 位大写字母/数字/下划线，且以字母开头")
    else:
        code = "ALD" + uuid.uuid4().hex[:8].upper()
    domain_id = _uid("ald")
    gen_id = _uid("alg")
    salt = _secrets.token_hex(16)
    with write_tx() as c:
        if c.execute("SELECT 1 FROM guard_alias_domains WHERE code=?",
                     (code,)).fetchone():
            raise AliasConflict(f"域代码 {code} 已存在")
        clash = c.execute(
            "SELECT domain_id,name,fields_json FROM guard_alias_domains "
            "WHERE status='active'").fetchall()
        for other in clash:
            of = set(json.loads(other["fields_json"]))
            if of & set(fields):
                raise AliasConflict(
                    f"字段 {sorted(of & set(fields))} 已属于活动化名域 "
                    f"{other['name']}（{other['domain_id']}）；同一活动字段只能"
                    "属于一个化名域")
        c.execute(
            """INSERT INTO guard_alias_domains(domain_id,code,name,fields_json,
               alias_slots,current_generation,status,note,created_by)
               VALUES (?,?,?,?,?,1,'active',?,?)""",
            (domain_id, code, name, json.dumps(fields, ensure_ascii=False), slots,
             note, actor))
        c.execute(
            """INSERT INTO guard_alias_generations(generation_id,domain_id,generation,
               salt,status,created_by) VALUES (?,?,1,?,'current',?)""",
            (gen_id, domain_id, salt, actor))
        _audit(c, actor, "alias.domain.create", "alias_domain", domain_id,
               f"code={code} fields={fields} slots={slots} gen=1")
    return get_domain(domain_id)


def get_domain(domain_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM guard_alias_domains WHERE domain_id=?",
                             (domain_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"化名域不存在: {domain_id}")
    d = dict(row)
    d["fields"] = json.loads(d.pop("fields_json"))
    return d


def list_domains(include_disabled: bool = True) -> list[dict]:
    q = "SELECT * FROM guard_alias_domains"
    if not include_disabled:
        q += " WHERE status='active'"
    q += " ORDER BY created_at"
    out = []
    for r in get_conn().execute(q).fetchall():
        d = dict(r)
        d["fields"] = json.loads(d.pop("fields_json"))
        out.append(d)
    return out


def list_generations(domain_id: str) -> list[dict]:
    """代次列表（盐不落任何导出/结果，页面也不展示）。"""
    rows = get_conn().execute(
        """SELECT g.generation_id,g.domain_id,g.generation,g.status,g.created_by,
                  g.created_at,
                  (SELECT COUNT(*) FROM guard_alias_mappings m
                    WHERE m.domain_id=g.domain_id AND m.generation=g.generation) AS mappings,
                  (SELECT COUNT(*) FROM guard_alias_links l
                    WHERE l.domain_id=g.domain_id AND l.generation=g.generation) AS links
           FROM guard_alias_generations g WHERE g.domain_id=?
           ORDER BY g.generation DESC""", (domain_id,)).fetchall()
    return [dict(r) for r in rows]


def rotate_domain(domain_id: str, actor: str, note: str = "",
                  expected_generation: int | None = None) -> dict:
    """换代：当前代次置 superseded，新建一代（新随机盐）并翻域当前代次指针。

    旧映射原封不动（旧统计按保存的代次继续计算）；新数据只走新代次，新旧代次
    之间盐不同、不可关联。可带 expected_generation 做 CAS。
    """
    with write_tx() as c:
        d = _domain_row(c, domain_id)
        if d["status"] != "active":
            raise AliasConflict(f"化名域已停用，不能换代：{domain_id}")
        cur = d["current_generation"]
        if expected_generation is not None and cur != int(expected_generation):
            raise AliasConflict(
                f"并发冲突：代次已变化（当前 g{cur}，期望 g{expected_generation}），"
                "CAS 失败，请刷新后重试")
        new_gen = cur + 1
        gen_id = _uid("alg")
        salt = _secrets.token_hex(16)
        curg = c.execute(
            "UPDATE guard_alias_generations SET status='superseded' "
            "WHERE domain_id=? AND generation=? AND status='current'",
            (domain_id, cur))
        if curg.rowcount != 1:
            raise AliasConflict("并发冲突：当前代次状态已变化（CAS 失败）")
        c.execute(
            """INSERT INTO guard_alias_generations(generation_id,domain_id,generation,
               salt,status,created_by) VALUES (?,?,?,?,'current',?)""",
            (gen_id, domain_id, new_gen, salt, actor))
        c.execute(
            "UPDATE guard_alias_domains SET current_generation=?, updated_at="
            "datetime('now') WHERE domain_id=?", (new_gen, domain_id))
        _audit(c, actor, "alias.domain.rotate", "alias_domain", domain_id,
               f"g{cur} -> g{new_gen} note={note}")
    return get_domain(domain_id)


def disable_domain(domain_id: str, actor: str, reason: str = "",
                   expected_generation: int | None = None) -> dict:
    """停用域（不可逆）：当前代次置 superseded、域 status=disabled。

    停用后不再为该域分配新别名、拒绝新聚合查询（创建/执行）；历史映射、关联
    与已完成的聚合结果全部保留，可按保存的代次复查旧统计。
    """
    with write_tx() as c:
        d = _domain_row(c, domain_id)
        if d["status"] == "disabled":
            raise AliasConflict(f"化名域 {domain_id} 已停用")
        cur = d["current_generation"]
        if expected_generation is not None and cur != int(expected_generation):
            raise AliasConflict(
                f"并发冲突：代次已变化（当前 g{cur}，期望 g{expected_generation}），"
                "CAS 失败，请刷新后重试")
        upd = c.execute(
            "UPDATE guard_alias_domains SET status='disabled', disabled_at="
            "datetime('now'), disabled_by=?, disable_reason=?, updated_at="
            "datetime('now') WHERE domain_id=? AND status='active'",
            (actor, reason, domain_id))
        if upd.rowcount != 1:
            raise AliasConflict("并发冲突：域状态已变化，停用失败（CAS 失败）")
        c.execute(
            "UPDATE guard_alias_generations SET status='superseded' "
            "WHERE domain_id=? AND status='current'", (domain_id,))
        _audit(c, actor, "alias.domain.disable", "alias_domain", domain_id,
               f"g{cur} 停用 reason={reason}")
    return get_domain(domain_id)


# ---------------------------------------------------------------- 分析师授权

def grant_analyst(domain_id: str, analyst: str, actor: str, reason: str = "") -> dict:
    """授权分析师使用某化名域做聚合。幂等：已存在有效授权则返回原行；
    历史上撤销过则重新发一张新授权（旧授权不复活）。"""
    analyst = str(analyst or "").strip()
    if not analyst:
        raise AliasError("分析师标识不能为空")
    with write_tx() as c:
        _domain_row(c, domain_id)
        existing = c.execute(
            "SELECT * FROM guard_alias_grants WHERE domain_id=? AND analyst=? "
            "AND revoked_at IS NULL", (domain_id, analyst)).fetchone()
        if existing:
            gid = existing["grant_id"]
        else:
            gid = _uid("alg_grant")
            c.execute(
                """INSERT INTO guard_alias_grants(grant_id,domain_id,analyst,
                   granted_by,reason) VALUES (?,?,?,?,?)""",
                (gid, domain_id, analyst, actor, reason))
            _audit(c, actor, "alias.grant", "alias_grant", gid,
                   f"domain={domain_id} analyst={analyst}")
    return get_grant(gid)


def revoke_analyst(grant_id: str, expected_version: int, actor: str,
                   reason: str = "") -> dict:
    """撤销分析授权（expected_version CAS）。撤销后不能再创建/执行新查询；
    已完成查询的历史结果不受影响（按创建时保存的授权快照复查）。"""
    with write_tx() as c:
        row = c.execute("SELECT * FROM guard_alias_grants WHERE grant_id=?",
                        (grant_id,)).fetchone()
        if not row:
            raise AliasNotFound(f"化名授权不存在: {grant_id}")
        if row["revoked_at"]:
            raise AliasConflict("该授权已撤销")
        cur = c.execute(
            "UPDATE guard_alias_grants SET revoked_at=datetime('now'), revoked_by=?, "
            "reason=?, revoke_version=revoke_version+1 WHERE grant_id=? AND "
            "revoke_version=? AND revoked_at IS NULL",
            (actor, reason, grant_id, int(expected_version)))
        if cur.rowcount != 1:
            raise AliasConflict("并发冲突：授权版本号已变化（CAS 失败），请刷新后重试")
        _audit(c, actor, "alias.grant.revoke", "alias_grant", grant_id,
               f"domain={row['domain_id']} analyst={row['analyst']}")
    return get_grant(grant_id)


def get_grant(grant_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM guard_alias_grants WHERE grant_id=?",
                             (grant_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"化名授权不存在: {grant_id}")
    return dict(row)


def list_grants(domain_id: str | None = None, include_revoked: bool = True) -> list[dict]:
    q = "SELECT * FROM guard_alias_grants"
    clauses, args = [], []
    if domain_id:
        clauses.append("domain_id=?"); args.append(domain_id)
    if not include_revoked:
        clauses.append("revoked_at IS NULL")
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY created_at DESC"
    return [dict(r) for r in get_conn().execute(q, tuple(args)).fetchall()]


def _active_grant(c, domain_id: str, analyst: str):
    return c.execute(
        "SELECT * FROM guard_alias_grants WHERE domain_id=? AND analyst=? "
        "AND revoked_at IS NULL", (domain_id, analyst)).fetchone()


# ---------------------------------------------------------------- 别名分配（请求落库事务内调用）

def active_field_map(c) -> dict[str, dict]:
    """契约顶层字段 -> 当前活动域（含当前代次与盐）。停用域不在内。"""
    rows = c.execute(
        """SELECT d.*, g.salt FROM guard_alias_domains d
           JOIN guard_alias_generations g
             ON g.domain_id=d.domain_id AND g.generation=d.current_generation
           WHERE d.status='active' AND g.status='current'""").fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        for f in json.loads(r["fields_json"]):
            out[f] = {"domain_id": r["domain_id"], "code": r["code"],
                      "generation": r["current_generation"], "salt": r["salt"],
                      "alias_slots": r["alias_slots"]}
    return out


def _assign_one(c, dom: dict, raw: str) -> dict:
    """在调用方写事务内为 (域, 当前代, 原值) 取别名映射：先复用既有，否则
    偏好槽位+线性探测新建。调用串行于写锁，且两个唯一约束兜底并发。"""
    did, gen, salt = dom["domain_id"], dom["generation"], dom["salt"]
    idx = blind_index(did, gen, salt, raw)
    existing = c.execute(
        "SELECT * FROM guard_alias_mappings WHERE domain_id=? AND generation=? "
        "AND value_index=?", (did, gen, idx)).fetchone()
    if existing:
        return dict(existing)
    nslots = int(dom["alias_slots"])
    taken = {r["alias_slot"] for r in c.execute(
        "SELECT alias_slot FROM guard_alias_mappings WHERE domain_id=? AND generation=?",
        (did, gen)).fetchall()}
    if len(taken) >= nslots:
        raise AliasError(f"化名域 {did} g{gen} 别名槽位已满，请换代后再分配")
    slot = preferred_slot(did, gen, salt, raw, nslots)
    while slot in taken:  # 稳定改派：线性探测，只影响新原值，已有映射不动
        slot = (slot + 1) % nslots
    alias_id = _uid("alm")
    c.execute(
        """INSERT INTO guard_alias_mappings(alias_id,domain_id,generation,value_index,
           alias_slot,alias_label) VALUES (?,?,?,?,?,?)""",
        (alias_id, did, gen, idx, slot, _alias_label(dom["code"], slot)))
    return {"alias_id": alias_id, "domain_id": did, "generation": gen,
            "value_index": idx, "alias_slot": slot,
            "alias_label": _alias_label(dom["code"], slot)}


def assign_for_request(c, request_id: str, tokens: list[dict]) -> int:
    """在 invoke 的**最终写事务**内调用：为字段属于活动化名域的遮盖占位符
    分配/复用别名并写关联行。返回写入的关联行数。

    - ``tokens`` 是 Guard 扫描记录（含 field/path/token/raw）；模型输入中的
      普通占位符原样不动，本函数只额外建立关联，不改写任何输入列；
    - 域/代次在本写事务内读取：与请求落库同一串行点，同一请求不可能跨代；
    - 同一 (request_id, token) 唯一，重试安全；重复请求走幂等重建，不到这里。
    """
    fmap = active_field_map(c)
    if not fmap:
        return 0
    n = 0
    for t in tokens:
        dom = fmap.get(t.get("field"))
        if not dom:
            continue
        mapping = _assign_one(c, dom, t["raw"])
        c.execute(
            """INSERT INTO guard_alias_links(request_id,domain_id,generation,alias_id,
               field,path,token) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(request_id,token) DO NOTHING""",
            (request_id, dom["domain_id"], dom["generation"], mapping["alias_id"],
             t["field"], t["path"], t["token"]))
        n += 1
    return n


def request_aliases(request_id: str) -> list[dict]:
    """某请求已建立的化名关联（仅别名标签/字段/代次；供复查页只读展示）。"""
    rows = get_conn().execute(
        """SELECT l.domain_id,d.code AS domain_code,l.generation,l.field,l.path,
                  l.alias_id,m.alias_label,l.created_at
           FROM guard_alias_links l
           JOIN guard_alias_domains d ON d.domain_id=l.domain_id
           JOIN guard_alias_mappings m ON m.alias_id=l.alias_id
           WHERE l.request_id=? ORDER BY l.id""", (request_id,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- 授权聚合查询

def create_query(analyst: str, actor: str, *, domain_ids: list[str] | None = None,
                 family_id: str | None = None) -> dict:
    """创建授权聚合任务并**固定查询开始时的代次集合**。

    代次固定在写锁事务内完成：读取每个域的 current_generation 与随机盐版本行，
    连同生效授权快照一起写进任务。随后换代只产生新代次行，执行谓词按固定代次
    过滤，新旧数据不可能在同一次聚合里混合。
    """
    analyst = str(analyst or "").strip()
    if not analyst:
        raise AliasError("analyst 不能为空")
    with write_tx() as c:
        if family_id:
            if not c.execute("SELECT 1 FROM families WHERE family_id=?",
                            (family_id,)).fetchone():
                raise AliasNotFound(f"模板族不存在: {family_id}")
        if domain_ids:
            domains = [_domain_row(c, d) for d in domain_ids]
        else:
            domains = c.execute(
                "SELECT * FROM guard_alias_domains WHERE status='active'").fetchall()
        if not domains:
            raise AliasError("没有可聚合的活动化名域")
        pinned, grant_ids = [], []
        for d in domains:
            if d["status"] != "active":
                raise AliasDenied(
                    f"化名域 {d['code']} 已停用，拒绝新聚合查询；历史结果可按保存"
                    "代次复查")
            g = _active_grant(c, d["domain_id"], analyst)
            if not g:
                raise AliasDenied(
                    f"分析师 {analyst} 未获得化名域 {d['code']} 的有效授权"
                    "（或授权已撤销），拒绝创建聚合查询")
            gen_row = c.execute(
                "SELECT generation_id FROM guard_alias_generations WHERE domain_id=? "
                "AND generation=? AND status='current'",
                (d["domain_id"], d["current_generation"])).fetchone()
            if not gen_row:
                raise AliasConflict(f"化名域 {d['code']} 当前代次状态异常")
            pinned.append({"domain_id": d["domain_id"], "code": d["code"],
                           "generation": d["current_generation"],
                           "generation_id": gen_row["generation_id"]})
            grant_ids.append(g["grant_id"])
        query_id = _uid("alq")
        c.execute(
            """INSERT INTO guard_alias_queries(query_id,analyst,family_id,
               domain_ids_json,pinned_json,grant_ids_json,created_by)
               VALUES (?,?,?,?,?,?,?)""",
            (query_id, analyst, family_id,
             json.dumps([p["domain_id"] for p in pinned]),
             json.dumps(pinned, ensure_ascii=False, sort_keys=True),
             json.dumps(grant_ids), actor))
        _audit(c, actor, "alias.query.create", "alias_query", query_id,
               f"analyst={analyst} family={family_id or '*'} domains="
               f"{[p['code'] + '@g' + str(p['generation']) for p in pinned]}")
    return get_query(query_id)


def get_query(query_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM guard_alias_queries WHERE query_id=?",
                             (query_id,)).fetchone()
    if not row:
        raise AliasNotFound(f"聚合任务不存在: {query_id}")
    d = dict(row)
    d["domain_ids"] = json.loads(d.pop("domain_ids_json"))
    d["pinned"] = json.loads(d.pop("pinned_json"))
    d["grant_ids"] = json.loads(d.pop("grant_ids_json"))
    return d


def list_queries(analyst: str | None = None, limit: int = 100) -> list[dict]:
    q = "SELECT * FROM guard_alias_queries"
    args: tuple = ()
    if analyst:
        q += " WHERE analyst=?"; args = (analyst,)
    q += " ORDER BY created_at DESC LIMIT ?"
    args = args + (limit,)
    out = []
    for r in get_conn().execute(q, args).fetchall():
        d = dict(r)
        d["pinned"] = json.loads(d.pop("pinned_json"))
        d.pop("domain_ids_json", None); d.pop("grant_ids_json", None)
        out.append(d)
    return out


_BATCH = 500


def run_query(query_id: str, actor: str = "api",
              progress: Callable[[int, int], None] | None = None) -> dict:
    """执行聚合：按任务**固定的代次集合**统计每个别名的请求数/出现数/成败数/
    首末出现时间。结果只有别名标签与计数。

    一致性：执行开始先在写事务内把 pinned→running 并复查域未停用、授权未撤销
    （停用/撤权后拒绝执行新查询）；随后所有读取在**单一只读快照事务**内完成，
    快照锚定执行时刻，期间换代/停用/新请求的提交对本任务一律不可见——配合
    固定代次谓词，保证不会混入半批新别名。每批之间调用 ``progress(done,total)``
    （测试借此在执行中换代，验证不混批）。
    """
    with write_tx() as c:
        q = c.execute("SELECT * FROM guard_alias_queries WHERE query_id=?",
                      (query_id,)).fetchone()
        if not q:
            raise AliasNotFound(f"聚合任务不存在: {query_id}")
        if q["status"] != "pinned":
            raise AliasConflict(
                f"聚合任务状态为 {q['status']}，仅 pinned 任务可执行（结果不可变，"
                "重查请新建任务）")
        pinned = json.loads(q["pinned_json"])
        for p in pinned:
            d = _domain_row(c, p["domain_id"])
            if d["status"] == "disabled":
                raise AliasDenied(
                    f"化名域 {p['code']} 已停用，拒绝执行新聚合；历史结果可按保存"
                    "代次复查")
            g = _active_grant(c, p["domain_id"], q["analyst"])
            if not g:
                raise AliasDenied(
                    f"分析师 {q['analyst']} 对化名域 {p['code']} 的授权已撤销/"
                    "不存在，拒绝执行聚合")
            # 固定代次行必须仍可按保存的 generation_id 解析（换代只会新增行）。
            gr = c.execute(
                "SELECT 1 FROM guard_alias_generations WHERE generation_id=?",
                (p["generation_id"],)).fetchone()
            if not gr:
                raise AliasConflict("固定代次缺失（数据异常），拒绝执行")
        c.execute("UPDATE guard_alias_queries SET status='running', started_at="
                  "datetime('now') WHERE query_id=? AND status='pinned'", (query_id,))
        family_id = q["family_id"]

    try:
        rows = _aggregate(query_id, family_id, progress)
    except Exception as exc:
        with write_tx() as c:
            c.execute("UPDATE guard_alias_queries SET status='error', error_reason=?, "
                      "finished_at=datetime('now') WHERE query_id=?",
                      (str(exc)[:300], query_id))
            _audit(c, actor, "alias.query.error", "alias_query", query_id, str(exc)[:200])
        raise

    with write_tx() as c:
        # 结果落库前清空（running 状态不会有旧行；防御性），整体单事务切换。
        c.execute("DELETE FROM guard_alias_results WHERE query_id=?", (query_id,))
        for r in rows:
            c.execute(
                """INSERT INTO guard_alias_results(query_id,domain_id,generation,
                   alias_id,alias_label,request_count,occurrence_count,success_count,
                   failure_count,first_seen_at,last_seen_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (query_id, r["domain_id"], r["generation"], r["alias_id"],
                 r["alias_label"], r["request_count"], r["occurrence_count"],
                 r["success_count"], r["failure_count"],
                 r["first_seen_at"], r["last_seen_at"]))
        upd = c.execute(
            "UPDATE guard_alias_queries SET status='done', result_count=?, finished_at="
            "datetime('now') WHERE query_id=? AND status='running'",
            (len(rows), query_id))
        if upd.rowcount != 1:
            raise AliasConflict("聚合任务状态已变化，结果放弃")
        _audit(c, actor, "alias.query.run", "alias_query", query_id,
               f"rows={len(rows)}（仅别名标签与计数）")
    return get_query(query_id)


def _aggregate(query_id: str, family_id: str | None,
               progress: Callable[[int, int], None] | None) -> list[dict]:
    """在单一只读快照连接内分批统计。快照对执行中的换代/停用/新写入不可见。"""
    out: list[dict] = []
    # 成败回执按"不同请求"计数（一个请求可有多条关联行，JOIN 不得放大计数）；
    # family 过滤在主统计与两个标量子查询中一致施加。子查询内使用独立别名，
    # 不与外层 FROM 的 l/r 冲突（SQLite 相关子查询不解析外层 FROM 别名）。
    outer_fam = "AND r.family_id=?" if family_id else ""

    def _links_sql() -> str:
        if family_id:
            req_join = "JOIN requests rqf ON rqf.request_id=ll.request_id"
            fam_cond = "AND rqf.family_id=?"
        else:
            req_join, fam_cond = "", ""
        return ("SELECT DISTINCT ll.request_id FROM guard_alias_links ll "
                f"{req_join} WHERE ll.alias_id=m.alias_id AND ll.domain_id=? "
                f"AND ll.generation=? {fam_cond}")

    sql = f"""
        SELECT m.alias_id,m.alias_label,
               COUNT(DISTINCT l.request_id) AS request_count,
               COUNT(l.id) AS occurrence_count,
               MIN(r.created_at) AS first_seen_at,
               MAX(r.created_at) AS last_seen_at,
               (SELECT COUNT(*) FROM feedback_receipts fb
                 WHERE fb.outcome='success' AND fb.request_id IN
                   ({_links_sql()})) AS success_count,
               (SELECT COUNT(*) FROM feedback_receipts fb
                 WHERE fb.outcome='failure' AND fb.request_id IN
                   ({_links_sql()})) AS failure_count
        FROM guard_alias_links l
        JOIN guard_alias_mappings m ON m.alias_id=l.alias_id
        JOIN requests r ON r.request_id=l.request_id
        WHERE l.domain_id=? AND l.generation=?
          AND m.alias_id IN ({{ph}}) {outer_fam}
        GROUP BY m.alias_id"""

    with snapshot_tx() as sc:
        pinned = sc.execute(
            "SELECT pinned_json FROM guard_alias_queries WHERE query_id=?",
            (query_id,)).fetchone()
        pins = json.loads(pinned["pinned_json"])
        total_alias = 0
        for p in pins:
            total_alias += sc.execute(
                "SELECT COUNT(*) c FROM guard_alias_mappings WHERE domain_id=? "
                "AND generation=?", (p["domain_id"], p["generation"])).fetchone()["c"]
        done = 0
        for p in pins:
            did, gen = p["domain_id"], p["generation"]
            # 按固定代次逐别名分页；只取本代内在关联表出现过的别名。
            alias_ids = [r["alias_id"] for r in sc.execute(
                "SELECT DISTINCT alias_id FROM guard_alias_links WHERE domain_id=? "
                "AND generation=? ORDER BY alias_id", (did, gen)).fetchall()]
            sub_args = [did, gen] + ([family_id] if family_id else [])
            for i in range(0, len(alias_ids), _BATCH):
                batch = alias_ids[i:i + _BATCH]
                ph = ",".join("?" * len(batch))
                args = [*sub_args, *sub_args,  # 两个标量子查询各一份参数
                        did, gen, *batch]
                if family_id:
                    args.append(family_id)
                cur = sc.execute(sql.format(ph=ph), args).fetchall()
                for r in cur:
                    out.append({"domain_id": did, "generation": gen,
                                "alias_id": r["alias_id"],
                                "alias_label": r["alias_label"],
                                "request_count": r["request_count"],
                                "occurrence_count": r["occurrence_count"],
                                "success_count": r["success_count"],
                                "failure_count": r["failure_count"],
                                "first_seen_at": r["first_seen_at"],
                                "last_seen_at": r["last_seen_at"]})
                done += len(batch)
                if progress:
                    progress(done, total_alias)
    out.sort(key=lambda r: (r["domain_id"], r["generation"], -r["request_count"],
                            r["alias_label"]))
    return out



def get_results(query_id: str, analyst: str | None = None) -> dict:
    """读聚合结果（只有别名标签与计数）。

    完成的历史结果可复查：给定 analyst 时要求与任务创建者一致（页面按会话参数
    传递）；不给 analyst（内部复查）直接返回。
    """
    q = get_query(query_id)
    if analyst and analyst != q["analyst"]:
        raise AliasDenied("只能查看自己创建的聚合任务结果")
    rows = get_conn().execute(
        "SELECT * FROM guard_alias_results WHERE query_id=? ORDER BY domain_id, "
        "generation, request_count DESC, alias_label", (query_id,)).fetchall()
    return {"query": {k: q[k] for k in
                      ("query_id", "analyst", "family_id", "status", "result_count",
                       "created_at", "started_at", "finished_at", "error_reason",
                       "pinned")},
            "results": [dict(r) for r in rows]}


def domain_overview(domain_id: str) -> dict:
    """域配置页数据：域、代次（仅状态/计数，无盐）、授权、各代别名计数。"""
    d = get_domain(domain_id)
    gens = list_generations(domain_id)
    grants = list_grants(domain_id)
    return {"domain": d, "generations": gens, "grants": grants}


def audit_stream(limit: int = 100) -> list[dict]:
    """化名域相关审计流（明细只有域/代/计数，绝无原值与盲索引）。"""
    rows = get_conn().execute(
        "SELECT * FROM audit_log WHERE action LIKE 'alias.%' "
        "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
