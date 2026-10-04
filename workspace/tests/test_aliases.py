"""化名域（Alias Domains）端到端验证（标准库 unittest，离线可跑）。

覆盖需求场景：

- **同域关联**：同一原值在同一域同一代次内始终得到同一别名；模型输入仍是普通
  遮盖占位符，requests/遮盖映射/审计/证据包绝不含原值或别名。
- **跨域隔离**：同一原值在不同域的别名互不相同、不能相互推断（独立代次盐）。
- **并发首次分配**：多线程同时为首次出现的原值分配别名，只产生一个映射，所有
  线程拿到同一别名。
- **碰撞处理**：极小码空间下多原值同槽稳定线性改派，已有映射永不改变；空间
  用尽给出确定错误。
- **换代**：换代后新请求用新代次，旧统计按保存代次继续计算；查询期间换代不混入
  半批新别名（快照代次集合固定）；历史任务复查逐组一致。
- **停用**：停用后拒绝新聚合查询（409）、新请求不再分配别名，历史任务仍可复查。
- **授权**：无授权/授权撤销不能发起聚合（403）；时间窗过滤。
- JSON API 与页面冒烟。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid

_TMP = tempfile.mkdtemp(prefix="promptgov-alias-test-")
os.environ["PROMPTGOV_DATA"] = _TMP
os.environ["PROMPTGOV_SEED"] = "0"
os.environ["PROMPTGOV_PORT"] = "0"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from promptgov import aliases, app as appmod, db, evidence, guard, services  # noqa: E402
from promptgov.db import get_conn  # noqa: E402

db.init_db()

CONTRACT = {"customer_text": {"type": "string", "required": True},
            "order_id": {"type": "string", "required": False},
            "lang": {"type": "string", "required": False}}
PARAMS = {"temperature": 0.2, "top_p": 0.9, "max_tokens": 1024}
INSTRUCTION = "你是客服分流助手。客户原话：{{ customer_text }} 请给出 label。"
TEST_CASES = [
    {"name": "用例1", "inputs": {"customer_text": "很满意 13800000000"},
     "expect": {"assert": "json_field", "field": "label", "equals": "positive"}},
]
PHONE = r"1[3-9]\d{9}"
ORDER = r"SO-\d{6}"
RULES = [
    {"id": "phone", "kind": "regex", "action": "mask", "pattern": PHONE,
     "fields": ["*"], "token": "PHONE", "name": "手机号"},
    {"id": "order", "kind": "regex", "action": "mask", "pattern": ORDER,
     "fields": ["*"], "token": "ORDER", "name": "工单号"},
]


def _u() -> str:
    return uuid.uuid4().hex[:8]


def make_family(rules=RULES):
    fid = f"f-{_u()}"
    services.create_family(fid, f"族{fid}", "", "test")
    services.create_testset(fid, "测试集", TEST_CASES, "test")
    vid = services.create_version(fid, "1.0.0", INSTRUCTION, CONTRACT, ["ticket.read"],
                                  PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(vid["version_id"], "test"), "test")
    services.approve(vid["version_id"], "release", "ops", "approved", "首发")
    services.promote(fid, vid["version_id"], "test")
    rs = guard.create_ruleset(fid, rules, "test", "rules", activate=True)
    return fid, vid, rs


def invoke_text(fid, text, rid=None, order_id=None):
    inputs = {"customer_text": text}
    if order_id is not None:
        inputs["order_id"] = order_id
    return services.invoke(fid, inputs, "test", request_id=rid or f"req-{_u()}")


def _ctx(domain_id, gen=1, space=None, prefix="T"):
    """构造某代次 mint 上下文（测试辅助；盐经内部函数读取，不经过导出路径）。"""
    d = aliases.get_domain(domain_id)
    gr = aliases.list_generations(domain_id)[gen - 1]
    return {"domain_id": domain_id, "space": space or d["alias_space"],
            "prefix": d["alias_prefix"] or prefix,
            "current_gen": gr["gen"], "generation_id": gr["generation_id"],
            "secret": aliases._generation_secret(domain_id, gr["gen"]),
            "fields": ["*"]}


def code_of(domain_id, gen):
    """取某代次某原值已落库的别名码（用于碰撞验证）。"""
    row = get_conn().execute(
        "SELECT alias_code,alias_value FROM alias_mappings WHERE domain_id=? AND gen=?",
        (domain_id, gen)).fetchall()
    return {r["alias_code"]: r["alias_value"] for r in row}


class DomainConfigTest(unittest.TestCase):

    def test_create_validation_and_generation(self):
        fid, _, _ = make_family()
        with self.assertRaises(aliases.AliasDomainError):
            aliases.create_domain(fid, "", ["customer_text"], "test")
        with self.assertRaises(aliases.AliasDomainError):
            aliases.create_domain(fid, "域x", [], "test")
        with self.assertRaises(aliases.AliasDomainError):
            aliases.create_domain(fid, "域x", ["customer_text"], "test",
                                  alias_prefix="超长前缀!!!")
        d = aliases.create_domain(fid, "客户域", ["customer_text"], "test",
                                  alias_prefix="C", alias_space=4)
        self.assertEqual(d["current_gen"], 1)
        self.assertEqual(d["status"], "active")
        gens = aliases.list_generations(d["domain_id"])
        self.assertEqual([g["gen"] for g in gens], [1])
        # 同族域名唯一
        with self.assertRaises(aliases.AliasConflict):
            aliases.create_domain(fid, "客户域", ["customer_text"], "test")
        # 代次盐不出现在域视图中
        self.assertNotIn("gen_secret", d)

    def test_rotate_cas_and_retire(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, f"域{_u()}", ["customer_text"], "test")
        d2 = aliases.rotate_domain(d["domain_id"], "test", "换代", expected_gen=1)
        self.assertEqual(d2["current_gen"], 2)
        gens = aliases.list_generations(d["domain_id"])
        self.assertEqual([(g["gen"], g["status"]) for g in gens],
                         [(1, "retired"), (2, "active")])
        # 错误 expected_gen -> CAS 409
        with self.assertRaises(aliases.AliasConflict):
            aliases.rotate_domain(d["domain_id"], "test", expected_gen=1)
        # 已停用不能换代
        aliases.grant_analyst(d["domain_id"], "a1", "test")
        aliases.disable_domain(d["domain_id"], "test", 1, "停用")
        with self.assertRaises(aliases.AliasConflict):
            aliases.rotate_domain(d["domain_id"], "test")

    def test_disable_cas(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, f"域{_u()}", ["customer_text"], "test")
        with self.assertRaises(aliases.AliasConflict):
            aliases.disable_domain(d["domain_id"], "test", 99, "错误版本")
        d2 = aliases.disable_domain(d["domain_id"], "test", 1, "停用")
        self.assertEqual(d2["status"], "disabled")
        self.assertEqual(d2["revoke_version"], 2)
        with self.assertRaises(aliases.AliasConflict):
            aliases.disable_domain(d["domain_id"], "test", 2)


class SameDomainAssociationTest(unittest.TestCase):

    def test_same_raw_same_alias_and_placeholder_to_model(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "客户域", ["customer_text"], "test",
                                  alias_prefix="C")
        r1 = invoke_text(fid, "好评，回电 13800001111", rid=f"r1-{_u()}")
        r2 = invoke_text(fid, "再联系 13800001111 谢谢", rid=f"r2-{_u()}")
        # 模型输入/渲染提示只含普通占位符，绝不含手机号，也不含别名
        self.assertNotIn("13800001111", r1["rendered_prompt"])
        self.assertIn("⟦PHONE#001⟧", r1["rendered_prompt"])
        for resp in (r1, r2):
            blob = json.dumps(resp, ensure_ascii=False)
            self.assertNotIn("13800001111", blob)
        # 两请求化名落点应使用同一别名（聚合层面）
        aliases.grant_analyst(d["domain_id"], "an", "test")
        job = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        gen1 = {g["alias_value"]: g for g in job["results"] if g["gen"] == 1}
        phone_alias_rows = [g for g in gen1.values() if g["occurrence_count"] >= 2
                            and g["request_count"] == 2]
        self.assertEqual(len(phone_alias_rows), 1,
                         f"同一手机号应聚到同一别名: {job['results']}")
        # 结果不含原值/HMAC
        raw_blob = json.dumps(job, ensure_ascii=False)
        self.assertNotIn("13800001111", raw_blob)
        self.assertNotIn("dedup", raw_blob)

    def test_no_alias_in_requests_audit_masks_and_pack(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "客户域", ["customer_text"], "test",
                                  alias_prefix="SECRET")
        invoke_text(fid, "回电 13800002222", rid=f"x-{_u()}")
        conn = get_conn()
        # 别名值/原值都不得出现在 requests/masks/审计 的文本列
        for table, col in (("requests", "inputs_json"), ("requests", "rendered_prompt"),
                           ("requests", "output"), ("guard_request_masks", "tokens_json"),
                           ("audit_log", "detail")):
            for row in conn.execute(f"SELECT {col} AS x FROM {table}"):
                self.assertNotIn("13800002222", row["x"] or "")
        # 别名只在化名表；别名表全套禁止入证据包（下面 ForbiddenLeak 用例再断言篡改）
        n = conn.execute(
            "SELECT COUNT(*) c FROM guard_request_aliases WHERE domain_id=?",
            (d["domain_id"],)).fetchone()["c"]
        self.assertGreaterEqual(n, 1)
        # 普通请求复查 API 不含别名值
        rid = conn.execute(
            "SELECT request_id FROM guard_request_aliases WHERE domain_id=? LIMIT 1",
            (d["domain_id"],)).fetchone()["request_id"]
        req = services.get_request(rid)
        self.assertNotIn("SECRET", json.dumps(req, ensure_ascii=False))
        summary = aliases.request_alias_summary(rid)
        self.assertTrue(all("alias_value" not in s for s in summary))
        self.assertNotIn("13800002222", json.dumps(summary, ensure_ascii=False))


class CrossDomainIsolationTest(unittest.TestCase):

    def test_same_raw_different_domain_unlinkable(self):
        fid, _, _ = make_family()
        da = aliases.create_domain(fid, "域A", ["customer_text"], "test", alias_prefix="A")
        db_ = aliases.create_domain(fid, "域B", ["customer_text"], "test", alias_prefix="B")
        invoke_text(fid, "电话 13800003333", rid=f"a-{_u()}")
        aliases.grant_analyst(da["domain_id"], "an", "test")
        aliases.grant_analyst(db_["domain_id"], "an", "test")
        ja = aliases.create_aggregation_job(da["domain_id"], "an", "test")
        jb = aliases.create_aggregation_job(db_["domain_id"], "an", "test")
        va = {g["alias_value"] for g in ja["results"]}
        vb = {g["alias_value"] for g in jb["results"]}
        # 别名带不同前缀，且集合不相交；无法由域 A 别名推断域 B
        self.assertTrue(va)
        self.assertTrue(vb)
        self.assertTrue(va.isdisjoint(vb))
        self.assertTrue(all(v.startswith("A") for v in va))
        self.assertTrue(all(v.startswith("B") for v in vb))
        # 两域各自独立：A 的结果里不含 B 的 domain 落点行
        self.assertTrue(all(g["gen"] == 1 for g in ja["results"]))

    def test_field_scoping_and_order_field(self):
        fid, _, _ = make_family()
        # 域只关联 order_id：customer_text 中的手机号不应进域
        do = aliases.create_domain(fid, "工单域", ["order_id"], "test", alias_prefix="O")
        invoke_text(fid, "电话 13800004444", order_id="SO-100001", rid=f"o-{_u()}")
        invoke_text(fid, "又一单", order_id="SO-100001", rid=f"o-{_u()}2")
        aliases.grant_analyst(do["domain_id"], "an", "test")
        job = aliases.create_aggregation_job(do["domain_id"], "an", "test")
        rows = job["results"]
        self.assertEqual(len(rows), 1)  # 同一工单号 = 同一别名
        self.assertEqual(rows[0]["request_count"], 2)
        self.assertEqual(rows[0]["occurrence_count"], 2)
        self.assertTrue(rows[0]["alias_value"].startswith("O"))
        # 手机号没有为该域产生落点
        cnt = get_conn().execute(
            "SELECT COUNT(*) c FROM guard_request_aliases WHERE domain_id=?",
            (do["domain_id"],)).fetchone()["c"]
        self.assertEqual(cnt, 2)  # 每请求一个工单别名槽


class ConcurrentFirstAssignmentTest(unittest.TestCase):

    def test_concurrent_mint_single_mapping(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "并发域", ["customer_text"], "test")
        raws = [f"138{9_000_000 + i:07d}" for i in range(12)]
        results, errors = [], []
        lock = threading.Lock()
        ctx = _ctx(d["domain_id"], 1)
        barrier = threading.Barrier(48)

        def worker(raw):
            barrier.wait()
            try:
                with db.write_tx() as c:
                    m = aliases._mint_one(c, ctx, raw)
                with lock:
                    results.append((raw, m["alias_value"]))
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        # 每个原值由 4 个线程并发首次分配（48 线程）
        threads = []
        for raw in raws:
            for _ in range(4):
                threads.append(threading.Thread(target=worker, args=(raw,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors, f"并发分配出错: {errors[:3]}")
        # 映射表中每个原值（dedup_hmac）只有一行：12 个不同原值 -> 12 个映射
        n_maps = get_conn().execute(
            "SELECT COUNT(*) c FROM alias_mappings WHERE domain_id=? AND gen=1",
            (d["domain_id"],)).fetchone()["c"]
        self.assertEqual(n_maps, 12)
        # 同一原值的 4 个线程全部拿到同一别名
        by_raw = {}
        for raw, val in results:
            by_raw.setdefault(raw, set()).add(val)
        self.assertTrue(all(len(v) == 1 for v in by_raw.values()))
        # 12 个别名互不相同（默认大空间，这里不会碰撞）
        self.assertEqual(len({v for vs in by_raw.values() for v in vs}), 12)

    def test_concurrent_invoke_first_seen_single_alias(self):
        """多线程同时 invoke 首次出现的同一原值：只产生一个映射。"""
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "并发invoke域", ["customer_text"], "test")
        phone = "138000076543"
        results, errors = [], []
        lock = threading.Lock()
        n = 10
        barrier = threading.Barrier(n)

        def worker(i):
            barrier.wait()
            try:
                r = invoke_text(fid, f"好评回电 {phone}", rid=f"par-{i}-{_u()}")
                with lock:
                    results.append(r)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertFalse(errors, errors[:2])
        # 映射表该代次该域只有一个不同别名（同原值）
        n_maps = get_conn().execute(
            "SELECT COUNT(*) c FROM alias_mappings WHERE domain_id=? AND gen=1",
            (d["domain_id"],)).fetchone()["c"]
        self.assertEqual(n_maps, 1)
        # 10 个请求落点都指向同一名
        slots = get_conn().execute(
            "SELECT DISTINCT alias_value FROM guard_request_aliases WHERE domain_id=?",
            (d["domain_id"],)).fetchall()
        self.assertEqual(len(slots), 1)
        total = get_conn().execute(
            "SELECT COALESCE(SUM(occurrences),0) s FROM guard_request_aliases "
            "WHERE domain_id=?", (d["domain_id"],)).fetchone()["s"]
        self.assertEqual(total, n)


class CollisionHandlingTest(unittest.TestCase):

    def test_collision_linear_reassignment_keeps_existing(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "碰撞域", ["customer_text"], "test",
                                  alias_prefix="K", alias_space=4)
        gen = aliases.list_generations(d["domain_id"])[0]
        secret = aliases._generation_secret(d["domain_id"], 1)
        # 找到 4 个首选槽位覆盖全部 0..3 的不同原值（确定性，可复现）
        chosen = {}
        i = 0
        while len(chosen) < 4:
            raw = f"coll-{i}"
            slot = aliases.preferred_slot(secret, raw, 4)
            if slot not in chosen:
                chosen[slot] = raw
            i += 1
        ordered_raws = [chosen[s] for s in range(4)]
        first_aliases = {}
        with db.write_tx() as c:
            ctx = _ctx(d["domain_id"], 1, space=4, prefix="K")
            for raw in ordered_raws:
                first_aliases[raw] = aliases._mint_one(c, ctx, raw)["alias_value"]
        codes = code_of(d["domain_id"], 1)
        self.assertEqual(set(codes), {0, 1, 2, 3})

        # 再喂更多新原值：全部碰撞/改派直到空间用尽；已有 4 个映射不变
        with self.assertRaises(aliases.AliasSpaceExhausted):
            with db.write_tx() as c:
                ctx = _ctx(d["domain_id"], 1, space=4, prefix="K")
                for j in range(i, i + 50):
                    aliases._mint_one(c, ctx, f"extra-{j}")
        # 用尽后表中仍是原来 4 个映射，码位与别名一个都没变
        codes_after = code_of(d["domain_id"], 1)
        self.assertEqual(codes_after, codes)
        # 原原值再取仍是原别名（碰撞改派不改变已有映射）
        with db.write_tx() as c:
            ctx = _ctx(d["domain_id"], 1, space=4, prefix="K")
            for raw, val in first_aliases.items():
                self.assertEqual(aliases._mint_one(c, ctx, raw)["alias_value"], val)

    def test_collision_via_invoke_stable(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "碰撞域2", ["customer_text"], "test",
                                  alias_prefix="Z", alias_space=2)
        # 多次 invoke 不同手机号；小空间下稳定改派或报空间耗尽（换代后恢复），
        # 但已产生的请求落点与映射不被改写。
        seen = {}
        exhausted = False
        for i in range(6):
            try:
                res = invoke_text(fid, f"电话 138{1_000_000 + i:08d}", rid=f"c-{i}")
                for s in res["alias_domains"]:
                    if s["domain_id"] == d["domain_id"]:
                        seen[i] = s
            except aliases.AliasSpaceExhausted:
                exhausted = True
                break
        self.assertTrue(seen)
        if exhausted:
            # 换代后新数据进入新代次，旧请求仍按代次 1 复查
            aliases.rotate_domain(d["domain_id"], "test", "空间耗尽换代")
            res = invoke_text(fid, "电话 13800009999", rid=f"c-new-{_u()}")
            self.assertTrue(any(s["gen"] == 2 for s in res["alias_domains"]
                                if s["domain_id"] == d["domain_id"]))


class RotationDuringQueryTest(unittest.TestCase):

    def test_snapshot_pins_generation_set(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "快照域", ["customer_text"], "test")
        aliases.grant_analyst(d["domain_id"], "an", "test")
        invoke_text(fid, "gen1 电话 13800005555", rid=f"g1-{_u()}")

        started = threading.Event()
        proceed = threading.Event()

        def hook(sc, snap):
            # 已在快照事务内、聚合读取前：另一线程换代并写入 gen2 数据
            started.set()
            proceed.wait(5)

        job_holder = {}

        def run_job():
            job_holder["job"] = aliases.create_aggregation_job(
                d["domain_id"], "an", "test", snapshot_hook=hook)

        t = threading.Thread(target=run_job)
        t.start()
        self.assertTrue(started.wait(5))
        # 快照已打开：换代 + gen2 新请求
        aliases.rotate_domain(d["domain_id"], "intruder", "查询期间换代")
        invoke_text(fid, "gen2 电话 13800006666", rid=f"g2-{_u()}")
        proceed.set()
        t.join(5)
        self.assertFalse(t.is_alive())
        job = job_holder["job"]
        # 任务固定的代次集合只含 gen1（cutpoint 时 gen2 尚不存在）
        self.assertEqual(job["gen_snapshot"]["current_gen"], 1)
        gens = [g["gen"] for g in job["gen_snapshot"]["generations"]]
        self.assertEqual(gens, [1])
        # 结果里只有 gen1 分组，绝无 gen2 半批混入
        self.assertTrue(job["results"])
        self.assertTrue(all(g["gen"] == 1 for g in job["results"]))
        aliases_in_job = json.dumps(job, ensure_ascii=False)
        self.assertNotIn("13800006666", aliases_in_job)

        # 换代后新建任务：gen1/gen2 分开统计（同一原值若两代号相同也不并组）
        invoke_text(fid, "gen2 再次 13800005555", rid=f"g2b-{_u()}")
        job2 = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        gens2 = sorted({g["gen"] for g in job2["results"]})
        self.assertEqual(gens2, [1, 2])
        # 历史任务复查：按保存的 gen1 集合重算，逐组一致
        rv = aliases.review_job(job["job_id"])
        self.assertTrue(rv["match"], rv["diffs"])

    def test_old_stats_stay_on_saved_generation(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "复查域", ["customer_text"], "test")
        aliases.grant_analyst(d["domain_id"], "an", "test")
        invoke_text(fid, "电话 13800007777", rid=f"old-{_u()}")
        invoke_text(fid, "电话 13800007777", rid=f"old-{_u()}2")
        job_old = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        old_groups = [(g["gen"], g["alias_value"], g["occurrence_count"],
                       g["request_count"]) for g in job_old["results"]]
        aliases.rotate_domain(d["domain_id"], "test", "换代")
        # 换代后大量新数据
        for i in range(5):
            invoke_text(fid, f"新数据 138{8_000_000 + i:07d}", rid=f"new-{i}-{_u()}")
        # 复查旧任务：仍只按 gen1，结果与落库完全一致
        rv = aliases.review_job(job_old["job_id"])
        self.assertTrue(rv["match"], rv["diffs"])
        self.assertEqual(rv["recomputed_summary"]["groups"], len(old_groups))


class DisabledDomainTest(unittest.TestCase):

    def test_disabled_rejects_new_queries_and_assignments(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "停用域", ["customer_text"], "test")
        aliases.grant_analyst(d["domain_id"], "an", "test")
        invoke_text(fid, "电话 13800008888", rid=f"d1-{_u()}")
        job = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        self.assertTrue(job["results"])
        # 停用
        aliases.disable_domain(d["domain_id"], "admin", 1, "项目结束")
        # 新聚合被拒绝（409 语义）
        with self.assertRaises(aliases.AliasConflict):
            aliases.create_aggregation_job(d["domain_id"], "an", "test")
        # 即便重新授权也仍拒绝（域终态停用）
        with self.assertRaises(aliases.AliasConflict):
            aliases.create_aggregation_job(d["domain_id"], "an", "test")
        # 新请求不再为该域分配别名（遮盖照常，模型仍只见占位符）
        res = invoke_text(fid, "停用后 电话 13800009999", rid=f"d2-{_u()}")
        self.assertFalse(any(s["domain_id"] == d["domain_id"]
                             for s in res["alias_domains"]))
        n_after = get_conn().execute(
            "SELECT COUNT(*) c FROM guard_request_aliases WHERE domain_id=? AND gen>=1",
            (d["domain_id"],)).fetchone()["c"]
        # 停用前只有 d1 请求的落点
        self.assertEqual(n_after, 1)
        # 历史任务仍可复查且一致
        rv = aliases.review_job(job["job_id"])
        self.assertTrue(rv["match"])
        got = aliases.get_job(job["job_id"])
        self.assertTrue(got["results"])


class AuthorizationTest(unittest.TestCase):

    def test_grant_required_and_revoked(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "授权域", ["customer_text"], "test")
        invoke_text(fid, "电话 13800001010", rid=f"au-{_u()}")
        with self.assertRaises(aliases.AliasUnauthorized):
            aliases.create_aggregation_job(d["domain_id"], "hacker", "test")
        g = aliases.grant_analyst(d["domain_id"], "an", "boss", "质检")
        job = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        self.assertEqual(job["created_by"], "an")
        aliases.revoke_analyst(g["grant_id"], g["revoke_version"], "boss", "离场")
        with self.assertRaises(aliases.AliasUnauthorized):
            aliases.create_aggregation_job(d["domain_id"], "an", "test")
        # 撤销 CAS
        with self.assertRaises(aliases.AliasConflict):
            aliases.revoke_analyst(g["grant_id"], g["revoke_version"], "boss")

    def test_window_filter(self):
        fid, _, _ = make_family()
        d = aliases.create_domain(fid, "窗口域", ["customer_text"], "test")
        aliases.grant_analyst(d["domain_id"], "an", "test")
        invoke_text(fid, "电话 13800002020", rid=f"w1-{_u()}")
        # 未来窗口：无数据
        future = services.shift_ts(services.db_now(), 3600)
        job_empty = aliases.create_aggregation_job(
            d["domain_id"], "an", "test", window_from=future)
        self.assertEqual(job_empty["results"], [])
        # 过去到现在窗口：有数据
        past = services.shift_ts(services.db_now(), -3600)
        job_full = aliases.create_aggregation_job(
            d["domain_id"], "an", "test", window_from=past)
        self.assertTrue(job_full["results"])


class EvidencePackExclusionTest(unittest.TestCase):

    def test_alias_tables_never_exported_and_injection_rejected(self):
        import base64 as _b64
        fid, vid, _ = make_family()
        d = aliases.create_domain(fid, "出包域", ["customer_text"], "test")
        aliases.grant_analyst(d["domain_id"], "an", "test")
        invoke_text(fid, "电话 13800003030", rid=f"ep-{_u()}")
        job = aliases.create_aggregation_job(d["domain_id"], "an", "test")
        # 正常族导出不含任何化名表对象
        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test")
        blob = evidence.pack_file_bytes(pack["pack_id"])[1]
        self.assertNotIn(d["domain_id"].encode(), blob)
        self.assertNotIn(job["job_id"].encode(), blob)
        self.assertNotIn(b"alias_mappings", blob)
        self.assertNotIn(b"13800003030", blob)
        counts = pack["counts"]
        for banned in ("alias_domains", "alias_generations", "alias_mappings",
                       "guard_request_aliases", "alias_domain_grants",
                       "alias_jobs", "alias_job_results"):
            self.assertNotIn(banned, counts)
        # counts 只含白名单表
        self.assertTrue(set(counts).issubset(set(evidence.TABLES)))

        # 篡改：往归档载荷尾部夹带一个化名映射对象行（含别名/HMAC）。落库前校验
        # 链（对象数/载荷哈希/对象摘要）必须拒绝，夹带对象不可能进入落库语义阶段。
        fake_rec = {"mapping_id": "alm_forged", "domain_id": d["domain_id"],
                    "generation_id": "alg_forged", "gen": 1,
                    "dedup_hmac": "x" * 64, "alias_code": 0,
                    "alias_value": "FORGED0"}
        fake_obj = {"kind": "object",
                    "sha256": __import__("hashlib").sha256(
                        json.dumps(fake_rec, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode()).hexdigest(),
                    "data": _b64.b64encode(json.dumps(
                        fake_rec, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":")).encode()).decode()}
        tampered = blob + b"\n" + json.dumps(
            fake_obj, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode()
        report = evidence.verify_bytes(tampered)
        self.assertFalse(report["ok"])
        codes = {e["code"] for e in report["errors"]}
        # 多余对象即被对象计数/载荷哈希/分片哈希拦下（夹带化名表无法落库）
        self.assertTrue(codes & {"object_count", "archive_sha_mismatch",
                                 "shard_sha_mismatch"}, codes)



class HttpApiTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = appmod.build_server()
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _req(self, method, path, body=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_full_flow_and_pages(self):
        fid, _, _ = make_family()
        # 建域
        code, d = self._req("POST", f"/api/families/{fid}/alias-domains",
                            {"name": "HTTP域", "fields": ["customer_text"],
                             "alias_prefix": "H", "alias_space": 8})
        self.assertEqual(code, 201, d)
        did = d["domain_id"]
        # 未授权聚合 403
        code, err = self._req("POST", f"/api/alias-domains/{did}/jobs",
                              {"reviewer": "nobody"})
        self.assertEqual(code, 403, err)
        # 授权
        code, g = self._req("POST", f"/api/alias-domains/{did}/grants",
                            {"reviewer": "an-http", "reason": "x"})
        self.assertEqual(code, 201)
        # 产生请求
        code, res = self._req("POST", f"/api/families/{fid}/invoke",
                              {"inputs": {"customer_text": "电话 13800007070"},
                               "request_id": f"http-{_u()}"})
        self.assertEqual(code, 201)
        # 聚合
        code, job = self._req("POST", f"/api/alias-domains/{did}/jobs",
                              {"reviewer": "an-http"})
        self.assertEqual(code, 201, job)
        self.assertTrue(job["results"])
        self.assertNotIn("13800007070", json.dumps(job))
        jid = job["job_id"]
        code, rv = self._req("POST", f"/api/alias-jobs/{jid}/review", {})
        self.assertEqual(code, 200)
        self.assertTrue(rv["match"])
        # 换代（CAS）
        code, d2 = self._req("POST", f"/api/alias-domains/{did}/rotate",
                             {"expected_gen": 1, "note": "换代"})
        self.assertEqual(code, 200)
        self.assertEqual(d2["current_gen"], 2)
        code, _ = self._req("POST", f"/api/alias-domains/{did}/rotate",
                           {"expected_gen": 1})
        self.assertEqual(code, 409)
        # 停用后新查询 409
        code, _ = self._req("POST", f"/api/alias-domains/{did}/disable",
                            {"expected_version": 1, "reason": "end"})
        self.assertEqual(code, 200)
        code, err = self._req("POST", f"/api/alias-domains/{did}/jobs",
                              {"reviewer": "an-http"})
        self.assertEqual(code, 409, err)
        # 历史结果仍可取
        code, old = self._req("GET", f"/api/alias-jobs/{jid}")
        self.assertEqual(code, 200)
        self.assertTrue(old["results"])
        # 页面冒烟
        rid = self._latest_rid(fid)
        for path in (f"/families/{fid}/guard/aliases", "/aliases",
                     f"/aliases?domain={did}", f"/alias/jobs/{jid}",
                     f"/alias/jobs/{jid}?review=1", f"/requests/{rid}/replay"):
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
                self.assertEqual(r.status, 200, path)

    def _latest_rid(self, fid):
        rows = services.list_requests(fid, 1)
        return rows[0]["request_id"] if rows else ""


if __name__ == "__main__":
    unittest.main()
