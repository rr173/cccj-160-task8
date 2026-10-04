"""化名域（Alias Domains）端到端验证（标准库 unittest，离线可跑）。

覆盖需求场景：
- 同域关联：同一原值在同一域同一代次内始终得到相同别名，跨请求聚合计数正确；
  模型输入仍是普通遮盖占位符，别名不进渲染提示/输出/调用返回。
- 跨域隔离：不同域（或不同代次）派生材料不同，别名与盲索引都不能相互推断。
- 并发首次分配：多线程同时为首次出现的原值分配别名，只产生一个映射、一个槽位。
- 碰撞处理：偏好槽碰撞时线性探测稳定改派，已有映射槽位不变，同原值重复分配复用。
- 查询期间换代：任务创建时固定代次集合，执行（分批）中换代只产生新代次行，
  本批结果只含固定代次，旧统计按保存代次继续；换代后的新值走新别名。
- 停用：停用域拒绝新查询（创建/执行）与新别名分配；历史映射与已完成结果保留复查。
- 授权：未授权/授权撤销不能创建或执行；授权快照随任务保存，撤销不改写历史结果。
- 零泄漏：原值与盲索引不出现在查询结果/审计/证据包（.pgpack 下载）/请求各列。
- JSON API 与页面冒烟（403/409 状态码、结果页只含别名与计数）。
"""
from __future__ import annotations

import base64 as _b64
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

from promptgov import alias, app as appmod, db, evidence, guard, services  # noqa: E402
from promptgov.db import get_conn, write_tx  # noqa: E402

db.init_db()

CONTRACT = {"customer_text": {"type": "string", "required": True},
            "contact_note": {"type": "string", "required": False},
            "lang": {"type": "string", "required": False}}
PARAMS = {"temperature": 0.2, "top_p": 0.9, "max_tokens": 1024}
INSTRUCTION = ("客户原话：{{ customer_text }} "
               "{% if contact_note %}备注：{{ contact_note }}{% endif %} 输出JSON")
PHONE = r"1[3-9]\d{9}"
RULES = [{"id": "phone", "kind": "regex", "action": "mask", "pattern": PHONE,
          "fields": ["*"], "token": "PHONE", "name": "手机号"}]


def _u() -> str:
    return uuid.uuid4().hex[:8]


def make_family():
    fid = f"f-{_u()}"
    services.create_family(fid, f"族{fid}", "", "test")
    services.create_testset(fid, "固定测试集", [
        {"name": "c1", "inputs": {"customer_text": "满意 13800000000"},
         "expect": {"assert": "contains", "value": "label"}}], "test")
    v = services.create_version(fid, "1.0.0", INSTRUCTION, CONTRACT, ["ticket.read"],
                                PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v["version_id"], "test"), "test")
    services.approve(v["version_id"], "release", "ops", "approved", "首发")
    services.promote(fid, v["version_id"], "test")
    guard.create_ruleset(fid, RULES, "test", "v1", activate=True)
    return fid, v["version_id"]


def invoke(fid, text, rid=None, note=None):
    inputs = {"customer_text": text}
    if note is not None:
        inputs["contact_note"] = note
    return services.invoke(fid, inputs, "test", request_id=rid or f"req-{_u()}")


def make_domain(fields=("customer_text",), code=None, slots=4096, analyst="ana"):
    # 化名域是全局对象且"活动域字段两两不相交"；各用例共享临时库，故先停用占用
    # 同字段的旧活动域（历史域保留，字段即可复用），使用例彼此独立。
    for old in alias.list_domains(include_disabled=False):
        if set(old["fields"]) & set(fields):
            alias.disable_domain(old["domain_id"], "test", "为新用例释放字段",
                                 expected_generation=old["current_generation"])
    d = alias.create_domain(f"域{code or _u()}", list(fields), "test",
                            code=code or f"D{_u().upper()}", alias_slots=slots)
    if analyst:
        alias.grant_analyst(d["domain_id"], analyst, "test")
    return d


def labels_of(rid):
    return {(x["domain_id"], x["generation"], x["alias_label"])
            for x in alias.request_aliases(rid)}


def run_and_get(analyst="ana", domain_ids=None, family_id=None):
    q = alias.create_query(analyst, "test", domain_ids=domain_ids, family_id=family_id)
    alias.run_query(q["query_id"], "test")
    return alias.get_results(q["query_id"], analyst)["results"], q


class SameDomainLinkTest(unittest.TestCase):

    def test_same_raw_same_alias_and_aggregation(self):
        fid, _ = make_family()
        d = make_domain()
        r1 = invoke(fid, "回访电话 13812345678 好评", "same-1")
        r2 = invoke(fid, "还是 13812345678 这个号码", "same-2")
        r3 = invoke(fid, "另一个号 13700001111", "same-3")
        a1, a2, a3 = labels_of("same-1"), labels_of("same-2"), labels_of("same-3")
        self.assertEqual(a1, a2)                       # 同原值→同别名
        self.assertNotEqual(a1, a3)                    # 不同原值→不同别名
        # 模型输入仍是普通占位符；别名不进提示/输出/返回
        self.assertIn("⟦PHONE#001⟧", r1["rendered_prompt"])
        lbl = next(iter(a1))[2]
        self.assertNotIn(lbl, r1["rendered_prompt"])
        self.assertNotIn(lbl, r1["output"])
        self.assertNotIn(lbl, json.dumps(r1, ensure_ascii=False))
        # 聚合：同别名请求数=2（出现次数也=2），另一个=1
        rows, _ = run_and_get(domain_ids=[d["domain_id"]])
        by_label = {r["alias_label"]: r for r in rows}
        self.assertEqual(by_label[lbl]["request_count"], 2)
        self.assertEqual(by_label[lbl]["occurrence_count"], 2)
        other = next(iter(a3))[2]
        self.assertEqual(by_label[other]["request_count"], 1)
        # 同原值再来一条，既有映射复用、计数变 3
        invoke(fid, "第三次 13812345678", "same-4")
        rows2, _ = run_and_get(domain_ids=[d["domain_id"]])
        self.assertEqual(next(r for r in rows2 if r["alias_label"] == lbl)
                         ["request_count"], 3)

    def test_model_never_sees_alias_and_response_no_alias_block(self):
        fid, _ = make_family()
        make_domain()
        res = invoke(fid, "号码 13812345678", "noleak-1")
        # 整个落库文本列里只有占位符，没有别名
        self.assertIn("PHONE", res["rendered_prompt"])
        row = get_conn().execute(
            "SELECT * FROM guard_alias_links WHERE request_id=?",
            ("noleak-1",)).fetchone()
        label = get_conn().execute(
            "SELECT alias_label FROM guard_alias_mappings WHERE alias_id=?",
            (row["alias_id"],)).fetchone()["alias_label"]
        for tbl, col in (("requests", "inputs_json"), ("requests", "rendered_prompt"),
                         ("requests", "output"), ("guard_request_masks", "tokens_json")):
            for r in get_conn().execute(f"SELECT {col} x FROM {tbl}"):
                self.assertNotIn(label, r["x"] or "")


class CrossDomainIsolationTest(unittest.TestCase):

    def test_domains_and_generations_unlinkable(self):
        fid, _ = make_family()
        da = make_domain(fields=("customer_text",), code="DOMA" + _u().upper())
        db_ = make_domain(fields=("contact_note",), code="DOMB" + _u().upper())
        invoke(fid, "号码 13812345678", "cross-1", note="号码 13812345678")
        la = {x["domain_id"]: x for x in alias.request_aliases("cross-1")}
        self.assertEqual(len(la), 2)
        self.assertNotEqual(la[da["domain_id"]]["alias_label"],
                            la[db_["domain_id"]]["alias_label"])
        # 盲索引也不同（不同域盐/材料）
        def vidx(domain_id, generation, raw):
            salt = get_conn().execute(
                "SELECT salt FROM guard_alias_generations WHERE domain_id=? "
                "AND generation=?", (domain_id, generation)).fetchone()["salt"]
            return alias.blind_index(domain_id, generation, salt, raw)
        self.assertNotEqual(vidx(da["domain_id"], 1, "13812345678"),
                            vidx(db_["domain_id"], 1, "13812345678"))
        # 换代：同原值的 g1/g2 盲索引、别名都不同
        alias.rotate_domain(da["domain_id"], "test")
        invoke(fid, "号码 13812345678", "cross-2")
        g2 = next(x for x in alias.request_aliases("cross-2")
                  if x["domain_id"] == da["domain_id"])
        self.assertEqual(g2["generation"], 2)
        self.assertNotEqual(g2["alias_label"], la[da["domain_id"]]["alias_label"])
        self.assertNotEqual(vidx(da["domain_id"], 1, "13812345678"),
                            vidx(da["domain_id"], 2, "13812345678"))


class ConcurrentFirstAssignTest(unittest.TestCase):

    def test_eight_threads_one_mapping(self):
        fid, _ = make_family()
        d = make_domain()
        raw = "13811112222"
        barrier = threading.Barrier(8)

        def w(i):
            barrier.wait()
            invoke(fid, f"并发 {raw}", f"conc-{i}")

        ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        got = {(x["generation"], x["alias_label"])
               for i in range(8) for x in alias.request_aliases(f"conc-{i}")}
        self.assertEqual(len(got), 1)
        row = get_conn().execute(
            "SELECT COUNT(*) c FROM guard_alias_mappings WHERE domain_id=? AND generation=1",
            (d["domain_id"],)).fetchone()
        self.assertEqual(row["c"], 1)
        links = get_conn().execute(
            "SELECT COUNT(*) c, COUNT(DISTINCT alias_id) a FROM guard_alias_links "
            "WHERE domain_id=? AND generation=1", (d["domain_id"],)).fetchone()
        self.assertEqual((links["c"], links["a"]), (8, 1))


class CollisionTest(unittest.TestCase):

    def test_stable_reassignment_keeps_existing(self):
        fid, _ = make_family()
        d = make_domain(slots=64)
        invoke(fid, "号 13833334444", "col-1")
        first = get_conn().execute(
            "SELECT alias_slot,value_index,salt FROM guard_alias_mappings m "
            "JOIN guard_alias_generations g ON g.domain_id=m.domain_id "
            "AND g.generation=m.generation WHERE m.domain_id=? AND m.generation=1",
            (d["domain_id"],)).fetchone()
        # 找一个偏好槽与首值相同的不同原值（候选须是 11 位手机号才能命中 mask）
        coll = next(f"139{n:08d}" for n in range(1, 10**8)
                    if len(f"139{n:08d}") == 11
                    and alias.preferred_slot(d["domain_id"], 1, first["salt"],
                                             f"139{n:08d}", 64)
                    == first["alias_slot"])
        invoke(fid, f"碰撞号 {coll}", "col-2")
        rows = get_conn().execute(
            "SELECT alias_slot,alias_label,value_index FROM guard_alias_mappings "
            "WHERE domain_id=? AND generation=1 ORDER BY alias_slot",
            (d["domain_id"],)).fetchall()
        slots = sorted(r["alias_slot"] for r in rows)
        self.assertEqual(len(slots), len(set(slots)))      # 槽位仍唯一
        # 首值槽位不变，次值线性探测到下一槽
        self.assertEqual(rows[0]["value_index"], first["value_index"])
        self.assertEqual(rows[0]["alias_slot"], first["alias_slot"])
        self.assertEqual(rows[1]["alias_slot"],
                         (first["alias_slot"] + 1) % 64)
        # 同碰撞原值再出现：复用第二槽，不产生第三映射
        invoke(fid, f"碰撞号 {coll} 再来", "col-3")
        self.assertEqual(get_conn().execute(
            "SELECT COUNT(*) c FROM guard_alias_mappings WHERE domain_id=? AND generation=1",
            (d["domain_id"],)).fetchone()["c"], 2)


class RotationDuringQueryTest(unittest.TestCase):

    def test_pinned_generation_no_half_batch(self):
        fid, _ = make_family()
        d = make_domain(slots=256)
        # g1：两个不同原值各一条
        invoke(fid, "旧号 13800000001", "rd-1")
        invoke(fid, "旧号 13800000002", "rd-2")
        alias.rotate_domain(d["domain_id"], "test")   # → g2
        invoke(fid, "新代号 13800000003", "rd-3")
        q = alias.create_query("ana", "test", domain_ids=[d["domain_id"]])
        self.assertEqual(q["pinned"][0]["generation"], 2)

        fired = {"n": 0}

        def progress(done, total):
            # 执行首批后换代到 g3 并写入 g3 数据：不得混入本任务
            if fired["n"] == 0:
                fired["n"] += 1
                alias.rotate_domain(d["domain_id"], "test", "during")
                invoke(fid, "执行中新代号 13800000004", "rd-4")
        alias.run_query(q["query_id"], "test", progress=progress)
        self.assertEqual(alias.get_domain(d["domain_id"])["current_generation"], 3)
        res = alias.get_results(q["query_id"], "ana")["results"]
        self.assertTrue(res)
        self.assertEqual({r["generation"] for r in res}, {2})  # 只有固定代次 g2
        seen = {r["alias_label"] for r in res}
        g3links = labels_of("rd-4")
        self.assertFalse(seen & {x[2] for x in g3links})
        # g1 历史统计仍可按保存代次复查：旧 g1 请求的 link 原样保留
        g1 = get_conn().execute(
            "SELECT COUNT(*) c FROM guard_alias_links WHERE domain_id=? AND generation=1",
            (d["domain_id"],)).fetchone()["c"]
        self.assertEqual(g1, 2)
        # 新数据走 g3
        self.assertEqual(next(iter(labels_of("rd-4")))[1], 3)

    def test_historical_results_remain_after_later_rotation(self):
        fid, _ = make_family()
        d = make_domain()
        invoke(fid, "号 13800000005", "hr-1")
        results1, q1 = run_and_get(domain_ids=[d["domain_id"]])
        self.assertEqual(len(results1), 1)
        alias.rotate_domain(d["domain_id"], "test")
        # 已完成任务结果不可变、仍可复查
        again = alias.get_results(q1["query_id"], "ana")["results"]
        self.assertEqual(again, results1)


class DisableTest(unittest.TestCase):

    def test_disabled_rejects_new_and_keeps_history(self):
        fid, _ = make_family()
        d = make_domain()
        invoke(fid, "停用前 13800000006", "dis-1")
        results, q = run_and_get(domain_ids=[d["domain_id"]])
        self.assertEqual(len(results), 1)
        alias.disable_domain(d["domain_id"], "test", "到期停用")
        # 拒绝新查询
        with self.assertRaises(alias.AliasDenied):
            alias.create_query("ana", "test", domain_ids=[d["domain_id"]])
        # 停用域不出现在"全部活动域"任务里：已无活动域→400；仍有活动域时，
        # 本停用域绝不参与（无授权则直接 403，同样说明停用域不被放行）。
        other_active = alias.list_domains(include_disabled=False)
        if not other_active:
            with self.assertRaises(alias.AliasError):
                alias.create_query("ana", "test")
        else:
            try:
                qq = alias.create_query("ana", "test")
            except alias.AliasDenied:
                pass
            else:
                self.assertNotIn(d["domain_id"], qq["domain_ids"])
        # 停用后不能再换代
        with self.assertRaises(alias.AliasConflict):
            alias.rotate_domain(d["domain_id"], "test")
        # 停用后新请求不再为该域分配别名（遮盖照常，模型仍见占位符）
        r = invoke(fid, "停用后 13800000006", "dis-2")
        self.assertIn("⟦PHONE#001⟧", r["rendered_prompt"])
        self.assertEqual(alias.request_aliases("dis-2"), [])
        # 历史映射与已完成结果仍可复查
        self.assertTrue(alias.request_aliases("dis-1"))
        old = alias.get_results(q["query_id"], "ana")["results"]
        self.assertEqual(len(old), 1)

    def test_revoke_blocks_create_and_run_but_keeps_history(self):
        fid, _ = make_family()
        d = make_domain()
        invoke(fid, "撤权前 13800000007", "rev-1")
        done, q_done = run_and_get(domain_ids=[d["domain_id"]])
        # 新任务创建后、执行前撤权 → 执行被拒，任务保持 pinned
        q = alias.create_query("ana", "test", domain_ids=[d["domain_id"]])
        grant = next(g for g in alias.list_grants(d["domain_id"])
                     if g["analyst"] == "ana" and not g["revoked_at"])
        alias.revoke_analyst(grant["grant_id"], grant["revoke_version"], "test")
        with self.assertRaises(alias.AliasDenied):
            alias.run_query(q["query_id"], "test")
        self.assertEqual(alias.get_query(q["query_id"])["status"], "pinned")
        # 未授权分析师不能创建
        with self.assertRaises(alias.AliasDenied):
            alias.create_query("intruder", "test", domain_ids=[d["domain_id"]])
        # 重新授权后历史完成结果仍可查，新任务也可建
        alias.grant_analyst(d["domain_id"], "ana", "test")
        self.assertEqual(
            alias.get_results(q_done["query_id"], "ana")["results"], done)
        alias.run_query(q["query_id"], "test")
        self.assertEqual(alias.get_query(q["query_id"])["status"], "done")
        # 撤销 CAS 版本号错误 → 409
        g2 = next(g for g in alias.list_grants(d["domain_id"])
                  if g["analyst"] == "ana" and not g["revoked_at"])
        with self.assertRaises(alias.AliasConflict):
            alias.revoke_analyst(g2["grant_id"], 999, "test")

    def test_field_overlap_and_config_validation(self):
        # 直接建两个同字段的活动域（不经 helper 的释放），第二个必须冲突
        c1 = f"OVLA{_u().upper()}"
        alias.create_domain("重叠1", ["customer_text"], "test", code=c1)
        with self.assertRaises(alias.AliasConflict):
            alias.create_domain("重叠2", ["customer_text"], "test",
                                code=f"OVLB{_u().upper()}")
        with self.assertRaises(alias.AliasError):
            alias.create_domain("x", ["*"], "test")
        with self.assertRaises(alias.AliasError):
            alias.create_domain("x", ["a.b"], "test")
        with self.assertRaises(alias.AliasError):
            alias.create_domain("x", [], "test")
        with self.assertRaises(alias.AliasError):
            alias.create_domain("x", ["z"], "test", alias_slots=4)


class NoLeakageTest(unittest.TestCase):
    """查询结果/审计/证据包下载文件都不得携带原值或可离线枚举的摘要。"""

    def test_results_and_audit_clean(self):
        fid, _ = make_family()
        d = make_domain()
        raw = "13866667777"
        invoke(fid, f"号 {raw}", "leak-1")
        invoke(fid, f"又号 {raw}", "leak-2")
        results, q = run_and_get(domain_ids=[d["domain_id"]])
        blob = json.dumps({"results": results,
                           "query": alias.get_query(q["query_id"])},
                          ensure_ascii=False)
        self.assertNotIn(raw, blob)
        # 结果不含盲索引/盐/request_id
        for r in results:
            self.assertEqual(set(r),
                             {"id", "query_id", "domain_id", "generation", "alias_id",
                              "alias_label", "request_count", "occurrence_count",
                              "success_count", "failure_count",
                              "first_seen_at", "last_seen_at"})
        # 审计明细不含映射 id（只记域/代/计数）
        self.assertFalse(any("alm_" in a["detail"] for a in alias.audit_stream(200)))
        # 审计流无原值、无盲索引、无盐
        audit_blob = json.dumps(alias.audit_stream(200), ensure_ascii=False)
        self.assertNotIn(raw, audit_blob)
        salt = get_conn().execute(
            "SELECT salt FROM guard_alias_generations WHERE domain_id=? AND generation=1",
            (d["domain_id"],)).fetchone()["salt"]
        self.assertNotIn(salt, audit_blob)
        for a in alias.audit_stream(200):
            self.assertNotIn("value_index", a["detail"])

    def test_evidence_pack_excludes_all_alias_tables(self):
        fid, _ = make_family()
        d = make_domain()
        invoke(fid, "号 13800000088 入包前", "alias-pack-1")
        results, _ = run_and_get(domain_ids=[d["domain_id"]])
        label = results[0]["alias_label"]
        raw = "13800000088"
        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test")
        blob = bytes(get_conn().execute(
            "SELECT archive_blob FROM evidence_packs WHERE pack_id=?",
            (pack["pack_id"],)).fetchone()[0])
        text = blob.decode("utf-8", errors="replace")
        # 下载文件绝不含原值/别名/盲索引/盐/化名表名对象
        self.assertNotIn(raw, text)
        self.assertNotIn(label, text)
        salt = get_conn().execute(
            "SELECT salt FROM guard_alias_generations WHERE domain_id=?",
            (d["domain_id"],)).fetchone()["salt"]
        self.assertNotIn(salt, text)
        report = evidence.verify_bytes(blob)
        self.assertTrue(report["ok"])
        tables = {it["table"] for it in report["manifest"]["items"]}
        for t in ("guard_alias_domains", "guard_alias_generations",
                  "guard_alias_mappings", "guard_alias_links", "guard_alias_grants",
                  "guard_alias_queries", "guard_alias_results", "guard_secrets",
                  "guard_credentials"):
            self.assertNotIn(t, tables)

    def test_forbidden_alias_object_tamper_rejected(self):
        """伪造夹带化名映射对象的包：落库前校验按禁止表拒绝（422）。"""
        fid, _ = make_family()
        make_domain()
        invoke(fid, "号 13800000099", "alias-tamper-1")
        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test")
        blob = bytes(get_conn().execute(
            "SELECT archive_blob FROM evidence_packs WHERE pack_id=?",
            (pack["pack_id"],)).fetchone()[0])
        lines = blob.split(b"\n")
        tampered = None
        for i, line in enumerate(lines):
            w = json.loads(line.decode())
            if w.get("kind") == "object":
                rec = json.loads(_b64.b64decode(w["data"]).decode())
                if rec.get("request_id") == "alias-tamper-1" and "tokens_json" in rec:
                    fake = {"id": 999001, "domain_id": "ald_x", "generation": 1,
                            "alias_id": "alm_x", "alias_label": "X-0001",
                            "request_count": 1}
                    w["data"] = _b64.b64encode(json.dumps(
                        fake, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":")).encode()).decode()
                    lines[i] = json.dumps(w, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode()
                    tampered = i
                    break
        self.assertIsNotNone(tampered)
        report = evidence.verify_bytes(b"\n".join(lines))
        # 夹带的禁止表对象在落库前被识别（清单表名非法/不在 TABLES 体系）
        self.assertFalse(report["ok"])


class FeedbackAggregateTest(unittest.TestCase):

    def test_success_failure_counts_distinct_requests(self):
        fid, _ = make_family()
        d = make_domain()
        invoke(fid, "回执号 13800000101", "fb-1")
        invoke(fid, "回执号 13800000101 第二次", "fb-2")  # 同原值
        invoke(fid, "另一 13800000202", "fb-3")
        # 一个请求内同一原值出现两次 → occurrence=2 但 request_count=1
        invoke(fid, "重复 13800000303 再重复 13800000303", "fb-4")
        results, _ = run_and_get(domain_ids=[d["domain_id"]])
        by = {r["alias_label"]: r for r in results}
        same = next(r for r in results if r["request_count"] == 2)
        self.assertEqual(same["occurrence_count"], 2)
        twice = next(r for r in results if r["occurrence_count"] == 2
                     and r["request_count"] == 1)
        self.assertEqual(twice["failure_count"], 0)
        self.assertEqual(len(by), 3)


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

    def test_full_api_and_pages(self):
        fid, _ = make_family()
        # 建域（用 contact_note 字段，避免与其他用例的活动 customer_text 域互斥）
        code, d = self._req("POST", "/api/guard/aliases",
                           {"name": "API域", "fields": ["lang"],
                            "code": f"API{_u().upper()}", "alias_slots": 256})
        self.assertEqual(code, 201)
        did = d["domain_id"]
        # 未授权聚合 → 403
        code, err = self._req("POST", "/api/guard/alias-queries",
                              {"analyst": "nobody", "domain_ids": [did]})
        self.assertEqual(code, 403)
        # 授权
        code, g = self._req("POST", f"/api/guard/aliases/{did}/grants",
                            {"analyst": "api-ana", "reason": "x"})
        self.assertEqual(code, 201)
        # 产生数据（号码写在 contact_note 字段以命中该域）
        self._req("POST", f"/api/families/{fid}/invoke",
                  {"inputs": {"customer_text": "API 客户 13800000000",
                              "lang": "回电标记 13812345001"},
                   "request_id": "alias-api-1"})
        self._req("POST", f"/api/families/{fid}/invoke",
                  {"inputs": {"customer_text": "API 客户再评 13800000000",
                              "lang": "还是标记 13812345001"},
                   "request_id": "alias-api-2"})
        # 不提供"按单个请求查别名"接口（防止已知请求直连聚合化名）；别名只经
        # 授权聚合结果出现。
        code, _ = self._req("GET", "/api/requests/alias-api-1/aliases")
        self.assertEqual(code, 404)
        # 创建+执行
        code, q = self._req("POST", "/api/guard/alias-queries",
                            {"analyst": "api-ana", "domain_ids": [did],
                             "family_id": fid})
        self.assertEqual(code, 201)
        qid = q["query_id"]
        code, q2 = self._req("POST", f"/api/guard/alias-queries/{qid}/run")
        self.assertEqual(code, 200)
        code, res = self._req(
            "GET", f"/api/guard/alias-queries/{qid}/results?analyst=api-ana")
        self.assertEqual(code, 200)
        self.assertEqual(res["results"][0]["request_count"], 2)
        self.assertNotIn("13812345001", json.dumps(res))
        # 重复执行 → 409（结果不可变）
        code, err = self._req("POST", f"/api/guard/alias-queries/{qid}/run")
        self.assertEqual(code, 409)
        # 换代 CAS：错误代次 409
        code, err = self._req("POST", f"/api/guard/aliases/{did}/rotate",
                              {"expected_generation": 99, "note": "x"})
        self.assertEqual(code, 409)
        code, _ = self._req("POST", f"/api/guard/aliases/{did}/rotate",
                            {"expected_generation": 1, "note": "例行换代"})
        self.assertEqual(code, 200)
        # 撤权 409（错误版本号）与正常撤销
        code, err = self._req("POST", f"/api/guard/alias-grants/{g['grant_id']}/revoke",
                              {"expected_version": 999})
        self.assertEqual(code, 409)
        code, _ = self._req("POST", f"/api/guard/alias-grants/{g['grant_id']}/revoke",
                            {"expected_version": g["revoke_version"]})
        self.assertEqual(code, 200)
        # 停用
        code, _ = self._req("POST", f"/api/guard/aliases/{did}/disable",
                            {"reason": "测试停用", "expected_generation": 2})
        self.assertEqual(code, 200)
        code, err = self._req("POST", "/api/guard/alias-queries",
                              {"analyst": "api-ana", "domain_ids": [did]})
        self.assertEqual(code, 403)
        # 页面冒烟
        for path in ("/guard/aliases", f"/guard/aliases/{did}",
                     "/guard/alias-queries",
                     f"/guard/alias-queries/{qid}?analyst=api-ana"):
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}{path}") as r:
                self.assertEqual(r.status, 200)
        # 结果页不含原值
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}"
                f"/guard/alias-queries/{qid}?analyst=api-ana") as r:
            html_text = r.read().decode()
        self.assertNotIn("13812345001", html_text)


if __name__ == "__main__":
    unittest.main()
