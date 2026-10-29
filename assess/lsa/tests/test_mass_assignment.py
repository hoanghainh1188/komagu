#!/usr/bin/env python3
"""Tests for the Tier 1 mass assignment scanner (Issue #269, part b).

Validates find_mass_assignment.py:
1. Whole-object binding per language (Node, PHP, Laravel, Java, .NET, Python,
   Ruby, Classic ASP, ColdFusion) and the explicit-field / allow-list shapes it
   must leave alone.
2. Model resolution across files: Laravel $fillable / $guarded, JPA @Entity,
   Entity Framework DbSet<T>; sensitive fields in an allow-list.
3. Privileged fields written from request input.
4. Candidate shape, deterministic ids, priorities, cache reuse and prescan output.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from find_mass_assignment import find_mass_assignment  # noqa: E402
from lsa_common import load_config  # noqa: E402
from scan_cache import ScanCache, compute_config_hash  # noqa: E402

RUN_PRESCAN = KIT / "scripts" / "run_prescan.py"


class _Repo(unittest.TestCase):
    def scan(self, files: dict, cache: ScanCache = None, root: Path = None) -> dict:
        if root is None:
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            root = Path(tmp.name)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        self.root = root
        return find_mass_assignment(root, load_config(None), cache=cache)

    def lines(self, res: dict, rel: str) -> list:
        return sorted(c["line"] for c in res["candidates"] if c["file"] == rel)


class TestWholeObjectBinding(_Repo):
    CASES = {
        "a.js": [
            ("User.findByIdAndUpdate(id, req.body, cb);", True),
            ("var u = new User(req.body);", True),
            ("Object.assign(user, req.body);", True),
            ("const u = { ...req.body, owner: me };", True),
            ("User.create(req.body);", True),
            ("User.update({ name: req.body.name });", False),
            ("const name = req.body.name;", False),
            ("res.json(req.body);", False),
        ],
        "b.php": [
            ("extract($_POST);", True),
            ("foreach ($_POST as $k => $v) { $user->$k = $v; }", True),
            ("$this->db->update('users', $this->input->post());", True),
            ("$user->fill($request->all());", True),
            ("$user->update($request->only(['name']));", False),
            ("$name = $_POST['name'];", False),
            ("foreach ($_POST['ids'] as $id) { delete($id); }", False),
        ],
        "c.py": [
            ("user = User(**request.json)", True),
            ("User.objects.create(**request.POST.dict())", True),
            ("user.__dict__.update(request.form)", True),
            ("for k, v in request.json.items():", True),
            ("user.name = request.json['name']", False),
            ("    fields = '__all__'", True),
            ("    fields = ['name', 'email']", False),
        ],
        "d.rb": [
            ("@user.update(params[:user])", True),
            ("User.new(params.require(:user).permit!)", True),
            ("@user.update(user_params)", False),
            ("params.require(:user).permit(:name, :email)", False),
        ],
        "e.asp": [
            ("For Each fld In Request.Form", True),
            ("name = Request.Form(\"name\")", False),
        ],
        "f.cfm": [
            ("<cfset StructAppend(user, form)>", True),
            ("<cfloop collection=\"#form#\" item=\"k\">", True),
            ("<cfset user.name = form.name>", False),
        ],
    }

    def test_language_shapes(self) -> None:
        for rel, cases in self.CASES.items():
            text = "\n".join(code for code, _ in cases) + "\n"
            res = self.scan({rel: text})
            want = [i for i, (_, hit) in enumerate(cases, 1) if hit]
            with self.subTest(file=rel):
                self.assertEqual(self.lines(res, rel), want, [c["code"] for c in res["candidates"]])


class TestModelResolution(_Repo):
    def test_laravel_guarded_fillable_and_sensitive_fillable(self) -> None:
        res = self.scan({
            "app/Models/User.php": "<?php\nclass User extends Model {\n    protected $guarded = [];\n}\n",
            "app/Models/Post.php": "<?php\nclass Post extends Model {\n    protected $fillable = ['title', 'body'];\n}\n",
            "app/Models/Team.php": "<?php\nclass Team extends Model {\n    protected $fillable = ['name', 'owner_id'];\n}\n",
            "app/Http/C.php": "<?php\nUser::create($request->all());\nPost::create($request->all());\nTeam::create($request->all());\nWidget::create($request->all());\n",
        })
        by_line = {c["line"]: c for c in res["candidates"] if c["file"] == "app/Http/C.php"}
        self.assertEqual(sorted(by_line), [2, 4, 5])
        self.assertEqual((by_line[2]["target"], by_line[2]["allowlist"], by_line[2]["priority"]), ("User", "none", "high"))
        self.assertEqual(by_line[4]["subtype"], "privileged_field_writable")
        self.assertEqual(by_line[4]["sensitive_fields"], ["owner_id"])
        self.assertEqual((by_line[5]["allowlist"], by_line[5]["priority"]), ("unknown", "medium"))

    def test_java_entity_binding_only(self) -> None:
        res = self.scan({
            "model/Account.java": "@Entity\npublic class Account { private String role; }\n",
            "web/C.java": (
                "class C {\n"
                "  public String a(@ModelAttribute Account account) { return null; }\n"
                "  public String b(@ModelAttribute RenameForm form) { return null; }\n"
                "  public Account c(@RequestBody Account account) { return account; }\n"
                "  void d() { BeanUtils.populate(account, request.getParameterMap()); }\n"
                "  void e() { BeanUtils.copyProperties(form, account); }\n"
                "}\n"
            ),
        })
        self.assertEqual(self.lines(res, "web/C.java"), [2, 4, 5, 6])

    def test_dotnet_dbset_entities_and_bind_include(self) -> None:
        res = self.scan({
            "Models/Db.cs": "public class Db : DbContext {\n  public DbSet<Customer> Customers { get; set; }\n}\n",
            "Controllers/C.cs": (
                "public class C : Controller {\n"
                "  public ActionResult Edit(Customer customer) { return null; }\n"
                "  public ActionResult Name([Bind(Include = \"Id,Name\")] Customer customer) { return null; }\n"
                "  public ActionResult Dto(CustomerForm form) { return null; }\n"
                "  public ActionResult R(int id) { TryUpdateModel(customer); return null; }\n"
                "  public ActionResult S(int id) { TryUpdateModel(customer, new[] { \"Name\" }); return null; }\n"
                "}\n"
            ),
        })
        self.assertEqual(self.lines(res, "Controllers/C.cs"), [2, 5])


    def test_diff_scope_still_sees_models_in_unchanged_files(self) -> None:
        files = {
            "model/Account.java": "@Entity\npublic class Account {}\n",
            "web/C.java": "class C {\n  public String a(@ModelAttribute Account account) { return null; }\n}\n",
            "web/D.java": "class D {\n  public String b(@ModelAttribute Account account) { return null; }\n}\n",
        }
        self.scan(files)
        cfg = load_config(None)
        cfg["scope"]["only_files"] = ["web/C.java"]
        res = find_mass_assignment(self.root, cfg)
        self.assertEqual([(c["file"], c["line"]) for c in res["candidates"]], [("web/C.java", 2)])

class TestPrivilegedFieldWritable(_Repo):
    def test_sensitive_field_from_request(self) -> None:
        res = self.scan({"p.php": "<?php\n$user->role = $_POST['role'];\n$user->nickname = $_POST['nick'];\n"
                                  "$order['price'] = $_GET['price'];\n$limit = 10;\n",
                         "q.js": "user.isAdmin = req.body.isAdmin;\nuser.ownerId = req.user.id;\n"})
        self.assertEqual(self.lines(res, "p.php"), [2, 4])
        self.assertEqual(self.lines(res, "q.js"), [1])
        c = next(c for c in res["candidates"] if c["file"] == "q.js")
        self.assertEqual((c["subtype"], c["priority"], c["sensitive_fields"]), ("privileged_field_writable", "high", ["isAdmin"]))


class TestCandidatesAndPipeline(_Repo):
    def test_shape_ids_redaction_and_summary(self) -> None:
        res = self.scan({"a.js": "x(req.body, 'password=hunter22');\nUser.create(req.body);\n", "b.php": "<?php\nextract($_POST);\n"})
        ids = [c["candidate_id"] for c in res["candidates"]]
        self.assertEqual(ids, ["M-0001", "M-0002"])
        first = res["candidates"][0]
        for key in ("file", "line", "language", "rule", "subtype", "target", "allowlist", "priority", "code", "sensitive_fields"):
            self.assertIn(key, first)
        self.assertEqual(res["summary"]["total"], 2)
        self.assertNotIn("hunter22", json.dumps(res))

    def test_cache_reuse(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "repo"
        cfg = load_config(None)
        files = {"a.js": "User.create(req.body);\n"}
        cache = ScanCache(cache_dir=Path(tmp.name) / "cache")
        cache.load(compute_config_hash(cfg))
        first = self.scan(files, cache, root)
        cache.save()
        cache2 = ScanCache(cache_dir=Path(tmp.name) / "cache")
        cache2.load(compute_config_hash(cfg))
        second = find_mass_assignment(root, cfg, cache=cache2)
        self.assertEqual(first["candidates"], second["candidates"])
        self.assertEqual(cache2.stats["mass_hits"], 1)

    def test_prescan_writes_candidates(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root, out = Path(tmp.name) / "repo", Path(tmp.name) / "out"
        self.scan({"a.js": "User.create(req.body);\n"}, root=root)
        res = subprocess.run([sys.executable, str(RUN_PRESCAN), str(root), str(out)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        doc = json.loads((out / "mass-assignment.candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["summary"]["total"], 1)
        self.assertIn("Mass assignment candidates: 1", res.stdout)


if __name__ == "__main__":
    unittest.main()
