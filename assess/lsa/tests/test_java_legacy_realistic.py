#!/usr/bin/env python3
"""Tier 1 gaps found by comparing the pre-scan with real Java legacy applications (Issue #364).

Each test is a minimal reproduction of a pattern observed in a public application:
Apache Roller, Apache Struts 1, JEECG, JeeSite 1.x and OpenMRS 1.9. No third-party code is copied here.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "assess" / "lsa" / "scripts"))

from detect_stack import detect  # noqa: E402
from find_injection import find_injection  # noqa: E402
from lsa_common import iter_source_files, load_config  # noqa: E402
from map_routes import map_routes  # noqa: E402

CONFIG_XML_HEADER = '<?xml version="1.0"?>\n'


def write_repo(root: Path, files: Dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def scan_routes(files: Dict[str, str]) -> List[Dict]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write_repo(root, files)
        return map_routes(root, load_config(None), workers=1)["candidates"]


def scan_stack(files: Dict[str, str]) -> Dict:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write_repo(root, files)
        return detect(root, load_config(None))


def scan_injection(files: Dict[str, str]) -> Dict:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write_repo(root, files)
        return find_injection(root, load_config(None), workers=1)


def scoped_files(files: Dict[str, str]) -> List[str]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write_repo(root, files)
        return [rel for _, rel in iter_source_files(root, load_config(None))]


def paths_of(routes: List[Dict], stack: str) -> List[str]:
    return sorted(r["path"] for r in routes if r["stack"] == stack)


def controller(body: str, class_annotations: str = "") -> Dict[str, str]:
    source = (
        "package com.acme.web;\n"
        "@Controller\n"
        f"{class_annotations}\n"
        "public class ItemController {\n"
        f"{body}\n"
        "}\n"
    )
    return {"src/main/java/com/acme/web/ItemController.java": source}


class TestScope(unittest.TestCase):
    def test_java_package_named_like_a_build_directory_is_scanned(self) -> None:
        scanned = scoped_files({
            "src/main/java/com/acme/vendor/VendorController.java": "class A {}\n",
            "src/main/java/com/acme/modules/test/web/TestController.java": "class B {}\n",
            "src/com/acme/build/BuildDao.java": "class C {}\n",
        })
        self.assertEqual(len(scanned), 3)

    def test_jsp_in_a_web_directory_named_test_is_scanned(self) -> None:
        scanned = scoped_files({"src/main/webapp/test/mailer_test.jsp": "<html/>\n"})
        self.assertEqual(scanned, ["src/main/webapp/test/mailer_test.jsp"])

    def test_real_test_and_vendor_trees_stay_excluded(self) -> None:
        scanned = scoped_files({
            "src/test/java/com/acme/FooTest.java": "class T {}\n",
            "test/com/acme/BarTest.java": "class U {}\n",
            "target/classes/com/acme/Baz.java": "class V {}\n",
            "src/main/webapp/test/helper.js": "var a = 1;\n",
            "src/main/webapp/static/vendor/lib.js": "var b = 1;\n",
        })
        self.assertEqual(scanned, [])


class TestStackDetection(unittest.TestCase):
    def test_java_ternary_is_not_dotnet_mvc(self) -> None:
        profile = scan_stack({"src/A.java": "class A { Object c = ok ? other : Controller.NONE; }\n"})
        self.assertNotIn("dotnet-mvc", [s["id"] for s in profile["stacks"]])

    def test_commented_import_is_not_struts2(self) -> None:
        profile = scan_stack({"src/A.java": "//import com.opensymphony.xwork2.ognl.OgnlUtil;\nclass A {}\n"})
        self.assertNotIn("java-struts2", [s["id"] for s in profile["stacks"]])

    def test_hibernate_validator_is_not_the_orm(self) -> None:
        profile = scan_stack({"src/A.java": "import org.hibernate.validator.constraints.Length;\nclass A {}\n"})
        self.assertNotIn("java-hibernate", [s["id"] for s in profile["stacks"]])
        self.assertNotIn("Hibernate/JPA", profile["data_access"])

    def test_mybatis_sql_command_type_is_not_ado_net(self) -> None:
        profile = scan_stack({"src/A.java": "class A { SqlCommandType type; }\n"})
        self.assertNotIn("ADO.NET", profile["data_access"])

    def test_real_dotnet_and_orm_still_detected(self) -> None:
        profile = scan_stack({
            "Web/HomeController.cs": "class HomeController : Controller { SqlCommand c; }\n",
            "src/A.java": "import org.hibernate.Session;\nclass A {}\n",
        })
        self.assertIn("dotnet-mvc", [s["id"] for s in profile["stacks"]])
        self.assertIn("java-hibernate", [s["id"] for s in profile["stacks"]])
        self.assertIn("ADO.NET", profile["data_access"])


class TestXmlRoutes(unittest.TestCase):
    def test_commented_out_mappings_are_not_routes(self) -> None:
        web = CONFIG_XML_HEADER + (
            "<web-app>\n<!--\n<servlet><servlet-name>cxf</servlet-name><servlet-class>a.Cxf</servlet-class></servlet>\n"
            "<servlet-mapping><servlet-name>cxf</servlet-name><url-pattern>/cxf/*</url-pattern></servlet-mapping>\n-->\n</web-app>\n"
        )
        struts = CONFIG_XML_HEADER + (
            '<struts-config><action-mappings><action path="/live" type="a.Live"/>\n'
            '<!-- <action path="/dead" type="a.Dead"/> -->\n</action-mappings></struts-config>\n'
        )
        routes = scan_routes({"WEB-INF/web.xml": web, "WEB-INF/struts-config.xml": struts})
        self.assertEqual(paths_of(routes, "java-servlet"), [])
        self.assertEqual(paths_of(routes, "java-struts1"), ["/live.do"])

    def test_servlet_with_description_and_several_url_patterns(self) -> None:
        web = CONFIG_XML_HEADER + (
            "<web-app><servlet><description>x</description><servlet-name>s</servlet-name><servlet-class>com.acme.Img</servlet-class></servlet>\n"
            "<servlet-mapping><servlet-name>s</servlet-name><url-pattern>/a/*</url-pattern><url-pattern>/b/*</url-pattern></servlet-mapping>\n"
            "<servlet-mapping><servlet-name>s</servlet-name><url-pattern>/c/*</url-pattern></servlet-mapping></web-app>\n"
        )
        servlet = "package com.acme;\npublic class Img extends HttpServlet {\n  public void doGet(HttpServletRequest r) {}\n}\n"
        routes = scan_routes({"WEB-INF/web.xml": web, "src/com/acme/Img.java": servlet})
        self.assertEqual(paths_of(routes, "java-servlet"), ["/a/*", "/b/*", "/c/*"])
        self.assertTrue(all(r["handler"]["file"].endswith("Img.java") for r in routes))

    def test_handler_is_resolved_by_package_not_simple_name(self) -> None:
        struts = CONFIG_XML_HEADER + (
            '<struts-config><action-mappings><action path="/a" type="com.acme.one.ListAction"/>'
            '<action path="/b" type="com.acme.two.ListAction"/>'
            '<action path="/lib" type="org.other.ListAction"/></action-mappings></struts-config>\n'
        )
        routes = scan_routes({
            "WEB-INF/struts-config.xml": struts,
            "src/com/acme/one/ListAction.java": "package com.acme.one;\nclass ListAction {}\n",
            "src/com/acme/two/ListAction.java": "package com.acme.two;\nclass ListAction {}\n",
        })
        handlers = {r["path"]: r["handler"]["file"] for r in routes}
        self.assertEqual(handlers["/a.do"], "src/com/acme/one/ListAction.java")
        self.assertEqual(handlers["/b.do"], "src/com/acme/two/ListAction.java")
        self.assertEqual(handlers["/lib.do"], "WEB-INF/struts-config.xml")

    def test_struts2_included_file_and_custom_extension(self) -> None:
        main = CONFIG_XML_HEADER + (
            "<struts><include file=\"struts-order.xml\"/>\n"
            '<package name="m" namespace="/m"><action name="home" class="a.Home"/></package></struts>\n'
        )
        included = (
            CONFIG_XML_HEADER
            + '<!DOCTYPE struts PUBLIC "x" "y">\n<struts><package name="o" namespace="/o"><action name="view" class="a.View"/></package></struts>\n'
        )
        routes = scan_routes({
            "src/main/resources/struts.xml": main,
            "src/main/resources/struts-order.xml": included,
            "src/main/resources/struts.properties": "struts.action.extension=rol\n",
        })
        self.assertEqual(paths_of(routes, "java-struts2"), ["/m/home.rol", "/o/view.rol"])

    def test_struts2_extension_from_constant_with_blank_alternative(self) -> None:
        xml = CONFIG_XML_HEADER + (
            '<struts><constant name="struts.action.extension" value="do,,"/>\n'
            '<package name="m" namespace="/m"><action name="home" class="a.Home"/></package></struts>\n'
        )
        routes = scan_routes({"src/main/resources/struts.xml": xml})
        self.assertEqual(paths_of(routes, "java-struts2"), ["/m/home.do"])

    def test_struts1_module_prefix_comes_from_web_xml(self) -> None:
        web = CONFIG_XML_HEADER + (
            "<web-app><servlet><servlet-name>a</servlet-name><servlet-class>org.apache.struts.action.ActionServlet</servlet-class>\n"
            "<init-param><param-name>config/admin</param-name><param-value>/WEB-INF/admin/struts-config.xml</param-value></init-param>\n"
            "</servlet></web-app>\n"
        )
        admin = CONFIG_XML_HEADER + '<struts-config><action-mappings><action path="/edit" type="a.Edit"/></action-mappings></struts-config>\n'
        root = CONFIG_XML_HEADER + '<struts-config><action-mappings><action path="/home" type="a.Home"/></action-mappings></struts-config>\n'
        routes = scan_routes({
            "app/WEB-INF/web.xml": web,
            "app/WEB-INF/admin/struts-config.xml": admin,
            "app/WEB-INF/struts-config.xml": root,
        })
        self.assertEqual(paths_of(routes, "java-struts1"), ["/admin/edit.do", "/home.do"])

    def test_spring_simple_url_handler_mapping(self) -> None:
        servlet = CONFIG_XML_HEADER + (
            '<beans><bean id="urlMapping" class="org.springframework.web.servlet.handler.SimpleUrlHandlerMapping">\n'
            '<property name="interceptors"><list><bean class="com.acme.Audit"></bean></list></property>\n'
            '<property name="mappings"><props><prop key="/admin/order.form">orderForm</prop></props></property></bean>\n'
            '<bean id="orderForm" class="com.acme.OrderFormController"/>\n</beans>\n'
        )
        routes = scan_routes({
            "WEB-INF/app-servlet.xml": servlet,
            "src/com/acme/OrderFormController.java": 'package com.acme;\nclass OrderFormController { void f() { getParameter("orderId"); } }\n',
        })
        spring = [r for r in routes if r["stack"] == "java-spring-mvc"]
        self.assertEqual([r["path"] for r in spring], ["/admin/order.form"])
        self.assertEqual(spring[0]["handler"]["file"], "src/com/acme/OrderFormController.java")
        self.assertIn("orderId", [p["name"] for p in spring[0]["id_params"]])


class TestSpringAnnotations(unittest.TestCase):
    def test_annotation_between_modifier_and_return_type(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping("/q/h")\n  public @ResponseBody\n  List<Map<String, Object>> list(@RequestParam("itemId") int id) { return null; }\n'
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/q/h"])
        self.assertEqual(routes[0]["handler"]["symbol"], "list")

    def test_array_of_paths_gives_one_route_each(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping(value = {"list", ""})\n  public String list() { return ""; }\n',
            '@RequestMapping(value = "/sys/user")',
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/sys/user", "/sys/user/list"])

    def test_params_is_a_query_string_not_a_path(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping(params = "doDel")\n  public String del() { return ""; }\n'
            '  @RequestMapping(value = "/x", params = "action=up")\n  public String up() { return ""; }\n',
            '@RequestMapping("/item")',
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/item/x?action=up", "/item?doDel"])

    def test_produces_is_not_a_path(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping(method = RequestMethod.POST, produces = "application/json")\n  public String p() { return ""; }\n',
            '@RequestMapping("/item")',
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/item"])
        self.assertEqual(routes[0]["method"], ["POST"])

    def test_class_literal_in_a_method_does_not_become_the_class_prefix(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping(value = "export")\n  public String e() { new Excel(User.class); return ""; }\n'
            '  @RequestMapping(value = "info")\n  public String i() { return ""; }\n',
            '@RequestMapping(value = "/sys/user")',
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/sys/user/export", "/sys/user/info"])

    def test_string_constant_path_is_resolved(self) -> None:
        routes = scan_routes(controller(
            '  private static final String PATH = "/admin/settings";\n'
            '  @RequestMapping(value = PATH + "/save", method = RequestMethod.POST)\n  public String s() { return ""; }\n'
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/admin/settings/save"])

    def test_placeholder_is_not_an_id_parameter(self) -> None:
        routes = scan_routes(controller(
            '  @RequestMapping(value = "{tenantId}/view")\n  public String v() { return ""; }\n',
            '@RequestMapping(value = "${adminPath}/sys/user")',
        ))
        self.assertEqual([p["name"] for p in routes[0]["id_params"]], ["tenantId"])

    def test_commented_out_annotation_is_not_a_route(self) -> None:
        routes = scan_routes(controller(
            '  // @RequestMapping(value = "old")\n  public String old() { return ""; }\n'
            '  /*\n  @RequestMapping(value = "dead")\n  public String dead() { return ""; }\n  */\n'
            '  @RequestMapping(value = "live")\n  public String live() { return ""; }\n',
            '@RequestMapping("/item")',
        ))
        self.assertEqual(paths_of(routes, "java-spring-mvc"), ["/item/live"])


class TestJspEntryPoints(unittest.TestCase):
    def test_jsp_under_web_inf_is_not_a_route(self) -> None:
        routes = scan_routes({"app/src/main/webapp/WEB-INF/jsps/editor/Entries.jsp": "<html/>\n"})
        self.assertEqual(paths_of(routes, "java-jsp"), [])

    def test_public_jsp_in_an_include_like_directory_is_a_route(self) -> None:
        routes = scan_routes({"src/main/webapp/webpage/cgform/config/list.jsp": "<html/>\n"})
        self.assertEqual(paths_of(routes, "java-jsp"), ["/webpage/cgform/config/list.jsp"])

    def test_path_is_relative_to_the_web_root(self) -> None:
        routes = scan_routes({"app/WebContent/order/detail.jsp": "<html/>\n"})
        self.assertEqual(paths_of(routes, "java-jsp"), ["/order/detail.jsp"])


class TestInjectionPrecision(unittest.TestCase):
    def test_html_select_builder_is_not_sql(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  String f(String v) {\n"
            "    StringBuffer sb = new StringBuffer();\n"
            '    sb.append("<select name=\\"" + v + "\\">");\n'
            '    sb.append("<option value=\\"" + v + "\\">" + v);\n'
            "    return sb.toString();\n"
            "  }\n"
            "}\n"
        )})
        self.assertEqual(result["candidates"], [])

    def test_freemarker_generator_template_is_not_a_mapper(self) -> None:
        result = scan_injection({"src/main/resources/templates/gen/mapper.xml": (
            '<template><content><![CDATA[\n<mapper namespace="${pkg}">\n<select id="x">\n'
            "SELECT * FROM ${table.name} <#if flag>WHERE a = 1</#if>\n</select></mapper>\n]]></content></template>\n"
        )})
        self.assertEqual(result["candidates"], [])

    def test_real_mapper_dollar_still_flagged(self) -> None:
        result = scan_injection({"src/ItemDao.xml": (
            '<mapper namespace="a.ItemDao">\n<select id="x">\nSELECT * FROM item ORDER BY ${page.orderBy}\n</select></mapper>\n'
        )})
        self.assertEqual([c["rule"] for c in result["candidates"]], ["mybatis-dollar"])

    def test_positional_parameter_index_is_suppressed(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  String f(int size, String sortBy) {\n"
            '    StringBuilder q = new StringBuilder("SELECT e FROM Entry e WHERE ");\n'
            '    q.append(" AND e.name = ?").append(size);\n'
            '    q.append(" ORDER BY ").append(sortBy);\n'
            "    return q.toString();\n"
            "  }\n"
            "}\n"
        )})
        self.assertEqual([c["line"] for c in result["candidates"]], [5])
        self.assertEqual([s["line"] for s in result["suppressed"]], [4])


class TestInjectionRecall(unittest.TestCase):
    def test_operand_on_a_continuation_line_is_flagged(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  void f(Connection c, String name) throws Exception {\n"
            '    c.prepareStatement("INSERT INTO t (a) VALUES("\n'
            "        + name + \",?)\");\n"
            "  }\n"
            "}\n"
        )})
        self.assertEqual([c["line"] for c in result["candidates"]], [4])

    def test_leading_operand_call_on_a_continuation_line_is_flagged(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  int f(Connection c, Name n) {\n"
            '    return get(c, "SELECT count(*) FROM concept WHERE locale = \'"\n'
            "        + quote(n.getLocale())\n"
            '        + "\'");\n'
            "  }\n"
            "}\n"
        )})
        self.assertIn(4, [c["line"] for c in result["candidates"]])

    def test_constant_on_a_continuation_line_is_not_flagged(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  int f(Connection c) {\n"
            '    return get(c, "SELECT count(*) FROM concept WHERE kind = \'"\n'
            "        + ConceptNameType.FULLY_SPECIFIED\n"
            '        + "\'");\n'
            "  }\n"
            "}\n"
        )})
        self.assertEqual(result["candidates"], [])

    def test_jpql_literal_ending_in_where_is_flagged(self) -> None:
        result = scan_injection({"src/A.java": (
            "class A {\n"
            "  String f(StringBuilder whereClause) {\n"
            '    return "FROM MediaFile m WHERE " + whereClause;\n'
            "  }\n"
            "}\n"
        )})
        self.assertEqual([c["line"] for c in result["candidates"]], [3])


if __name__ == "__main__":
    unittest.main()
