import os
import shutil
import sys
import zlib

import aiohttp

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import re
import time
import asyncio
import ujson
import modules
import binascii
import traceback
import aiohttp.web
from aiohttp.web import Application
from aiohttp.web import Request
from aiohttp.web import json_response, Response, StreamResponse, FileResponse
from common import (
    code,
    utils,
    config,
    scheduler,
    variable,
)
from common.log import log
from common.utils import IsLocalIP, createMD5
from common.request import GetIPInfo
from common.config import ReadConfig, CheckIPBanned, GetKeyInfo

with open("./statistics.json", "r") as f:
    content = f.read()
    status = ujson.loads(content)

logger = log("Main+WebServer")
stopEvent = asyncio.exceptions.CancelledError


def handleResponse(request: Request, body: dict, status: int = 200) -> Response:
    if "yourinfo" not in body:
        body["yourinfo"] = {
            "ip": request.remote_addr,
            "ua": request.headers.get("User-Agent", ""),
        }
    return json_response(body, status=status)


async def before(app, handler):
    async def _before(request: Request) -> dict | Response | None:
        variable.StatsManager.increment("all_request")

        try:
            if ReadConfig("common.reverse_proxy.allow_proxy") and request.headers.get(
                ReadConfig("common.reverse_proxy.real_ip_header")
            ):
                if not (
                    ReadConfig("common.reverse_proxy.allow_public_ip")
                    or IsLocalIP(request.remote)
                ):
                    return handleResponse(
                        request,
                        {"code": code.NOT_ACCEPT, "message": "不允许的公网IP转发"},
                        code.NOT_ACCEPT,
                    )

                request.remote_addr = str(
                    request.headers[ReadConfig("common.reverse_proxy.real_ip_header")]
                )
            else:
                request.remote_addr = request.remote

            if CheckIPBanned(request.remote_addr):
                return handleResponse(
                    request,
                    {"code": code.NOT_ACCEPT, "message": "IP is banned."},
                    code.NOT_ACCEPT,
                )

            IPInfo = await GetIPInfo(request.remote_addr)

            logger.info(
                f"Req: {request.method} - {request.remote_addr} - {IPInfo['local']} - {request.url.path} - {request.headers['User-Agent']} - {request.url.query_string} - {request.headers.get('X-Request-Key', '')}"
            )

            start_time = time.perf_counter()
            response = await handler(request)
            process_time = time.perf_counter() - start_time

            if isinstance(
                response,
                (Response, StreamResponse, FileResponse),
            ):
                response = response

            response.headers["X-Process-Time"] = str(process_time)

            return response
        except BaseException:
            logger.error(traceback.format_exc())
            return handleResponse(
                request,
                {"code": code.SERVER_ERROR, "message": "服务器内部错误"},
                code.SERVER_ERROR,
            )
        except KeyboardInterrupt:
            return

    return _before


async def Home(request: Request):
    return {
        "code": code.SUCCESS,
        "message": "HELLO WORLD",
    }


async def Handle(
    request: Request,
) -> Response:
    enable, inlist = GetKeyInfo(request.headers.get("X-Request-Key", ""))

    if enable and not inlist:
        return handleResponse(
            request, {"code": code.NOT_ACCEPT, "message": "Key错误"}, code.NOT_ACCEPT
        )

    method = request.url.path.split("/")[1]
    source = request.query.get("source")
    songId = request.query.get("songId")
    quality = request.query.get("quality")

    if method == "url" and quality is None:
        return handleResponse(
            request,
            {"code": code.INVALID_REQUEST, "message": "必须参数: quality"},
            code.INVALID_REQUEST,
        )

    try:
        if source == "kg":
            songId = songId.lower()
        result = await getattr(modules, method)(source, songId, quality)
        return handleResponse(request, result)
    except BaseException:
        logger.error(traceback.format_exc())
        return handleResponse(
            request,
            {"code": code.SERVER_ERROR, "message": "内部服务器错误"},
            code.SERVER_ERROR,
        )


async def HandleSearch(request: Request):
    source = request.query.get("source")
    keyword = request.query.get("keyword")
    pages = request.query.get("pages")
    limit = request.query.get("limit")

    if not source or keyword or pages or limit:
        return handleResponse(
            request, {"code": code.INVALID_REQUEST, "message": "缺少参数"}
        )

    try:
        result = await modules.search(source, keyword, pages, limit)
        return handleResponse(request, result)
    except BaseException:
        logger.error(traceback.format_exc())
        return handleResponse(
            request,
            {"code": code.SERVER_ERROR, "message": "内部服务器错误"},
            code.SERVER_ERROR,
        )


async def Script(
    request: Request,
):
    key = request.query.get("key")

    enable, inlist = GetKeyInfo(key)

    if (not inlist) and (enable):
        return handleResponse(
            request, {"code": code.NOT_ACCEPT, "message": "Key错误"}, code.NOT_ACCEPT
        )

    try:
        with open(
            f"./data/script/lx-music-source-example.js", "r", encoding="utf-8"
        ) as f:
            script = f.read()
    except:
        return handleResponse(
            request, {"code": code.NOT_FOUND, "message": "本地无源脚本"}, code.NOT_FOUND
        )

    scriptLines = script.split("\n")
    newScriptLines = []

    for line in scriptLines:
        oline = line
        line = line.strip()
        host = request.headers.get(
            ReadConfig("common.reverse_proxy.real_host_header"), ""
        )
        url = (
            f"{request.url.scheme}"
            + f"://{host if host else request.url.host}"
            + f":{request.url.port}"
            if request.url.port
            else None
        )
        if line.startswith("const API_URL"):
            newScriptLines.append(f'''const API_URL = "{url}"''')
        elif line.startswith("const API_KEY"):
            newScriptLines.append(f"""const API_KEY = `{key if key else ''''''}`""")
        elif line.startswith("* @name"):
            newScriptLines.append(
                " * @name " + ReadConfig("common.download_config.name")
            )
        elif line.startswith("* @description"):
            newScriptLines.append(
                " * @description " + ReadConfig("common.download_config.intro")
            )
        elif line.startswith("* @author"):
            newScriptLines.append(
                " * @author " + ReadConfig("common.download_config.author")
            )
        elif line.startswith("* @version"):
            newScriptLines.append(
                " * @version " + ReadConfig("common.download_config.version")
            )
        elif line.startswith("const DEV_ENABLE "):
            newScriptLines.append(
                "const DEV_ENABLE = "
                + str(ReadConfig("common.download_config.dev")).lower()
            )
        elif line.startswith("const UPDATE_ENABLE "):
            newScriptLines.append(
                "const UPDATE_ENABLE = "
                + str(ReadConfig("common.download_config.update")).lower()
            )
        else:
            newScriptLines.append(oline)

    r = "\n".join(newScriptLines)

    r = re.sub(
        r"const MUSIC_QUALITY = {[^}]+}",
        f'const MUSIC_QUALITY = JSON.parse(\'{ujson.dumps(ReadConfig("common.download_config.quality"))}\')',
        r,
    )

    if ReadConfig("common.download_config.update"):
        md5 = createMD5(r)
        r = r.replace(r'const SCRIPT_MD5 = "";', f'const SCRIPT_MD5 = "{md5}";')
        if request.query.get("checkUpdate"):
            if request.query.get("checkUpdate") == md5:
                return handleResponse(
                    request, {"code": code.SUCCESS, "message": "成功"}
                )
            url = (
                f"{request.url.scheme}"
                + f"://{host if host else request.url.host}"
                + f":{request.url.port}"
                if request.url.port
                else None
            )
            updateUrl = f"{url}/script{('?key=' + key) if key else ''}"
            updateMsg = (
                str(ReadConfig("common.download_config.updateMsg"))
                .format(
                    updateUrl=updateUrl,
                    url=url,
                    key=key,
                    version=ReadConfig("common.download_config.version"),
                )
                .replace("\\n", "\n")
            )
            return {
                "code": code.SUCCESS,
                "message": "成功",
                "data": {"updateMsg": updateMsg, "updateUrl": updateUrl},
            }

    return Response(
        body=r,
        content_type="text/javascript",
        headers={
            "Content-Disposition": f"""attachment; filename={
                            ReadConfig("common.download_config.filename")
                            if ReadConfig("common.download_config.filename").endswith(".js")
                            else (ReadConfig("common.download_config.filename") + ".js")}"""
        },
    )


async def gcsp(request: Request):
    PACKAGE = ReadConfig("gcsp.package_md5")
    SALT_1 = ReadConfig("gcsp.salt_1")
    SALT_2 = ReadConfig("gcsp.salt_2")
    NEED_VERIFY = ReadConfig("gcsp.enable_verify")
    ENABLE_PLATFORM = ReadConfig("gcsp.enable_source")

    qm = {
        "mp3": "128k",
        "hq": "320k",
        "sq": "flac",
        "hr": "hires",
        "hires": "hires",
        "dsd": "master",
    }

    pm = {"qq": "tx", "wyy": "wy", "kugou": "kg", "kuwo": "kw", "mgu": "mg"}

    internal_trans = {
        "time": "[禁止下载]请求检验失败，请检查系统时间是否为标准时间",
        "sign": "[更新]951962664, 一串数字自己想想",
    }

    def decode(indata) -> dict:
        return ujson.loads(binascii.unhexlify(zlib.decompress(indata)))

    def verify(data):
        if not NEED_VERIFY:
            return "success"
        sign_1 = createMD5(PACKAGE + data["time"] + SALT_2)
        sign_2 = createMD5(
            str(
                ujson.dumps(data["text_1"])
                + ujson.dumps(data["text_2"])
                + sign_1
                + data["time"]
                + SALT_1
            )
            .replace("\\", "")
            .replace('}"', "}")
            .replace('"{', "{")
        )
        if data["sign_1"] != sign_1 or data["sign_2"] != sign_2:
            return "sign"
        if int(time.time()) - int(data["time"]) > 10:
            return "time"
        return "success"

    async def handleGcspBody(body):
        data = decode(body)
        result = verify(data)

        t2 = ujson.loads(data["text_2"])

        logger.info(
            f"收到歌词适配请求，设备名称：{t2['device']}，设备ID：{t2['deviceid']}"
        )

        if result != "success":
            compressed_data = zlib.compress(
                ujson.dumps(
                    {"code": "403", "error_msg": internal_trans[result], "data": None},
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return Response(
                compressed_data,
                media_type="application/octet-stream",
            )

        data["te"] = ujson.loads(data["text_1"])

        if pm[data["te"]["platform"]] not in ENABLE_PLATFORM:
            compressed_data = zlib.compress(
                ujson.dumps(
                    {
                        "code": "403",
                        "error_msg": "此平台已停止服务",
                        "bitrate": 1,
                        "data": None,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return Response(
                compressed_data,
                media_type="application/octet-stream",
            )

        body = await modules.url(
            pm[data["te"]["platform"]], data["te"]["t1"], qm[data["te"]["t2"]]
        )

        if body["code"] != 200:
            data = ujson.dumps(
                {"code": "403", "error_msg": body["message"]}, ensure_ascii=False
            )
        else:
            data = ujson.dumps(
                {
                    "code": "200",
                    "error_msg": "success",
                    "data": body["url"] if body["code"] == 200 else None,
                },
                ensure_ascii=False,
            )

        compressed_data = zlib.compress(data.encode("utf-8"))

        logger.info(f"歌词适配请求响应：{ujson.loads(data)}")

        return Response(compressed_data, media_type="application/octet-stream")

    method = request.match_info.get("method")

    if request.method == "POST":
        if method == "api.fcg":
            content_size = request.__len__()
            if content_size > 5 * 1024:
                return Response(body="Request Entity Too Large", status=413)
            body = await request.json()
            return await handleGcspBody(body)
        elif method == "check_version":
            body = {
                "code": "200",
                "data": {
                    "version": "2.0.8",
                    "update_title": "2.0.8",
                    "update_log": "更新启动图。",
                    "down_url": "",
                    "share_url": "",
                    "compulsory": "yes",
                    "file_md5": PACKAGE,
                },
            }

            req = await request.json()

            if req["clientversion"] != body["data"]["version"]:
                body = body
            else:
                body = {"code": 404}

            return body
        elif method == "zz":
            body1 = {
                "url": "",
                "text": "感谢支持",
            }  # 微信
            body2 = {
                "url": "",
                "text": "感谢支持",
            }  # 支付宝
            req = await request.json()
            if req["type"] == "wx":
                return body1
            elif req["type"] == "zfb":
                return body2
    elif request.method == "GET":
        if method == "Splash":
            return {
                "state": "0",
                "color": "white",
                "status_bar_color": "white",
                "imageUrl": "https://mf.ikunshare.top/歌词适配启动图.png",
            }
    else:
        return Response(body="Method Not Allowed", status=405)


app = Application(logger=logger, middlewares=[before])
utils.setGlobal(app, "app")

app.router.add_get("/", Home)
app.router.add_get("/url", Handle)
app.router.add_get("/info", Handle)
app.router.add_get("/lyric", Handle)
app.router.add_get("/search", HandleSearch)
app.router.add_get("/script", Script)
app.router.add_route("*", "/client/cgi-bin/{method}", gcsp)


from io import TextIOWrapper

for f in variable.LogFiles:
    if f and isinstance(f, TextIOWrapper):
        f.close()


async def run_app_host(host):
    retries = 0
    while True:
        if retries > 4:
            logger.warning(
                "重试次数已达上限，但仍有部分端口未能完成监听，已自动进行忽略"
            )
            break
        try:
            ports = [int(port) for port in config.ReadConfig("common.ports")]
            ssl_ports = [
                int(port) for port in config.ReadConfig("common.ssl_info.ssl_ports")
            ]
            final_ssl_ports = []
            final_ports = []
            for p in ports:
                if p not in ssl_ports and f"{host}_{p}" not in variable.RunningPorts:
                    final_ports.append(p)
                else:
                    if p not in variable.RunningPorts:
                        final_ssl_ports.append(p)

            cert_path = config.ReadConfig("common.ssl_info.path.cert")
            privkey_path = config.ReadConfig("common.ssl_info.path.privkey")

            http_runner = aiohttp.web.AppRunner(app)
            await http_runner.setup()

            for port in final_ports:
                if port not in variable.RunningPorts:
                    http_site = aiohttp.web.TCPSite(http_runner, host, port)
                    await http_site.start()
                    variable.RunningPorts.append(f"{host}_{port}")
                    logger.info(
                        f"""监听 -> http://{
                        host if (':' not in host)
                        else '[' + host + ']'
                    }:{port}"""
                    )

            if config.ReadConfig("common.ssl_info.enable") and final_ssl_ports != []:
                if os.path.exists(cert_path) and os.path.exists(privkey_path):
                    import ssl

                    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_context.load_cert_chain(cert_path, privkey_path)

                    https_runner = aiohttp.web.AppRunner(app)
                    await https_runner.setup()

                    for port in ssl_ports:
                        if port not in variable.RunningPorts:
                            https_site = aiohttp.web.TCPSite(
                                https_runner, host, port, ssl_context=ssl_context
                            )
                            await https_site.start()
                            variable.RunningPorts.append(f"{host}_{port}")
                            logger.info(
                                f"""监听 -> https://{
                                host if (':' not in host)
                                else '[' + host + ']'
                            }:{port}"""
                            )
            logger.debug(f"HOST({host}) 已完成监听")
            break
        except OSError as e:
            if str(e).startswith("[Errno 98]") or str(e).startswith("[Errno 10048]"):
                logger.error("端口已被占用，请检查\n" + str(e))
                logger.info("服务器将在10s后再次尝试启动...")
                await asyncio.sleep(10)
                logger.info("重新尝试启动...")
                retries += 1
            else:
                logger.error("未知错误，请检查\n" + traceback.format_exc())


async def run_app():
    for host in config.ReadConfig("common.hosts"):
        await run_app_host(host)


async def initMain():
    if not os.path.exists("./data/script/lx-music-source-example.js"):
        shutil.copyfile(
            "./common/lx-music-source-example.js",
            "./data/script/lx-music-source-example.js",
        )

    await scheduler.run()
    variable.StatsManager.start()

    try:
        await run_app()
        logger.info("服务器启动成功，请按下Ctrl + C停止")
        await asyncio.Event().wait()
    except (KeyboardInterrupt, stopEvent):
        pass
    except OSError as e:
        logger.error("遇到未知错误，请查看日志")
        logger.error(traceback.format_exc())
    except:
        logger.error("遇到未知错误，请查看日志")
        logger.error(traceback.format_exc())
    finally:
        logger.info("等待结束...")

        if variable.SyncClient:
            variable.SyncClient.close()
        if variable.AsyncClient:
            await variable.AsyncClient.close()
        if variable.StatsManager:
            variable.StatsManager.stop()

        variable.Running = False
        logger.info("Server stopped")


if __name__ == "__main__":
    try:
        asyncio.run(initMain())
    except KeyboardInterrupt:
        pass
    except:
        logger.critical("初始化出错，请检查日志")
        logger.critical(traceback.format_exc())
        with open(
            "dumprecord_{}.txt".format(int(time.time())), "w", encoding="utf-8"
        ) as f:
            f.write(traceback.format_exc())
            e = "\n\nGlobal variable object:\n\n"
            for k in dir(variable):
                e += (
                    (k + " = " + str(getattr(variable, k)) + "\n")
                    if (not k.startswith("_"))
                    else ""
                )
            f.write(e)
            e = "\n\nsys.modules:\n\n"
            for k in sys.modules:
                e += (
                    (k + " = " + str(sys.modules[k]) + "\n")
                    if (not k.startswith("_"))
                    else ""
                )
            f.write(e)
        logger.critical("dumprecord_{}.txt 已保存至当前目录".format(int(time.time())))
    finally:
        for f in variable.LogFiles:
            if f and isinstance(f, TextIOWrapper):
                f.close()
