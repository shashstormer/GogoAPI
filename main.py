from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from bs4 import BeautifulSoup
from html import unescape
import re
import json
import regex as regex_orignal
import yarl
from dataclasses import dataclass
from datetime import timedelta, datetime
from typing import Any, Union
import threading
import random
import time
import requests
import os
import requests.exceptions
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import uvicorn


def html(string):
    string = BeautifulSoup(string, "html.parser")
    return string


def reg_replace(pattern, sub, string):
    return re.sub(pattern, sub, string)


def reg_compile(pattern):
    return regex_orignal.compile(pattern)


def aes_encrypt(key, iv, string):
    cip = AES.new(key, AES.MODE_CBC, iv)
    if isinstance(string, str):
        string = string.encode("utf-8")
    string = pad(string, cip.block_size)
    string = cip.encrypt(string)
    return base64.b64encode(string).decode('utf-8')


def aes_decrypt(key, iv, string, decode=True, decoded=False, unpad_data=True):
    cip = AES.new(key, AES.MODE_CBC, iv)
    if not decoded:
        string = base64.b64decode(string)
    try:
        string = cip.decrypt(string)
    except ValueError:
        string = pad(string, cip.block_size)
        string = cip.decrypt(string)
    if unpad_data:
        string = unpad(string, cip.block_size)
    if decode:
        string = string.decode("utf-8")
    return string


def load(string, escaped=True, error_1=True, iterate=False):
    if escaped:
        string = load(string, escaped=False, iterate=iterate, error_1=error_1)
        if isinstance(string, str):
            string = unescape(string)
            string = load(string, escaped=False, iterate=iterate, error_1=error_1)
            if isinstance(string, str):
                _string = string.replace("\\\"", "\"").replace("\\\\", "/")
                _string = load(_string, escaped=False, iterate=iterate, error_1=error_1)
                if isinstance(_string, dict):
                    string = _string
    else:
        try:
            string = json.loads(string)
        except Exception as e:
            if error_1:
                pass
            else:
                print(e)
    try:
        if isinstance(string, str):
            return string
        if iterate:
            for key in string:
                if (isinstance(string[key], str)) and ("{" in string[key]) and ("}" in string[key]):
                    string[key] = load(string[key], escaped=escaped, iterate=iterate, error_1=error_1)
                elif isinstance(string[key], dict):
                    string[key] = load(string[key], escaped=escaped, iterate=iterate, error_1=error_1)
    except Exception as e:
        if error_1:
            pass
        else:
            print(e)
    return string


@dataclass
class Cache:
    def __init__(self, hours=0, minutes=30, seconds=0, session=None):
        """
        This class will not be requesting anything if session is None and will raise errors
        This class can be used wven without session, but it will not be able to request anything
        You may update or access the session using the session attribute
        """
        self._cache = {}
        self.cache_time = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        self.delete_time = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        self.session = session
        self.lock = threading.Lock()
        self.refresh_time = self.cache_time * 0.9
        self.stats = {"hits": 0, "caches created": 0}
        self.stat_lock = threading.Lock()
        self.being_set = []
        self._delete_thread = threading.Thread(target=self._delete_items)
        self._delete_thread.daemon = True
        self._delete_thread.start()

    def __getitem__(self, item, no_val=False):
        while item in self.being_set:
            time.sleep(1)
        with self.lock:
            value = self._cache.get(item, False)
            if not value:
                return no_val
            else:
                value: dict
                if (datetime.now() - value["time"]) > self.cache_time:
                    return no_val
                else:
                    with self.stat_lock:
                        self.stats["hits"] += 1
                    return value["content"]

    def __setitem__(self, item, value, auto=False):
        with self.lock:
            if item not in self.being_set:
                self.being_set.append(item)
            if len(value) == 4 and auto:  # and type(value[2]) == dict and type(value[1]) == str and type(
                # value[3]) == str and value[3] in ["get", "post"]
                self._cache[item] = {
                    "time": datetime.now(),
                    "content": value[0],
                    "auto_created": auto,
                    "params": value[2],
                    "url": value[1],
                    "method": value[3],
                    "new": True
                }
            else:
                _params = self._cache.get(item, {}).get("params", {})
                _url = self._cache.get(item, {}).get("url", "")
                _method = self._cache.get(item, {}).get("params", "")
                self._cache[item] = {
                    "time": datetime.now(),
                    "content": value,
                    "auto_created": auto,
                    "params": _params,
                    "url": _url,
                    "method": _method,
                    "new": False
                }
            self.being_set.remove(item)
        with self.stat_lock:
            self.stats["caches created"] += 1

    def __call__(self, url, method="get", **kwargs) -> Union[list[Union[bool, Any]], list[Any]]:
        data = self.__getitem__(url)
        if data:
            return [data, self._cache[url]["new"]]
        else:
            data = getattr(self.session, method)(url, **kwargs)
            self.__setitem__(url, [data, url, kwargs, method], True)
            return [data, self._cache[url]["new"]]

    def is_expired(self, url):
        return (datetime.now() - self._cache[url]['time']) > (self.delete_time * 0.9)

    def refresh(self, url):
        _url = url
        url = self._cache[url]
        return self.overload(_url, url["method"], **url["params"])

    def _delete_items(self):
        while True:
            time.sleep(5 * 60)
            for item in list(self._cache.keys()):
                if (datetime.now() - self._cache[item]['time']) > (self.delete_time * 0.9):
                    try:
                        self.overload(item, item["method"], **item["params"])
                        continue
                    except Exception as e:
                        print(e)
                with self.lock:
                    if (datetime.now() - self._cache[item]['time']) > self.delete_time:
                        del self._cache[item]

    def get(self, url, method="get", **kwargs) -> Union[list[Union[bool, Any]], list[Any]]:
        return self.__call__(url, method, **kwargs)

    def overload(self, url, method, **kwargs):
        """
        this function makes it such that there is no need for worrying about requesting data as soon as user makes
        request and helps reduce request time as all processes are controled by the new parameter
        """
        data = getattr(self.session, method)(url, **kwargs)
        self.__setitem__(url, [data, url, kwargs, method], True)

    def get_cache_list(self):
        return self._cache.copy()

    def check_cache_updated(self, what_exists):
        return what_exists == self._cache

    def __iter__(self):
        return iter(list(self._cache.keys()))


class Session:
    def __init__(self, human_browsing=False):
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                          ' Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                      'image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            # 'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': None,
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            "SEC-CH-UA-MOBILE": "?0",
            "SEC-CH-UA-PLATFORM": "Linux",
        }
        self.last_html_url = None
        self.human_browsing = human_browsing
        self.min_sleep = 1
        self.max_sleep = 7

    def where_to(self, url, headers=None, post=False, body=None, notify=True):
        ret = {}
        if headers is None:
            headers = {}
        _headers = self.headers.copy()
        if self.last_html_url:
            _headers['Referer'] = self.last_html_url
        _headers.update(headers)
        if notify:
            print("getting :", url, end="")
        if post:
            resp = self.session.get(url, headers=_headers, data=body, allow_redirects=False)
        else:
            resp = self.session.get(url, headers=_headers, allow_redirects=False)
        if notify:
            print("\rgot : ", resp.url, "\ncode : ", resp.status_code)
        ret["to"] = resp.headers.get("Location", url)
        ret["headers"] = resp.headers
        ret["cookies"] = resp.cookies
        return ret

    def get(self, url, headers=None, post=False, body=None, notify=True, text=True, return_page_url=False,
            return_cookies=False, set_html=True, sleep_for_anti_bot=True):
        if self.human_browsing and sleep_for_anti_bot:
            time.sleep(random.randint(self.min_sleep, self.max_sleep))
        if notify:
            print("getting :", url, end="")
        if headers is None:
            headers = {}
        _headers = self.headers.copy()
        if self.last_html_url:
            _headers['Referer'] = self.last_html_url
        _headers.update(headers)
        if not post:
            response = self.session.get(url, headers=_headers, timeout=60)
        else:
            response = self.session.post(url, headers=_headers, data=body, timeout=60)
        if 'text/html' in response.headers.get('Content-Type', '') and set_html:
            self.last_html_url = response.url
        if text:
            resp = response.text
        else:
            resp = response
        if notify:
            print("\rgot : ", response.url, "\ncode : ", response.status_code)
        if return_page_url:
            resp = {"resp": resp, "url": response.url}
        if return_cookies:
            if isinstance(resp, dict):
                resp.update({"cookies": response.cookies})
            else:
                resp = {"resp": resp, "cookies": response.cookies}
        return resp


main_url = "https://anitaku.so"
alternate_domains = ["https://gogoanime3.net/", "https://www9.gogoanimes.fi", ]
recent_url = "https://ajax.gogocdn.net/ajax/page-recent-release.html?page={}&type={}"
episodes_url = "https://ajax.gogocdn.net/ajax/load-list-episode?ep_start=0&ep_end=10000&id={}"
popular_url = "https://ajax.gogocdn.net/ajax/page-recent-release-ongoing.html?page={}"
trending_url = "https://ajax.gogocdn.net/anclytic-ajax.html?id={}"
movie_page_url = f"{main_url}/anime-movies.html"
tv_page_url = f"{main_url}/new-season.html"
trending_id = {"week": 1, "month": 2, "all": 3}
recent_possibilities = {"type": {"1": "Latest Subbed", "2": "Latest Dubbed", "3": "Latest Chinese"}}
KEYS_REGEX = reg_compile(r"(?:container|videocontent)-(\d+)")
ENCRYPTED_DATA_REGEX = reg_compile(r'data-value="(.+?)"')


class Gogo:
    def __init__(self):
        super().__init__()
        self.session = Session()
        self.cache = Cache(minutes=60 if os.getenv("server_env") == "dev" else 30, session=self.session)
        sn = random.randint(1, 59)
        self.long_cache = Cache(hours=3, minutes=sn, session=self.session)
        self.details = self.Details(self.session, self.long_cache)
        self.mini_cache = Cache(hours=0, minutes=10, session=self.session)
        self.details = self.Details(self.session, self.cache, super_class=self)

    def home(self, *__, **_):
        old = self.mini_cache[main_url]
        if not old and _.get("redirected_code", None) is None:
            dt = {}
            rtyp = recent_possibilities["type"]
            for typ in rtyp:
                try:
                    merge_data = self._cards(self.session.get(recent_url.format("1", typ)))
                except Exception as e:
                    print(e)
                    return self.home(redirected_code="1")
                merged = []
                merged.extend(merge_data[0])
                merged.extend(merge_data[1])
                dt[rtyp[typ]] = merged
            self.mini_cache[main_url] = dt
        elif _.get("redirected_code", None) is not None:
            dt = {}
            try:
                merge_data = self._cards(self.session.get(f"{main_url}/home.html"))
            except Exception as e:
                print(e)
                try:
                    merge_data = self._cards(self.session.get(alternate_domains[0]))
                except Exception as e2:
                    print(e2)
                    return {"alert": "selected source is down"}
            merged = []
            merged.extend(merge_data[0])
            merged.extend(merge_data[1])
            dt["Recent Subbed"] = merged
            self.mini_cache[main_url] = dt
        else:
            dt = old
        return dt

    @staticmethod
    def _cards(page_content):
        page_content = html(page_content)
        items = page_content.select_one("ul[class='items']")
        data = [[], []]
        for item in items.select("li"):
            image = item.select_one("img")["src"]
            a = item.select_one("a")
            title = a["title"]
            link = a["href"].split("-episode-")[0]
            link = "/category" + link if not link.startswith("/category/") else link
            typ = "DUB" if link.endswith("-dub") else "SUB"
            to_append = {
                "image": image,
                "url": link,
                "title": title,
                "type": typ,
                "rating": "?"
            }
            released_year = item.select_one("p[class='released']")
            if released_year:
                to_append["released_year"] = (
                    released_year.get_text().replace("Released:", "").replace("\n", "").replace("\t", "")
                    .strip(" "))
            data[0 if typ == "SUB" else 1].append(to_append)
        return data

    def search(self, method_value: str, *__, **_):
        if method_value.startswith("/"):
            method_value = method_value[1:]
        url = f"{main_url}/search.html?keyword={method_value.replace(' ', '%20')}"
        try:
            dt, new = self.cache.get(url)
        except Exception as e:
            print(e)
            dt, new = self.cache.get(url.replace(main_url, alternate_domains[0]))
        if new:
            results = self._cards(dt)
            dt = {}
            if results[0]:
                dt["Search Results Subbed"] = results[0]
            if results[1]:
                dt["Search Results Dubbed"] = results[1]
            self.cache[url] = dt
        return dt

    def seasons(self, method_value: str, *__, **_):
        method_value = "/" + method_value if not method_value.startswith("/") else method_value
        method_value = method_value.replace("//", "/")
        if method_value.startswith("/category/"):
            method_value = method_value.replace("/category", "", 1)
        dt = self.cache[main_url + method_value]
        if not dt:
            d = self.details("/category" + method_value, internal_call="seasons", *__, **_)
            if isinstance(d, dict) and "new_redirected:)" in d:
                method_value = d["new_redirected:)"].replace("/category/", "/")
        dt = self.cache[main_url + method_value]
        return {"seasons": dt["seasons"]}

    def episodes(self, method_value: str, *__, **_):
        srs_id = method_value.split("/")[-1]
        url = episodes_url.format(srs_id)
        new = False
        dt = "False"
        try:
            dt, new = self.cache.get(url)
        except Exception as e:
            print(e)
            _["redirected_code"] = "1"
        if new and _.get("redirected_code", None) is None:
            dn = []
            dt = html(dt)
            a_s = dt.select("a")
            for a in a_s:
                nm = a.select_one("div[class='name']").get_text().replace("EP", "Episode")
                href = a["href"].replace("/", "", 1)
                dn.append([href.strip(" "), nm])
            self.cache[url] = dn
            dt = dn
        elif _.get("redirected_code", None) is not None:
            dt = [[method_value.split("/")[-2] + "-episode-" + str(i + 1), f"Episode {i + 1}"] for i in range(
                int(self.details(method_value.replace("/episodes/", "/details/category/").replace(srs_id, ""),
                                 internal_call=True, *__, **_)["episodes_count"]))]
        if _["request_accessor"].headers.get("x-data-prefer") == "dict":
            return {"episodes": dt}
        return dt

    def source(self, method_value: str, *__, **_):
        anim_id = method_value.split("/", 1)[-1]
        url_main = f"{main_url}/{anim_id}"
        try:
            dt, new = self.cache.get(url_main)
        except Exception as e:
            print(e)
            dt, new = self.cache.get(url_main.replace(main_url, alternate_domains[0]))
        if new:
            x = html(dt)
            url = [i['data-video'] for i in x.find_all(class_="anime_muti_link")[0].find_all("a") if
                   "streaming.php" in i['data-video']][0]
            parsed_url = yarl.URL(url)
            content_id = parsed_url.query["id"]
            next_host = "https://{}/".format(parsed_url.host)
            url = "https://" + parsed_url.raw_host + parsed_url.raw_path_qs
            streaming_page = self.session.get(url)

            encryption_key, iv, decryption_key = (
                _.group(1) for _ in KEYS_REGEX.finditer(streaming_page)
            )

            component = aes_decrypt(
                key=encryption_key.encode(),
                iv=iv.encode(),
                string=ENCRYPTED_DATA_REGEX.search(streaming_page).group(1),
            )
            component += "&id={}&alias={}".format(
                aes_encrypt(key=encryption_key.encode(), iv=iv.encode(), string=content_id), content_id
            )

            _, component = component.split("&", 1)

            ajax_response = self.session.get(
                next_host + "encrypt-ajax.php?" + component,
                headers={"x-requested-with": "XMLHttpRequest"},
            )
            content: Any = load(
                aes_decrypt(string=load(ajax_response).get("data"), key=decryption_key.encode(), iv=iv.encode())
            )
            download_url = x.select_one("li.dowloads a")
            if download_url:
                try:
                    download_url = download_url["href"]
                except Exception as e:
                    print(e)
                    download_url = ""
            else:
                download_url = ""
            ret = {
                "source": content["source"][0]["file"] if "source" in content and content["source"] else "",
                "alt_src": content["source_bk"][0]["file"] if "source_bk" in content and content["source_bk"] else "",
                "thumbnails": [],
                "subs": [],
                "unknown": [],
                "title": anim_id.replace("-", " "),
                "download_url": download_url,
            }
            for track in content["track"]["tracks"] if (("track" in content) and (content["track"])) else []:
                if track["kind"] == "thumbnails":
                    ret["thumbnails"].append(track["file"])
                else:
                    ret["unknown"].append(track)
            self.cache[url_main] = ret
            dt = ret
        return dt

    @staticmethod
    def docs(*__, **_):
        return FileResponse("./server/routes/api/sites/gogo/docs.html")

    def trending(self, *__, **_):
        url = trending_url.format(trending_id.get(_.get("timeline", "week"), 1))
        dt, new = self.cache.get(url)
        if new:
            dt = html(dt)
            dt = [{"title": i["title"], "url": i["href"],
                   "released_ep_count": i.select_one("p[class*='reaslead']").get_text().replace("Episode",
                                                                                                "").replace(
                       ":", "").strip(" ") if i.select_one("p[class*='reaslead']") is not None else ""}
                  for i in dt.select("a")]
            self.cache[url] = dt
        if _["request_accessor"].headers.get("x-data-prefer") == "dict":
            return {"trending": dt}
        return dt

    def popular(self, *__, **_):
        url = popular_url.format(_.get("page", 1))
        dt, new = self.cache.get(url)
        if new:
            dt = html(dt)
            data = []
            for item in dt.select_one('div[class="added_series_body popular"]').select("li"):
                data_item = {}
                a = item.select("a")
                for a in a.copy():
                    if a.select_one("div") is not None:
                        a = a
                        break
                else:
                    continue
                data_item["url"] = a["href"]
                data_item["title"] = a["title"]
                data_item["image"] = a.select_one("div")["style"].split("'")[1]
                data_item["genres"] = []
                for genre in item.select("p[class='genres']")[0].select("a"):
                    data_item["genres"].append([main_url + genre["href"], genre["title"]])
                data.append(data_item)
            self.cache[url] = data
            dt = data
        if _["request_accessor"].headers.get("x-data-prefer") == "dict":
            return {"popular": dt}
        return dt

    def tv(self, *__, **_):
        dt, new = self.cache.get(tv_page_url)
        if new:
            dt = self._cards(dt)
            dt = {"Newly Added Tv": dt[0]}
            self.cache[tv_page_url] = dt
        return dt

    def movie(self, *__, **_):
        dt, new = self.cache.get(movie_page_url)
        if new:
            dt = self._cards(dt)
            dt = {"Newly Added Movies": dt[0]}
            self.cache[movie_page_url] = dt
        return dt

    class Details:
        def __init__(self, session, cache, different=False, super_class=None):
            self.check = different
            self.session = session
            self.cache = cache
            self.super_class = super_class

        def __call__(self, method_value: str, content_type=None, _param_x=False, *__, **_):
            if (not method_value.startswith("category/")) and (not method_value.startswith("/category/")):
                method_value = "category" + (method_value if method_value.startswith("/") else "/" + method_value)
            method_value = method_value.replace("/category/category/", "/category/", 1)
            ori_mval = method_value
            if ori_mval.startswith("/"):
                ori_mval = ori_mval[1:]
            method_value = "/" + method_value if not method_value.startswith("/") else method_value
            try:
                pg, new = self.cache.get(main_url + (method_value[:-1] if method_value.endswith('/') else method_value))
            except Exception as e:
                print(e)
                pg, new = self.cache.get(
                    main_url + (method_value[:-1] if method_value.endswith('/') else method_value).replace(main_url,
                                                                                                           alternate_domains[
                                                                                                               0]))
            try:
                if new:
                    pg = html(pg)
                    srs = method_value.replace("/category", "")
                    season_id = pg.select_one("input[id='movie_id']")["value"]
                    container_main = pg.select_one('div[class="anime_info_body_bg"]')
                    ret = {}
                    title = reg_replace("\n|&nbsp;", "", container_main.select_one("h1").get_text())
                    ret["title"] = title
                    ret["image"] = container_main.select_one("img")["src"]
                    dets = container_main.select("p[class='type']")
                    for det in dets:
                        tit = det.select_one("span").get_text().replace(":", "").strip(" ").lower().split(" ")[0]
                        if tit == "type":
                            x = det.select_one("a")
                            x = x["title"] if x else ""
                            ret["released"] = x
                        if tit == "plot":
                            ret["description"] = det.get_text().replace(":", "", 1).replace("Plot Summary", "").replace(
                                "\n", "").strip(" ")
                        if tit == "genre":
                            ret["genre"] = [[i["href"], i["title"]] for i in det.select("a")]
                        if tit == "released":
                            ret["year"] = det.get_text().replace("Released", "").replace(":", "").replace("\n",
                                                                                                          "").strip(
                                " ")
                        if tit == "status":
                            x = det.select_one("a")
                            x = x.get_text() if x else ""
                            ret["time_seasons"] = x
                        if tit == "other":
                            ret["alternate_titles"] = [i.strip(" ") for i in
                                                       det.get_text().replace("Other name", "").replace(":",
                                                                                                        "").replace(
                                                           "\n",
                                                           "").strip(
                                                           " ").split(";")][::-1]
                    if len(ret.get("alternate_titles", [])) == 0:
                        ret["alternate_titles"] = [ret["title"]]
                    ret["episodes_count"] = pg.select("ul[id='episode_page']")[0].select("a[class*='active']")[0][
                        'ep_end']
                    self.cache[main_url + srs] = {"seasons": [["not available", season_id]]}
                    self.cache[main_url + method_value] = {"details": ret}
                else:
                    ret = pg["details"]
            except Exception as e:
                print("E4DCQ: ", e)
                search_term = ori_mval.replace("category/", "", 1).replace("-dub", "", 1).replace("-", " ").replace(
                    "api/gogo/details/category/", "")
                results = self.super_class.search(search_term)
                rslts_ckhk = f"Search Results {'S' if '-dub' not in ori_mval else 'D'}ubbed"
                for result in results[rslts_ckhk]:
                    if result["url"].startswith(f"/{ori_mval}") or result["url"].replace("-tv-").startswith(
                            f"/{ori_mval}"):
                        if _.get("internal_call", False) is True:
                            return self.super_class.details(result["url"], *__, **_)
                        elif _.get("internal_call", False) == "seasons":
                            self.super_class.details(result["url"], *__, **_)
                            return {"new_redirected:)": result["url"]}
                        else:
                            # return self.super_class.details("/api/gogo/details" + result["url"])
                            return RedirectResponse("/api/gogo/details" + result["url"])
                else:
                    return {"Status": "Error Please Search for this title and watch"}
            return ret

    def to_slug(self, method_value: str, dub="false", *__, **_):
        dub = dub == "true"

        def fetch_anilist_data(anilist_id: str) -> Any:
            url = 'https://graphql.anilist.co'
            query = f'''
                query {{
                        Media(id:{anilist_id}) {{
                            seasonYear
                            title{{
                                english
                                romaji
                            }}
                        }}
                }}
            '''

            data = {'query': query}
            response = load(self.session.get(url, post=True, body=data))
            return response

        anilist_data: Any = fetch_anilist_data(method_value)["data"]["Media"]
        anilist_title = [anilist_data['title']['romaji'], anilist_data['title']['english']]
        for x in [None, 'None']:
            if x in anilist_title:
                anilist_title.remove(x)
        if len(anilist_title) == 1:
            anilist_title *= 2
        search_results = self.search(anilist_title[0])
        if anilist_title[0] != anilist_title[1]:
            try:
                if f'Search Results {"D" if dub else "S"}ubbed' in search_results:
                    search_results[f'Search Results {"D" if dub else "S"}ubbed'].extend(
                        search_results2[f'Search Results {"D" if dub else "S"}ubbed'])
                else:
                    search_results = search_results2
            except: 
                pass
           
        for result in search_results[f'Search Results {"D" if dub else "S"}ubbed']:
            result: Any = result
            print(result)
            for title in anilist_title:
                
                if result['title'] == "Bleach" and result['released_year'] == "2012":
                    result['released_year'] = "2004"

                if str(result['released_year']) == str(anilist_data['seasonYear'])  :
                    return {"slug": result['url']}
        return {"slug": False}


gogo = Gogo()


def add_gogo(_app: FastAPI):
    @_app.get("/api/gogo/{method_call}/{method_value:path}")
    async def gogoAni(
            method_call: str, method_value: str, request_accessor: Request, season: str or None = None,
            episode: str or None = None,
            content_type: str or None = None, redirected_code: str or None = None, page=None, timeline=None,
            dub: str = "false"
    ):
        if method_call.startswith("_"):
            return
        try:
            fn_to_call = getattr(gogo, method_call)
            try:
                to_return = fn_to_call(
                    method_value=method_value, season=season, episode=episode, content_type=content_type,
                    redirected_code=redirected_code, page=page, timeline=timeline, request_accessor=request_accessor,
                    dub=dub,
                )
            except Exception as e:
                print(e)
                return JSONResponse({"error": e}, status_code=500)
            return to_return
        except AttributeError as e:
            print(e)
            return JSONResponse({"error": e}, status_code=403)


app = FastAPI()

add_gogo(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5010)
