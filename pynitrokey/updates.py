# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import os.path
import urllib.parse
from dataclasses import dataclass
from typing import BinaryIO, Callable, Dict, Generator, Optional, Pattern

import requests

API_BASE_URL = "https://api.github.com"


ProgressCallback = Callable[[int, int], None]


class DownloadError(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__("Cannot download firmware: " + msg)


class OverwriteError(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(f"File {path} already exists and may not be overwritten")
        self.path = path


@dataclass
class Asset:
    tag: str
    url: str

    def download(
        self, f: BinaryIO, callback: Optional[ProgressCallback] = None
    ) -> None:
        for chunk in self._get_chunks(callback=callback):
            f.write(chunk)

    def download_to_dir(
        self,
        d: str,
        overwrite: bool = False,
        callback: Optional[ProgressCallback] = None,
    ) -> str:
        if not os.path.exists(d):
            raise DownloadError(f"Directory {d} does not exist")
        if not os.path.isdir(d):
            raise DownloadError(f"{d} is not a directory")
        url = urllib.parse.urlparse(self.url)
        filename = os.path.basename(url.path)
        path = os.path.join(d, filename)
        if os.path.exists(path) and not overwrite:
            raise OverwriteError(path)
        with open(path, "wb") as f:
            self.download(f, callback=callback)
        return path

    def read(self, callback: Optional[ProgressCallback] = None) -> bytes:
        result = bytes()
        for chunk in self._get_chunks(callback=callback):
            result += chunk
        return result

    def _get_chunks(
        self, chunk_size: int = 1024, callback: Optional[ProgressCallback] = None
    ) -> Generator[bytes, None, None]:
        response = self._get(stream=True)
        total = int(response.headers.get("content-length", 0))
        if callback:
            callback(0, total)

        for chunk in response.iter_content(chunk_size=chunk_size):
            if callback:
                callback(len(chunk), total)
            yield chunk

    def _get(self, stream: bool = False) -> requests.Response:
        response = requests.get(self.url, stream=stream)
        response.raise_for_status()
        return response

    def __str__(self) -> str:
        return self.url


@dataclass
class Release:
    tag: str
    assets: list[str]

    def __str__(self) -> str:
        return self.tag

    def find_asset(self, url_pattern: Pattern) -> Optional[Asset]:
        urls = []
        for asset in self.assets:
            if url_pattern.search(asset):
                urls.append(asset)

        if len(urls) == 1:
            return Asset(tag=self.tag, url=urls[0])
        elif len(urls) > 1:
            raise ValueError(
                f"Found multiple assets for release {self.tag} matching {url_pattern}"
            )
        else:
            return None

    def require_asset(self, url_pattern: Pattern) -> Asset:
        update = self.find_asset(url_pattern)
        if not update:
            raise ValueError(
                f"Failed to find asset for release {self.tag} matching {url_pattern}"
            )
        return update

    @classmethod
    def _from_api_response(cls, release: dict) -> "Release":
        tag = release["tag_name"]
        assets = [asset["browser_download_url"] for asset in release["assets"]]
        if not assets:
            raise ValueError(f"No update files for firmware release {tag}")
        return cls(tag=tag, assets=assets)


@dataclass
class Repository:
    owner: str
    name: str

    def get_latest_release(self) -> Release:
        release = self._call(f"/repos/{self.owner}/{self.name}/releases/latest")
        return Release._from_api_response(release)

    def get_release(self, tag: str) -> Release:
        release = self._call(
            f"/repos/{self.owner}/{self.name}/releases/tags/{tag}",
            {404: f"Failed to find firmware release {tag}"},
        )
        return Release._from_api_response(release)

    def get_release_or_latest(self, tag: Optional[str] = None) -> Release:
        if tag:
            return self.get_release(tag)
        return self.get_latest_release()

    def _call(self, path: str, errors: Dict[int, str] = dict()) -> dict:
        url = self._get_url(path)
        response = requests.get(url)
        for code in errors:
            if response.status_code == code:
                raise ValueError(errors[code])
        response.raise_for_status()
        return response.json()

    def _get_url(self, path: str) -> str:
        return API_BASE_URL + path
