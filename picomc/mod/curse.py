import concurrent.futures
import json
import os
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePath
from tempfile import TemporaryFile
from xml.etree import ElementTree
from zipfile import ZipFile

import click
import requests
from tqdm import tqdm

from picomc.cli.utils import pass_instance_manager, pass_launcher
from picomc.downloader import DownloadQueue
from picomc.logging import logger
from picomc.mod import forge
from picomc.utils import Directory, die, sanitize_name


FORGE_PREFIX = "forge-"
BASE_URL = "http://api.curseforge.com/v1"
MOD_BASE_URL = "https://edge.forgecdn.net/files/%(file_id_1)s/%(file_id_2)s/%(file_name)s"

api_key = "$2a$10$NiDzXhmht.Z0XxLxnJfoS.16fEGSaTDjZrij0B2lZtL/iwUE2qUEG"

def resolve_project_id(proj_id):
    headers={
                    "X-API-Key": api_key,
                    "Accept": "application/json"
                }
    resp = requests.get(f"{BASE_URL}/mods/{proj_id}/files", headers=headers)
    resp.raise_for_status()
    meta = resp.json()
    files = meta["data"]
    files.sort(key=lambda f: f["fileDate"], reverse=True)
    return files[0]["downloadUrl"]


def get_file_url(file_id, proj_id=None):
    headers = {"User-Agent": "curl"}
    if proj_id is None:
        proj_id = "anything"
    resp = requests.get(GETURL_URL.format(proj_id, file_id), headers=headers)
    resp.raise_for_status()
    return resp.text


def resolve_packurl(path):
    if path.startswith("https://") and path.endswith(".zip"):
        return path
    regex = r"^(https:\/\/|twitch:\/\/)www\.curseforge\.com\/minecraft\/modpacks\/[-a-z0-9]+\/(download|download-client|files)\/(\d+)(\/file|\?client=y|)$"
    match = re.match(regex, path)
    if match:
        file_id = match.group(3)
        return get_file_url(file_id)
    else:
        regex = r"^curseforge:\/\/install\?addonId=\d+&fileId=(\d+)"
        match = re.match(regex, path)
        if match:
            file_id = match.group(1)
            return get_file_url(file_id)
        else:
            raise ValueError("Unsupported URL")


def resolve_ccip(filename):
    xml = ElementTree.parse(filename)
    proj_attr = xml.find("project").attrib
    return get_file_url(proj_attr["file"], proj_attr["id"])


def install_from_zip(zipfileobj, launcher, instance_manager, instance_name=None):
    with ZipFile(zipfileobj) as pack_zf:
        for fileinfo in pack_zf.infolist():
            fpath = PurePath(fileinfo.filename)
            if fpath.parts[-1] == "manifest.json" and len(fpath.parts) <= 2:
                manifest_zipinfo = fileinfo
                archive_prefix = fpath.parent
                break
        else:
            raise ValueError("Zip file does not contain manifest")

        with pack_zf.open(manifest_zipinfo) as fd:
            manifest = json.load(fd)

        assert manifest["manifestType"] == "minecraftModpack"
        assert manifest["manifestVersion"] == 1

        assert len(manifest["minecraft"]["modLoaders"]) == 1
        forge_ver = manifest["minecraft"]["modLoaders"][0]["id"]

        assert forge_ver.startswith(FORGE_PREFIX)
        forge_ver = forge_ver[len(FORGE_PREFIX) :]
        packname = manifest["name"]
        packver = manifest["version"]
        if instance_name is None:
            instance_name = "{}-{}".format(
                sanitize_name(packname), sanitize_name(packver)
            )
            logger.info(f"Installing {packname} version {packver}")
        else:
            logger.info(
                f"Installing {packname} version {packver} as instance {instance_name}"
            )

        if instance_manager.exists(instance_name):
            die("Instace {} already exists".format(instance_name))

        try:
            forge.install(
                versions_root=launcher.get_path(Directory.VERSIONS),
                libraries_root=launcher.get_path(Directory.LIBRARIES),
                forge_version=forge_ver,
            )
        except forge.AlreadyInstalledError:
            pass

        # Trusting the game version from the manifest may be a bad idea
        inst = instance_manager.create(
            instance_name,
            "{}-forge-{}".format(manifest["minecraft"]["version"], forge_ver),
        )
        # This is a random guess, but better than the vanilla 1G
        inst.config["java.memory.max"] = "4G"

        project_files = {mod["projectID"]: mod["fileID"] for mod in manifest["files"]}
        headers = {"User-Agent": "curl"}
        dq = DownloadQueue()

        logger.info("Retrieving mod metadata from curse")
        modcount = len(project_files)
        mcdir: Path = inst.get_minecraft_dir()
        moddir = mcdir / "mods"
        with tqdm(total=modcount) as tq:
            headers={
                    "X-API-Key": api_key,
                    "Accept": "application/json"
                }
            resp = requests.post(
                f"{BASE_URL}/mods/files", json={'fileIds': list(project_files.values())}, headers=headers)
            resp.raise_for_status()
            filess_meta = resp.json()
            for file_info in filess_meta['data']:
                proj_id = file_info["modId"]
                if file_info["downloadUrl"] is None:
                    # Guess the download url
                    file_id = file_info['id']
                    file_id = str(file_id)[1:] if str(file_id).startswith("0") else str(file_id)
                    file_id_1 = file_id[:4]
                    file_id_2 = file_id[4:7]
                    file_info["downloadUrl"] = MOD_BASE_URL % {
                        "file_id_1": file_id_1,
                        "file_id_2": file_id_2,
                        "file_name": file_info["fileName"]
                    }

                dq.add(
                    file_info["downloadUrl"],
                    moddir / file_info["fileName"],
                    size=file_info["fileLength"],
                )


            batch_recvd = modcount - len(project_files)
            logger.debug("Got {} batched".format(batch_recvd))
            tq.update(batch_recvd)

        logger.info("Downloading mod jars")
        dq.download()

        logger.info("Copying overrides")
        overrides = archive_prefix / manifest["overrides"]
        for fileinfo in pack_zf.infolist():
            if fileinfo.is_dir():
                continue
            fname = fileinfo.filename
            try:
                outpath = mcdir / PurePath(fname).relative_to(overrides)
            except ValueError:
                continue
            if not outpath.parent.exists():
                outpath.parent.mkdir(parents=True, exist_ok=True)
            with pack_zf.open(fileinfo) as infile, open(outpath, "wb") as outfile:
                shutil.copyfileobj(infile, outfile)

        logger.info("Done installing {}".format(instance_name))


def install_from_path(path, launcher, instance_manager, instance_name=None):
    if path.isascii() and path.isdecimal():
        path = resolve_project_id(path)
    elif os.path.exists(path):
        if path.endswith(".ccip"):
            path = resolve_ccip(path)
        elif path.endswith(".zip"):
            with open(path, "rb") as fd:
                return install_from_zip(fd, launcher, instance_manager, instance_name)
        else:
            die("File must be .ccip or .zip")

    zipurl = resolve_packurl(path)
    with requests.get(zipurl, stream=True) as r:
        r.raise_for_status()
        with TemporaryFile() as tempfile:
            for chunk in r.iter_content(chunk_size=8192):
                tempfile.write(chunk)
            install_from_zip(tempfile, launcher, instance_manager, instance_name)


@click.group("curse")
def curse_cli():
    """Handles modpacks from curseforge.com"""
    pass


@curse_cli.command("install")
@click.argument("path")
@click.option("--name", "-n", default=None, help="Name of the resulting instance")
@pass_instance_manager
@pass_launcher
def install_cli(launcher, im, path, name):
    """Install a modpack.

    An instance is created with the correct version of forge selected and all
    the mods from the pack installed.

    PATH can be a URL of the modpack (either twitch:// or https://
    containing a numeric identifier of the file), a path to either a downloaded
    curse zip file or a ccip file or the project ID."""
    install_from_path(path, launcher, im, name)


def register_cli(root):
    root.add_command(curse_cli)
