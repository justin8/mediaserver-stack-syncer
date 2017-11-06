#!/usr/bin/env python3

from hashlib import md5
from pathlib import Path
import logging
import os
import shutil
import socket
import subprocess
import sys
import yaml

import click
import ffmpy
import paramiko

log = logging.getLogger("mediaserver-stack-syncer")

FAKE_LIBRARIES_PATH = Path(os.environ["HOME"]).joinpath(".config/mediaserver-stack-syncer")
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
CONFIG = SCRIPT_DIR.joinpath("mediaserver-stack-syncer.conf")

MOVIES = "movies"
TV = "tv"
VALID_TYPES = [MOVIES, TV]

global_config = {}


def set_log_level(verbose):
    log_level = logging.ERROR
    if verbose == 1:
        log_level = logging.WARNING
    if verbose == 2:
        log_level = logging.INFO
    if verbose >= 3:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)


def read_config():
    log.info("Reading config from '{}'".format(CONFIG))
    with CONFIG.open() as f:
        config = yaml.load(f)

    global global_config
    global_config = config["global"]
    libraries = config["libraries"]

    validate_config(global_config, library_validation=False)
    for library in libraries:
        validate_config(library)

    print("Loaded {} libraries from config".format(len(libraries)))
    return libraries


def get_value(library, key):
    return library[key] if key in library.keys() else global_config[key]


# For some reason you can't call assert inside a lambda?
def assert_wrapper(value):
    assert(value)


def assert_config(config, key, func):
    try:
        if key in config:
            func()
    except:
        print("Invalid value for '{}' in library '{}'".format(key, config["local_path"]))
        sys.exit(1)


def validate_config(config, library_validation=True):
    assert_config(config, "local_path",
                  lambda: assert_wrapper(os.path.exists(config["local_path"])))

    assert_config(config, "remote_user",
                  lambda: assert_wrapper(type(config["remote_user"]) == str))

    assert_config(config, "remote_path",
                  lambda: assert_wrapper(type(config["remote_path"]) == str))

    assert_config(config, "remote_port",
                  lambda: assert_wrapper(type(config["remote_port"]) == int))

    assert_config(config, "remote_host",
                  lambda: assert_wrapper(type(config["remote_host"]) == str))
    assert_config(config, "remote_host",
                  lambda: socket.gethostbyname(config["remote_host"]))

    assert_config(config, "permissions",
                  lambda: assert_wrapper(type(config["permissions"]) == int))

    assert_config(config, "type",
                  lambda: assert_wrapper(config["type"] in VALID_TYPES))

    if library_validation:
        try:
            keys = ["local_path", "remote_user", "remote_path", "remote_port", "remote_host", "permissions", "type"]
            for key in keys:
                get_value(config, key)
        except:
            print("'{}' is missing from the config for library {}".format(key, config["local_path"]))
            sys.exit(1)


def validate_port(port):
    assert(type(port) == int)


def pull_media(library):
    print("Pulling library ({})".format(get_value(library, "local_path")))
    ssh = ssh_connection(library)
    new_files = find_new_files(library, ssh)
    sftp = ssh.open_sftp()
    for file in new_files:
        remote_source_file = Path(file)
        relative_file_path = remote_source_file.relative_to(get_value(library, "remote_path"))
        local_target_file = Path(get_value(library, "local_path")).joinpath(relative_file_path)
        print("Syncing remote file '{}'".format(remote_source_file))
        local_target_file.parent.mkdir(parents=True, exist_ok=True)
        pull_file(library, relative_file_path)
        os.chmod(local_target_file, get_value(library, "permissions"))
        if get_value(library, "type") == MOVIES:
            sftp.remove(str(remote_source_file))
    return new_files


def pull_file(library, relative_path):
    port = get_value(library, "remote_port")
    user = get_value(library, "remote_user")
    host = get_value(library, "remote_host")

    remote_library = get_value(library, "remote_path")
    source = "{}@{}:{}/{}".format(user, host, remote_library, relative_path)

    local_library = get_value(library, "local_path")
    destination = "{}/{}".format(local_library, relative_path)

    command = ["rsync", "-asqe", "ssh -p {}".format(port), source, destination]
    log.debug("Pulling file with command: {}".format(command))
    subprocess.check_output(command)


def find_new_files(library, ssh_conn):
    command = "find {} -size +20M".format(get_value(library, "remote_path"))
    try:
        stdin, stdout, stderr = ssh_conn.exec_command(command)
    except Exception as e:
        ssh_conn.close()
        raise(e)

    new_files = []
    for file in stdout:
        if is_video(file):
            new_files.append(file.strip("\n"))
    log.info("Found new files: {}".format(new_files))
    return new_files


def ssh_connection(library):
    port = get_value(library, "remote_port")
    host = get_value(library, "remote_host")
    username = get_value(library, "remote_user")
    log.debug("Creating ssh connection to host: {}, port: {}".format(host, port))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()
    # TODO: remove hardcoded password
    ssh.connect(host, port=port, username=username)
    return ssh


def fake_library_path(library):
    library_hash = md5(get_value(library, "local_path").encode("utf-8")).hexdigest()
    return FAKE_LIBRARIES_PATH.joinpath(library_hash)


def create_fake_library(library):
    real_library_path = Path(get_value(library, "local_path"))
    print("Creating fake library for {}".format(real_library_path))
    fake_library = fake_library_path(library)
    log.info("Local fake library path: {}".format(fake_library))
    fake_library.mkdir(parents=True, exist_ok=True)

    for file in alliter(real_library_path):
        log.debug("Working on {}".format(file))
        if is_video(file):
            log.debug("Found video ({})".format(file))
            relative_video_path = file.relative_to(real_library_path)
            fake_video = fake_library.joinpath(relative_video_path)
            create_fake_video(file, fake_video)


def create_fake_video(real_video, fake_video):
    if fake_video.exists():
        log.info("Fake video already exists. ({})".format(fake_video))
        return

    log.info("Creating fake video for {}".format(fake_video))
    fake_video.parent.mkdir(parents=True, exist_ok=True)
    
    ff = ffmpy.FFmpeg(
            inputs={str(real_video): None},
            outputs={str(fake_video): "-vcodec copy -an -t 00:00:01"})
    log.debug("Running command: {}".format(ff.cmd))
    try:
        ff.run()
    except Exception as e:
        print("Failed to convert video! ({})".format(real_video))
        raise(e)
    shutil.copystat(real_video, fake_video)


def alliter(p):
    yield p
    for sub in p.iterdir():
        if sub.is_dir():
            yield from alliter(sub)
        else:
            yield sub


def is_video(f):
    videoExtensions = (".avi", ".divx", ".mkv", ".mp4", ".mpg", ".mpeg", ".mov", 
                       ".m4v", ".flv", ".ts", ".wmv")
    file_name = str(f).strip("\n")
    return file_name.lower().endswith(videoExtensions)


def ensure_trailing_slash(path):
    path = str(path)
    return path if path.endswith("/") else path + "/"


def push_tv(library):
    port = get_value(library, "remote_port")
    user = get_value(library, "remote_user")
    host = get_value(library, "remote_host")

    remote_library = ensure_trailing_slash(get_value(library, "remote_path"))
    remote_target = "{}@{}:{}".format(user, host, remote_library)

    local_fake_library = ensure_trailing_slash(fake_library_path(library))

    command = ["rsync", "--info=progress2", "-ase", "ssh -p {}".format(port), local_fake_library, remote_target]
    print("Pushing fake library to remote host (Command: '{}'".format(command))
    subprocess.check_output(command)


def purge_remote_library(library):
    print("Purging remote library...")
    ssh_conn = ssh_connection(library)
    ssh_conn.exec_command("rm -rf {}/*".format(library["remote_path"]))


def purge_cache(library):
    fake_library = fake_library_path(library)
    shutil.rmtree(fake_library, ignore_errors=True)


@click.command()
@click.option("-v", "--verbose", count=True, help="Enable more logging. More -v's for more logging")
@click.option("--push-only", is_flag=True, default=False, help="Do not pull changes, only generate fake libraries and push them")
@click.option("--purge-remote", is_flag=True, default=False, help="Delete all files on the remote host first")
@click.option("--purge-local-cache", is_flag=True, default=False, help="Delete the local library cache")
def start_sync(verbose, push_only, purge_remote, purge_local_cache):
    set_log_level(verbose)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 27584))
        s.listen(1)
    except:
        print("Another instance is already running")
        sys.exit(1)

    for library in read_config():
        if purge_remote:
            purge_remote_library(library)
        if purge_local_cache:
            purge_cache(library)
        if library["type"] == TV:
            log.info("Found TV library: {}".format(library))
            if push_only or pull_media(library):
                create_fake_library(library)
                push_tv(library)
        if library["type"] == MOVIES:
            log.info("Found Movie library: {}".format(library))
            if not push_only:
                pull_media(library)
        print("Finished syncing library '{}'".format(get_value(library, "local_path")))
        print("---------------------------------------")


if __name__ == "__main__":
    start_sync()
