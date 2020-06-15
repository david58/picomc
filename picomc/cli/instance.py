import functools

import click

from picomc.account import AccountError
from picomc.env import Env
from picomc.instance import Instance
from picomc.logging import logger
from picomc.utils import get_filepath, sanitize_name


def instance_list():
    import os

    yield from (
        name for name in os.listdir(get_filepath("instances")) if Instance.exists(name)
    )


def instance_cmd(fn):
    @click.argument("instance_name")
    @functools.wraps(fn)
    def inner(*args, instance_name, **kwargs):
        return fn(*args, instance_name=sanitize_name(instance_name), **kwargs)

    return inner


@click.group()
def instance_cli():
    """Manage your instances."""
    pass


@instance_cli.command()
@instance_cmd
@click.argument("version", default="latest")
def create(instance_name, version):
    """Create a new instance."""
    if Instance.exists(instance_name):
        logger.error("An instance with that name already exists.")
        return
    with Instance(instance_name) as inst:
        inst.populate(version)


@instance_cli.command()
def list():
    """Show a list of instances."""
    print("\n".join(instance_list()))


@instance_cli.command()
@instance_cmd
def delete(instance_name):
    """Delete the instance (from disk)."""
    if Instance.exists(instance_name):
        Instance.delete(instance_name)
    else:
        logger.error("No such instance exists.")


@instance_cli.command()
@instance_cmd
@click.option("--account", default=None)
@click.option("--version-override", default=None)
def launch(instance_name, account, version_override):
    """Launch the instance."""
    if account is None:
        account = Env.am.get_default()
    else:
        account = Env.am.get(account)
    if not Instance.exists(instance_name):
        logger.error("No such instance exists.")
        return
    with Instance(instance_name) as inst:
        try:
            inst.launch(account, version_override)
        except AccountError as e:
            logger.error("Not launching due to account error: {}".format(e))


@instance_cli.command()
@instance_cmd
def dir(instance_name):
    """Print root directory of instance."""
    if not instance_name:
        print(get_filepath("instances"))
    else:
        # Careful, if configurable instance dirs are added, this breaks.
        print(get_filepath("instances", instance_name))


def register_instance_cli(picomc_cli):
    picomc_cli.add_command(instance_cli, name="instance")