import os
import os.path as op
import re
import copy
import argparse
import traceback
import ConfigParser
import io
import logging


import was_common
import was_consts as c


_LOGGER = logging.getLogger(c.was_log)


def _match_filter(path_parts, excludes, excluding=False):
    if excluding:
        for part in path_parts:
            for p in excludes:
                if re.match("^" + p + "$", part):
                    return True
    else:
        for p in excludes:
            if re.match("^" + p + "$", path_parts[-1]):
                return True
    return False


def create_generation_msg(msg):
    cur_dir = op.dirname(op.abspath(__file__))
    try:
        with open(op.join(cur_dir, ".gen"), "w") as f:
            f.write(msg)
    except OSError:
        _LOGGER.error("Failed to create generation msg")


def remove_generation_msg():
    cur_dir = op.dirname(op.abspath(__file__))
    msg_file = op.join(cur_dir, ".gen")
    if not op.exists(msg_file):
        return

    try:
        os.remove(msg_file)
    except OSError:
        _LOGGER.error("Failed to remove generation mark")


def get_generation_msg():
    cur_dir = op.dirname(op.abspath(__file__))
    msg_file = op.join(cur_dir, ".gen")
    if op.exists(msg_file):
        with open(msg_file) as f:
            return f.read()
    return ""


def get_monitoring_dirs(config):
    """
    @config: dict like object which contains:
    {
        was_install_dir: was_install_dir,
        exclude_dirs: exclude_dir,
        file_whitelist: file_whitelist,
    }
    """

    target_dirs = set()
    default_logs = (".log", ".txt", ".traceout")
    for root, _, files in os.walk(config[c.was_install_dir]):
        parts = root.split(op.sep)
        if "temp" in root.lower():
            continue

        if config[c.exclude_dirs]:
            if _match_filter(parts, config[c.exclude_dirs], True):
                continue

        if not config[c.file_whitelist]:
            for f in files:
                _, f = op.splitext(f)
                if f in default_logs:
                    target_dirs.add(root)
        else:
            for f in files:
                if re.search(config[c.file_whitelist], f):
                    target_dirs.add(root)
    return target_dirs


def generate_was_inputs_stanzas(config):
    """
    @config: dict like object which contains:
    {
        was_install_dir: was_install_dir,
        exclude_dirs: exclude_dir,
        file_whitelist: file_whitelist,
    }
    """

    if config[c.exclude_dirs]:
        config[c.exclude_dirs] = config[c.exclude_dirs].split(",")

    if config[c.file_whitelist]:
        config[c.file_whitelist] = config[c.file_whitelist].replace("*", ".*")

    target_dirs = get_monitoring_dirs(config)
    whitelist = config[c.file_whitelist]
    if not whitelist:
        whitelist = "\.log*$|\.txt*$|\.traceout*$"

    stanza = ("[monitor://{1}]{0}"
              "whitelist = {2}{0}"
              "crcSalt = <SOURCE>{0}"
              "disabled = false{0}"
              "followTail = false{0}"
              "index = {3}{0}{0}")
    stanzas = []
    for d in target_dirs:
        if os.name == "nt":
            d = d.replace("\\\\", "\\")
        content = stanza.format("\n", d, whitelist, config[c.index])
        stanzas.append(content)
    return stanzas


def _get_settings_from_file(d, section=None):
    file_dir = op.join(op.dirname(op.dirname(op.abspath(__file__))), d)
    was_conf = op.join(file_dir, "ibm_was.conf")
    settings = {}
    if not op.exists(was_conf):
        return settings

    parser = ConfigParser.ConfigParser()
    parser.optionxform = str
    with io.open(was_conf, "r", encoding="utf_8_sig") as fp:
        parser.readfp(fp)

    if section:
        for option in parser.options(section):
            settings[option] = parser.get(section, option)
    else:
        for section in parser.sections():
            settings[section] = {}
            for option in parser.options(section):
                settings[section][option] = parser.get(section, option)
    return settings


def _commit_configs(local_settings, opts, invalid_setting):
    g_section = c.was_global_settings
    fm_section = c.was_file_monitor_settings

    new_parser = ConfigParser.ConfigParser()
    for section, options in local_settings.iteritems():
        new_parser.add_section(section)
        for k, v in options.iteritems():
            new_parser.set(section, k, v)

    for s in (fm_section, g_section):
        if s not in new_parser.sections():
            new_parser.add_section(s)

    if opts.index != invalid_setting:
        new_parser.set(g_section, c.index, opts.index)

    if opts.was_install_dir != invalid_setting:
        new_parser.set(g_section, c.was_install_dir, opts.was_install_dir)

    new_parser.set(fm_section, c.was_file_monitor_enabled, "1")
    if opts.exclude_dirs != invalid_setting:
        new_parser.set(fm_section, c.exclude_dirs, opts.exclude_dirs)

    if opts.file_whitelist != invalid_setting:
        new_parser.set(fm_section, c.file_whitelist, opts.file_whitelist)

    file_dir = op.join(op.dirname(op.dirname(op.abspath(__file__))), "local")
    if not op.exists(file_dir):
        os.mkdir(file_dir)

    was_conf = op.join(file_dir, c.was_conf_file)

    with open(was_conf, "w") as fp:
        new_parser.write(fp)


def _get_configs():
    g_section = c.was_global_settings
    fm_section = c.was_file_monitor_settings
    settings = _get_settings_from_file("default")
    local_settings = _get_settings_from_file("local")

    # Override default with local
    for section, options in local_settings.iteritems():
        for k, v in options.iteritems():
            settings[section][k] = v

    fm_settings = copy.deepcopy(settings[fm_section])
    fm_settings.update(settings[g_section])

    invalid_setting = "xxx"
    parser = argparse.ArgumentParser()
    parser.add_argument("--was_install_dir", dest=c.was_install_dir, type=str,
                        action="store", required=False,
                        default=invalid_setting,
                        help="The root installation directory of WebSphere "
                        "Application Server")
    parser.add_argument("--index", dest=c.index, type=str,
                        action="store", required=False,
                        default=invalid_setting,
                        help="Splunk index to hold the data")
    parser.add_argument("--exclude_dirs", dest=c.exclude_dirs, type=str,
                        action="store", required=False,
                        default=invalid_setting,
                        help="The directories which should be excluded for "
                        "monitoring. Seperated by comma.")
    parser.add_argument("--file_whitelist", dest=c.file_whitelist, type=str,
                        action="store", required=False,
                        default=invalid_setting,
                        help="The whitelist of log files to be monitored. "
                        "Refer to http://docs.splunk.com/Documentation/Splunk/"
                        "latest/data/Specifyinputpathswithwildcards for more "
                        "details")

    opts = parser.parse_args()

    # CLI params override local
    for o in (c.was_install_dir, c.index, c.exclude_dirs, c.file_whitelist):
        val = getattr(opts, o)
        if val != invalid_setting:
            fm_settings[o] = val

    # CLI options commit to ibm_was.conf
    _commit_configs(local_settings, opts, invalid_setting)
    fm_settings["interactive"] = True
    return fm_settings


def _get_non_monitor_stanzas():
    local_dir = op.join(op.dirname(op.dirname(op.abspath(__file__))), "local")
    input_conf = op.join(local_dir, "inputs.conf")
    if not op.exists(input_conf):
        return ""

    stanzas = {}
    with io.open(input_conf, "r", encoding="utf_8_sig") as fp:
        parser = ConfigParser.ConfigParser()
        parser.optionxform = str
        parser.readfp(fp)
        for section in parser.sections():
            if section.startswith("monitor://"):
                continue

            kvs = []
            for o in parser.options(section):
                kvs.append(
                    "{} = {}".format(o, parser.get(section, o)))
            stanzas[section] = os.linesep.join(kvs)

    res = "".join(("[{1}]{0}{2}{0}{0}".format(os.linesep, k, v, os.linesep)
                   for k, v in stanzas.iteritems()))
    return res


def _do_generate_was_inputs(config):
    """
    @config: dict like object which contains:
    {
        was_install_dir: was_install_dir,
        exclude_dirs: exclude_dir,
        file_whitelist: file_whitelist,
        index: main,
        interactive: True,
    }
    """

    loc = config[c.was_install_dir]
    if not loc:
        loc = was_common.discover_was_install_dir(config.get("interactive"))
        if not loc:
            raise Exception("WebSphere Application Server installation "
                            "directory is not specified and can't be "
                            "discovered")
        else:
            config[c.was_install_dir] = loc

    create_generation_msg("inputs.conf generation is in progress...")
    if not op.exists(config[c.was_install_dir]):
        msg = ("Failed to generate inputs.conf, error={} installation "
               "dir doesn't exist.").format(config[c.was_install_dir])
        _LOGGER.error(msg)
        if config.get("interactive"):
            print msg
        create_generation_msg(msg)
        return

    stanzas = generate_was_inputs_stanzas(config)
    non_monitor_stanzas = _get_non_monitor_stanzas()

    local_dir = op.join(op.dirname(op.dirname(op.abspath(__file__))), "local")
    if not op.exists(local_dir):
        os.mkdir(local_dir)

    input_conf = op.join(local_dir, "inputs.conf")
    with open(input_conf, "w") as f:
        f.write(non_monitor_stanzas)
        f.write("".join(stanzas))

    if stanzas:
        create_generation_msg("inputs.conf has been successfully generated. "
                              "Reboot Splunkd to make the inputs.conf "
                              "effective")
    else:
        create_generation_msg("Warning: no files matched the filters.")

    if config.get("interactive"):
        print ("Finished generate inputs.conf under local directory, "
               "please very the file monitor data inputs in it and reboot "
               "Splunkd to make it effective.")


def generate_was_inputs(config):
    try:
        if os.name == "nt":
            install_dir = config[c.was_install_dir]
            if install_dir:
                replaced = install_dir.replace("\\", "\\\\")
                replaced = replaced.replace("\\\\\\\\", "\\\\")
                config[c.was_install_dir] = replaced
        _do_generate_was_inputs(config)
    except Exception:
        msg = "Failed to generate inputs.conf, error={}".format(
            traceback.format_exc())
        create_generation_msg("Failed to generate inputs.conf.")
        _LOGGER.error(msg)
        raise


def main():
    config = _get_configs()
    generate_was_inputs(config)


if __name__ == "__main__":
    main()
