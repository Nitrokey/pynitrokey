#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

def filepath_from_config(
    config: Dict,
    key: str,
    default_value: str,
    base_dir: str,
    output_folder: str = "",
    file_extension: str = ".bin",
) -> str:
    """Get file path from configuration dictionary and append .bin if the value is not blank.

    Function returns the output_folder + filename if the filename does not contain path.
    In case filename contains path, return filename and append ".bin".
    The empty string "" indicates that the user doesn't want the output.
    :param config: Configuration dictionary
    :param key: Name of the key
    :param default_value: default value in case key value is not present
    :param base_dir: base directory for path expansion
    :param output_folder: Output folder, if blank file path from config will be used
    :param file_extension: File extension that will be appended
    :return: filename with appended ".bin" or blank filename ""
    """
    filename = config.get(key, default_value)
    if filename == "":
        return filename
    if not os.path.dirname(filename):
        filename = os.path.join(output_folder, filename)
    if not filename.endswith(file_extension):
        filename += file_extension
    return get_abs_path(filename, base_dir)
