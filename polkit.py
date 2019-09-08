#-*- coding: utf-8 -*-
"""
module for querying system-wide policy

 *
 * PolicyKit by David Zeuthen, <david@fubar.dk>
 * Python Bindings by Bahadır Kandemir <bahadir@pardus.org.tr>
 *                    Harald Hoyer <harald@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *

"""

import fnmatch
import sys
if sys.version_info > (3,):
    import configparser
else:
    import ConfigParser as configparser
import os
import pwd

import _polkit

from _polkit import (
    SCOPE_ONE_SHOT,
    SCOPE_PROCESS,
    SCOPE_SESSION,
    SCOPE_ALWAYS,
    TYPE_UID,
    DB_CAPABILITY_CAN_OBTAIN,
    CONSTRAINT_TYPE_REQUIRE_LOCAL,
    CONSTRAINT_TYPE_REQUIRE_ACTIVE,
    CONSTRAINT_TYPE_REQUIRE_EXE,
    CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT,
    error
    )

DB_FILE = "/etc/polkit-1/localauthority/10-vendor.d/pardus.pkla"


def action_list():
    """
    Lists all action_ids

    returns :
        A list() of action_ids
    """
    return [x["action_id"] for x in _polkit.action_list()]

def action_info(action_id):
    """
    Gives details about action_id

    action_id :
         Action id

    returns :
        A dict() of details about action_id
    """
    for act in _polkit.action_list():
        if act["action_id"] == action_id:
            return act
    return {}

def auth_list_uid(uid):
    """
    Lists all authorizations given to uid.

    uid :
        User ID

    returns :
        A list() of authorizations
    """

    return [x for x in auth_list_all() if x["uid"] == uid]

def auth_list_all():
    """
    Lists all authorizations given.

    returns :
         A list() of authorizations
    """

    authorizations = []

    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(DB_FILE)

    actions = action_list()

    for title in cp.sections():
        if not title.startswith("user:"):
            continue
        # UID and Action ID
        try:
            _uid = pwd.getpwnam(title.split(":")[1]).pw_uid
            _action_id = title.split(":")[2]
        except KeyError:
            continue

        if _action_id not in actions:
            continue

        auth = {
            "action_id": _action_id,
            "uid": _uid,
            "type": 3,
            "scope": 0,
            "negative": cp.get(title, "ResultAny") == "no",
        }
        authorizations.append(auth)

    return authorizations

def auth_add(action_id, auth_type, uid, pid=None):
    """
    action_id :
        Action ID

    auth_type :
        Authorization type.
        Should be one of SCOPE_ONE_SHOT, SCOPE_PROCESS,
        SCOPE_SESSION or SCOPE_ALWAYS

    uid :
        User ID

    pid :
        Process ID of process to grant authorization to.
        Normally one wants to pass result of os.getpid().
    """
    user = pwd.getpwuid(uid).pw_name

    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(DB_FILE)

    title = "user:%s:%s" % (user, action_id)

    if title in cp.sections():
        cp.remove_section(title)

    cp.add_section(title)
    cp.set(title, "Action", action_id)
    cp.set(title, "Identity", "unix-user:%s" % user)
    cp.set(title, "ResultAny", "yes")
    cp.set(title, "ResultInactive", "yes")
    cp.set(title, "ResultActive", "yes")

    with open(DB_FILE, "w") as configfile:
        cp.write(configfile)

def auth_revoke_all(uid):
    """
    Removes all authorizations of UID from the authorization database.

    uid :
        User ID
    """

    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(DB_FILE)

    user = pwd.getpwuid(uid).pw_name

    sections = cp.sections()
    for title in sections:
        if title.startswith("user:%s:" % user):
            cp.remove_section(title)

    with open(DB_FILE, "w") as configfile:
        cp.write(configfile)

def auth_revoke(uid, action_id):
    """
    Removes authorization of UID to perform action_id from the
    authorization database.

    uid :
        User ID

    action_id :
        Action ID
    """

    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(DB_FILE)

    user = pwd.getpwuid(uid).pw_name

    sections = cp.sections()
    for title in sections:
        if title == "user:%s:%s" % (user, action_id):
            cp.remove_section(title)

    with open(DB_FILE, "w") as configfile:
        cp.write(configfile)

def auth_block(uid, action_id):
    """
    Grants a negative authorization to a user for a specific action

    A negative authorization is normally used to block users that
    would normally be authorized from an implicit authorization.

    uid :
        User ID

    action_id :
        Action ID
    """
    user = pwd.getpwuid(uid).pw_name

    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(DB_FILE)

    title = "user:%s:%s" % (user, action_id)

    if title in cp.sections():
        cp.remove_section(title)

    cp.add_section(title)
    cp.set(title, "Action", action_id)
    cp.set(title, "Identity", "unix-user:%s" % user)
    cp.set(title, "ResultAny", "no")
    cp.set(title, "ResultInactive", "no")
    cp.set(title, "ResultActive", "no")

    with open(DB_FILE, "w") as configfile:
        cp.write(configfile)
