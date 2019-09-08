/*
* Copyright (c) 2008, TUBITAK/UEKAE
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
*/

#include <Python.h>
#include <datetime.h>
#include <unistd.h>
#include <glib.h>
#include <polkit/polkit.h>

PyObject *_polkit_module;

#if PY_MAJOR_VERSION >= 3
    #define PyInt_FromLong PyLong_FromLong
#endif
#if PY_MAJOR_VERSION >= 3
    #define PyString_FromString PyBytes_FromString
#endif
//! Standard exception for polkit
static PyObject *PK_Error;

//! Sets key of dictionary if value is not null
static void
dict_set_unless_null(PyObject *dict, const char *key, const char *value)
{
    if (value != NULL) {
        PyDict_SetItemString(dict, key, PyString_FromString(value));
    }
}

//! Returns a list of actions
static PyObject *
pk_action_list(PyObject *self, PyObject *args)
{
    g_type_init();

    GError *error = NULL;
    GList *glist, *gitem;
    PolkitAuthority *authority;
    PyObject *py_list = PyList_New(0);

    authority = polkit_authority_get();

    glist = polkit_authority_enumerate_actions_sync(authority, NULL, &error);
    for (gitem = glist; gitem; gitem = g_list_next(gitem)) {
        gpointer data = gitem->data;
        PyObject *py_dict = PyDict_New();
        // ID
        dict_set_unless_null(py_dict, "action_id", polkit_action_description_get_action_id(data));

        // Description
        dict_set_unless_null(py_dict, "description", polkit_action_description_get_description(data));

        // Message
        dict_set_unless_null(py_dict, "message", polkit_action_description_get_message(data));

        // Vendor
        dict_set_unless_null(py_dict, "vendor", polkit_action_description_get_vendor_name(data));

        // Vendor URL
        dict_set_unless_null(py_dict, "vendor_url", polkit_action_description_get_vendor_url(data));

        // Icon
        dict_set_unless_null(py_dict, "icon", polkit_action_description_get_icon_name(data));

        // Annotations
        PyObject *py_list2 = PyList_New(0);
        PyDict_SetItemString(py_dict, "annotations", py_list2);

        // Default policy
        PyDict_SetItemString(py_dict, "policy_any", PyString_FromString(polkit_implicit_authorization_to_string(polkit_action_description_get_implicit_any(data))));
        PyDict_SetItemString(py_dict, "policy_active", PyString_FromString(polkit_implicit_authorization_to_string(polkit_action_description_get_implicit_active(data))));
        PyDict_SetItemString(py_dict, "policy_inactive", PyString_FromString(polkit_implicit_authorization_to_string(polkit_action_description_get_implicit_inactive(data))));


        PyList_Append(py_list, py_dict);
        g_object_unref(data);
    }

    g_list_free(glist);
    g_list_free(gitem);

    return py_list;
}

//! Returns granted authorizations
static PyObject *
pk_auth_list_uid(PyObject *self, PyObject *args)
{
    int uid;
    if (!PyArg_ParseTuple(args, "i", &uid)) {
        return NULL;
    }

    PyObject *list = PyList_New(0);

    return list;
}

//! Returns granted authorizations
static PyObject *
pk_auth_list_all(PyObject *self, PyObject *args)
{
    PyObject *list = PyList_New(0);
    return list;
}

//! Authorize user for the given action a single time
static PyObject *
pk_auth_add(PyObject *self, PyObject *args)
{
    const char* action_id;
    int pid = -1;
    int uid = -1;
    int type = -1;

    if (!PyArg_ParseTuple(args, "sii|i", &action_id, &type, &uid, &pid)) {
        return NULL;
    }

    Py_INCREF(Py_False);
    return Py_False;
}

//! Revoke all authorizations of given user
static PyObject *
pk_auth_revoke_all(PyObject *self, PyObject *args)
{
    int uid = -1;

    if (!PyArg_ParseTuple(args, "i", &uid)) {
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

//! Revoke authorizations of given user for given action_id
static PyObject *
pk_auth_revoke(PyObject *self, PyObject *args)
{
    int uid = -1;
    const char *action_id;

    if (!PyArg_ParseTuple(args, "is", &uid, &action_id)) {
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

//! Grants a negative authorization to a user for a specific action
static PyObject *
pk_auth_block(PyObject *self, PyObject *args)
{
    int uid = -1;
    const char *action_id;

    if (!PyArg_ParseTuple(args, "is", &uid, &action_id)) {
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

//! polkit methods
static PyMethodDef polkit_methods[] = {
    {"action_list", (PyCFunction) pk_action_list, METH_NOARGS, "Lists all actions."},
    {"auth_list_uid", (PyCFunction) pk_auth_list_uid, METH_VARARGS, "List granted authorizations for specified UID."},
    {"auth_list_all", (PyCFunction) pk_auth_list_all, METH_NOARGS, "List granted authorizations."},
    {"auth_add", (PyCFunction) pk_auth_add, METH_VARARGS, "Authorize user for the given action."},
    {"auth_revoke_all", (PyCFunction) pk_auth_revoke_all, METH_VARARGS, "Revoke all authorizations of given user."},
    {"auth_revoke", (PyCFunction) pk_auth_revoke, METH_VARARGS, "Revoke authorization of given user for the given action."},
    {"auth_block", (PyCFunction) pk_auth_block, METH_VARARGS, "Grant a negative authorization to a user for a specific action."},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "_polkit",     /* m_name */
        "module for querying system-wide policy",  /* m_doc */
        -1,                  /* m_size */
        polkit_methods,    /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };
#endif


#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit__polkit(void)
#else
init_polkit(void)
#endif
{
    #if PY_MAJOR_VERSION >= 3
    PyObject *m = PyModule_Create(&moduledef);
    #else
    PyObject *m = Py_InitModule3("_polkit", polkit_methods, "module for querying system-wide policy");
    #endif

    if (m == NULL)
      return;

    PyModule_AddObject(m, "SCOPE_ONE_SHOT", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "SCOPE_PROCESS", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "SCOPE_SESSION", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "SCOPE_ALWAYS", PyInt_FromLong((long) 0));

    PyModule_AddObject(m, "TYPE_UID", PyInt_FromLong((long) 0));

    PyModule_AddObject(m, "DB_CAPABILITY_CAN_OBTAIN", PyInt_FromLong((long) 0));

    PyModule_AddObject(m, "CONSTRAINT_TYPE_REQUIRE_LOCAL", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "CONSTRAINT_TYPE_REQUIRE_ACTIVE", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "CONSTRAINT_TYPE_REQUIRE_EXE", PyInt_FromLong((long) 0));
    PyModule_AddObject(m, "CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT", PyInt_FromLong((long) 0));

    PK_Error = PyErr_NewException("polkit.error", NULL, NULL);
    Py_INCREF(PK_Error);
    PyModule_AddObject(m, "error", PK_Error);

    _polkit_module = m;
    return m;

}
