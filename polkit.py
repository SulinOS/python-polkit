import _polkit

def action_list():
    """
    Lists all actions defined in .policy files.

    returns :
         A list of action_ids
    """
    return _polkit.action_list()

def action_info(action_id):
    """
    Gives all actions defined in .policy files.

    action_id :
        Action ID to get details about.

    returns :
         A dictionary with description, message, vendor, vendor
         url, icon and annotations fields.
    """
    return _polkit.action_info(action_id)

def check_auth(pid, *args):
    """
    This function is similar to polkit_check_authv(),
    but takes the action_ids as a plain parameter list.
    """
    return check_authv(pid, args)

def check_authv(pid, action_ids):
    """
    A simple convenience function to check whether a given 
    process is authorized for a number of actions.

    This is useful for programs that just wants to check whether 
    they should carry out some action. Note that the user identity 
    used for the purpose of checking authorizations is the Real 
    one compared to the e.g. Effective one (e.g. getuid(), getgid() 
    is used instead of e.g. geteuid(), getegid()). This is typically 
    what one wants in a setuid root program if the setuid root program
    is designed to do work on behalf of the unprivileged user who 
    invoked it (for example, the PulseAudio sound server is setuid 
    root only so it can become a real time process; after that it
    drops all privileges).

    It varies whether one wants to pass getpid() or getppid() as 
    the process id to this function. For example, in the PulseAudio 
    case it is the right thing to pass getpid(). However, in a setup 
    where the process is a privileged helper, one wants to pass the 
    process id of the parent. Beware though, if the parent dies, getppid()
    will return 1 (the process id of /sbin/init) which is almost 
    certainly guaranteed to be privileged as it is running as uid 0.

    Note that this function will open a connection to the system 
    message bus and query ConsoleKit for details. In addition, it 
    will load PolicyKit specific files and spawn privileged helpers 
    if necessary. As such, there is a bit of IPC, context switching, 
    syscall overhead and I/O involved in using this function.

    pid :
        Process ID of process to grant authorization to. 
        Normally one wants to pass result of os.getpid().

    action_ids :
         A list or tuple of action id strings

    returns :
         A set() of action_ids, where authentication succeeded
    """
    ret = _polkit.check_authv(pid, action_ids)
    auth = set()
    for i, action in enumerate(action_ids):
        if (ret & (1<<i)):
            auth.add(action)
    return auth

def auth_obtain(action_id, xid, pid):
    """
    Convenience function to prompt the user to authenticate to 
    gain an authorization for the given action. First, an attempt 
    to reach an Authentication Agent on the session message bus is made.
    If that doesn't work and stdout/stdin are both tty's, 
    polkit-auth(1) is invoked. 

    action_id :
        The action_id string for the PolKitAction to make the 
        user authenticate for.

    xid :
        X11 window ID for the window that the dialog will be transient for.
        If there is no window, pass 0.

    pid :
        Process ID of process to grant authorization to. 
        Normally one wants to pass result of os.getpid().     
    """
    if action_id in check_auth(pid, action_id):
        return True

    ret = _polkit.auth_obtain(action_id, xid, pid)
    if (ret is list):
        raise PolicyKitException, "%s: %s" % ret
    return ret != 0

class PolicyKitException(Exception):
    pass

__all__ = [ 
        "polkit_check_auth",
        "polkit_check_authv",
        "polkit_auth_obtain",
        "PolicyKitException",
        ]
