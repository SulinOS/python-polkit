import polkit

#print polkit.auth_list_all()
polkit.auth_add("tr.org.sulin.scom.net.link.set", None, 1000, None)
