from virttest import virt_admin
from virttest import utils_libvirtd
from virttest import utils_misc

import logging as log
logging = log.getLogger('avocado.' + __name__)

import os
import uuid

def run(test, params, env):
    """
    Test virt-admin srv-threadpool-info

    1) Change the threadpool related parameters in daemon conf file;
    2) Restart daemon;
    3) Check whether the parameter value listed by srv-threadpool-info
       are the same with the above settings.
    """
    min_workers = params.get("min_workers")
    max_workers = params.get("max_workers")
    prio_workers = params.get("prio_workers")
    admin_min_workers = params.get("admin_min_workers")
    admin_max_workers = params.get("admin_max_workers")
    server_name = params.get("server_name")

    os.environ["VIRT_ADMIN_DEBUG"] = "0"
    os.environ["VIRT_ADMIN_LOG_FILE"] = "/tmp/virt_admin_" + str(uuid.uuid4()) + ".log"
    logging.info("Virt Admin logfile: {}".format(os.environ["VIRT_ADMIN_LOG_FILE"]))

    libvirt_debug_path = "/tmp/libvirt_debug_" + str(uuid.uuid4()) + ".log"
    os.environ["LIBVIRT_LOG_OUTPUTS"] = "1:file:" + libvirt_debug_path
    logging.info("libvirt debug file: {}".format(libvirt_debug_path))

    if not server_name:
        server_name = virt_admin.check_server_name()

    config = virt_admin.managed_daemon_config()
    daemon = utils_libvirtd.Libvirtd("virtproxyd", all_daemons=True)
    vqemud = utils_libvirtd.Libvirtd("virtqemud")

    try:
        if server_name == "admin":
            config.admin_min_workers = admin_min_workers
            config.admin_max_workers = admin_max_workers
        else:
            config.min_workers = min_workers
            config.max_workers = max_workers
            config.prio_workers = prio_workers

        daemon.restart()
        logging.info("Is daemon running? {}".format(daemon.is_running()))
        logging.info(str(daemon.__dict__))
        virt_admin.srv_list(uri="virtqemud:///system", ignore_status=False)

        utils_misc.wait_for(daemon.is_running, 360)
        utils_misc.wait_for(vqemud.is_running, 360)
        result = virt_admin.srv_threadpool_info(server_name, ignore_status=False,
                                                debug=True, uri="virtqemud:///system")
        logging.info("Is daemon running? {}".format(daemon.is_running()))

        output = result.stdout_text.strip().splitlines()
        out_split = [item.split(':') for item in output]
        out_dict = dict([[item[0].strip(), item[1].strip()] for item in out_split])

        if result.exit_status:
            test.fail("This operation should success "
                      "but failed! Output: \n %s" % result)
        else:
            if server_name == "admin":
                if not (out_dict["minWorkers"] == admin_min_workers and
                        out_dict["maxWorkers"] == admin_max_workers):
                    test.fail("attributes info listed by "
                              "srv-threadpool-info is not correct!")
            else:
                if not (out_dict["minWorkers"] == min_workers and
                        out_dict["maxWorkers"] == max_workers and
                        out_dict["prioWorkers"] == prio_workers):
                    test.fail("attributes info listed by "
                              "srv-threadpool-info is not correct!")
    finally:
        config.restore()
        daemon.restart()
