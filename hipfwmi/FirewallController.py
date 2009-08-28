#!/usr/bin/env python

import os
import sys
import syslog
import traceback
import ConfigParser

revision = '$Id: FirewallController.py 11 2005-12-28 11:40:48Z jmtapio $'


"""Main module for controlling the actual HIP firewall.

This module should be started with root privileges. It will spawn the
ManagementLogic as a separate process for listening and implementing
configuration requests.

The main use of this module is to set things up and restart the actual
firewall daemon when the ManagementLogic has changed the rule file.
Reloading is done using the reloadcommand specified in the
hipfirewall-section of the management interface configuration file.
"""


class FirewallController(object):
    """HIP firewall controller.

    Sets up the pair of daemons for controlling the HIP
    firewall. Spawns ManagementLogic and reloads the firewall when
    ManagementLogic reports the need for it.
    """
    
    def __init__(self):
        self.load_configuration()

    def load_configuration(self):
        """Process configuration files.
        """
        cfg = ConfigParser.ConfigParser()
        cfg.read('hipmi.conf')
        # TODO: add error checking:
        self.listeninterface = cfg.get('daemon', 'interface')
        self.listenport      = cfg.getint('daemon', 'port')
        self.pid             = cfg.getint('daemon', 'pid')
        self.gid             = cfg.getint('daemon', 'gid')
        self.pidfile         = cfg.get   ('daemon', 'pidfile')
        self.fwreloadcmd     = cfg.get   ('hipfirewall', 'reloadcommand')
        self.fwrulefile      = cfg.get   ('hipfirewall', 'rulefile')
        self.keydir          = cfg.get   ('hipfirewall', 'keydirectory')

    def save_pidfile(self):
        """Save our pid to the pidfile.

        Pidfile's name is specified by the pidfile option in the
        daemon-section of the configuration file.
        """
        syslog.syslog('Saving pid to %s.' % self.pidfile)
        try:
            fd = os.open(self.pidfile, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0622)
            os.write(fd, '%d\n' % os.getpid())
            os.close(fd)
        except OSError, e:
            # TODO: check if there is a pid in the pidfile and if such a pid is alive
            syslog.syslog('Error saving pidfile %s: %s' % (self.pidfile, e))
        except:
            syslog.syslog('Error in save_pidfile(): %s' % \
                          '; '.join(
                [s.strip() for s in
                 traceback.format_exception(sys.exc_type, sys.exc_value,
                                            sys.exc_traceback)])
                          )

    def clean_pidfile(self):
        """Remove the pidfile we have previously saved (supposedly)."""
        # TODO: do this properly
        try:
            os.unlink(self.pidfile)
        except:
            pass

    def daemonize(self):
        """Makeself a daemon process.

        Double fork, close standard pipes, start a new session and
        open logs.
        """
        pid = os.fork()
        if pid == 0:  # first child
            os.setsid()
            pid = os.fork()
            if pid == 0:  # second child
                # Can't chdir to root if we have relative paths to
                # conffile and other modules
                #os.chdir('/')
                os.umask(0)
            else:
                os._exit(0)
        else:
            os._exit(0)

        # close stdin, stdout and stderr ...
        for fd in range(3):
            try:
                os.close(fd)
            except OSError:
                pass
        # ... and replace them with /dev/null
        os.open('/dev/null', os.O_RDWR)
        os.dup(0)
        os.dup(0)

        syslog.openlog('hip-mgmt-iface',
                       syslog.LOG_PID | syslog.LOG_NDELAY,
                       syslog.LOG_DAEMON)
        syslog.syslog('FirewallController started.')

    def start_management_logic(self):
        """Start a child process and run ManagementLogic in it.

        Creates a pipe to communicate with the child process.
        """
        parent_in, child_out = os.pipe()

        pid = os.fork()
        if pid == 0:
            # This block is executed within the management logic's process.
            # Close unneeded file descriptors.
            os.close(parent_in)
            os.dup2(child_out, 1)
            os.close(child_out)
            # Redirect sys.stdout to the fresh child-parent-pipe.
            sys.stdout = os.fdopen(1, 'w')

            try:
                try:
                    import ManagementLogic
                    mgmtlogic = ManagementLogic.ManagementLogic(
                        self.listeninterface, self.listenport,
                        self.fwrulefile, self.keydir)
                    syslog.syslog('ManagementLogic started.')
                    # Drop root privileges (group first, then uid)
                    os.setgid(self.gid)
                    os.setuid(self.pid)
                    mgmtlogic.enable_debugging()
                    mgmtlogic.run()
#                except StandardException, e:
#                    syslog.syslog('Management Logic failed: %s' % e)
                except Exception, e:
                    # temporary hack to improve logging during developement
                    import traceback
                    f = open('/tmp/traceback', 'w')
                    traceback.print_exc(file=f)
                    f.close()
                    syslog.syslog("APUVA, APUVA, APUVA")
            finally:
                syslog.syslog('Closing down.')
                syslog.closelog()
                sys.exit(0)

        else:
            # This block is executed within the firewall controller's process
            self.mgmtlogic_in = os.fdopen(parent_in, 'r', 1)
            os.close(child_out)

    def do_processing(self):
        """Process incoming requests from the ManagementLogic.

        Process incoming requests from the ManagementLogic until it
        closes the control pipe. After that return false and let run()
        clean up.
        """
        line = self.mgmtlogic_in.readline()
        if line == '':
            return False
        line = line.strip()
        if line.startswith('reloadfw'):
            syslog.syslog('reloading fw')
            # this is a bit naughty
            os.system(self.fwreloadcmd)
        else:
            syslog.syslog('Unknown message from ManagementLogic: %s' % repr(line))
        return True
    
    def run(self):
        """Start doing the firewallcorish stuff."""
        self.daemonize()
        self.save_pidfile()
        try:
            self.start_management_logic()
        except StandardError:
            syslog.syslog('Error, exiting: %s' % \
                          '; '.join(
                [s.strip() for s in
                 traceback.format_exception(sys.exc_type, sys.exc_value,
                                            sys.exc_traceback)])
                          )
        sys.stderr = open('error.log', 'w+')
        while self.do_processing(): pass
        syslog.syslog('ManagementLogic exited. pid=%d, status=%d.' % os.wait())
        self.clean_pidfile()
        syslog.closelog()


if __name__ == '__main__':
    controller = FirewallController()
    controller.run()
