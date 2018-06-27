import paramiko
from paramiko import SSHClient
import os


class SSHConnection:
    """
    SSHConnection hides the complexity of sending commands to the microVM
    via ssh.

    This class should be instantiated as part of the ssh fixture with the
    the hostname obtained from the MAC address, the username for logging into
    the image and the path of the ssh key.

    The ssh config dictionary contains the following fields:
    * hostname
    * username
    * ssh_key_path

    This translates in a ssh connection as follows:
    ssh -i ssh_key_path username@hostname
    """

    def __init__(self, ssh_config):
        self.ssh_client = SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        assert (os.path.exists(ssh_config['ssh_key_path']))
        self.ssh_client.connect(
            ssh_config['hostname'],
            look_for_keys=False,
            username=ssh_config['username'],
            key_filename=ssh_config['ssh_key_path']
        )

    def execute_command(self, cmd_string):
        """Executes the command passed as a string in the ssh context"""
        return self.ssh_client.exec_command(cmd_string)

    def close(self):
        """Closes the SSH connection"""
        self.ssh_client.close()
