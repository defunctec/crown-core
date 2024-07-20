#!/usr/bin/env python3

import configparser
import argparse
import json
import os
import shutil
import subprocess
import time
import math


def create_dir(dirname):
    dirname = os.path.expanduser(dirname)
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def delete_dir(dirname):
    dirname = os.path.expanduser(dirname)
    if os.path.exists(dirname):
        shutil.rmtree(dirname)


def parse_json(fp):
    try:
        return json.load(fp)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Error parsing JSON: {e}")


def parse_nodeconfig(fp):
    config = {}
    for line in fp.readlines():
        lex = [l for l in line.split(' ') if len(l) > 0]
        if lex[0][0] == '#':
            continue

        if len(lex) < 5:
            continue

        alias, ip, key = tuple(lex[0:3])
        tx = (lex[3], int(lex[4]))
        config[alias] = {'ip': ip, 'key': key, 'tx': tx}

    return config


def write_nodeconfig(fp, nodeconfig):
    def line(als, n):
        return ' '.join([als, n['ip'], n['key'], n['tx'][0], str(n['tx'][1])]) + '\n'

    fp.writelines(
        [line(alias, node) for alias, node in nodeconfig.items()] # Changed iteritems() to items() for python3 update
    )


def tx_find_output(tx, amount):
    vouts = tx['vout']
    for i in range(0, len(vouts)):
        vout = vouts[i]
        if vout['value'] == amount:
            return vout['n']


class Config:
    class _FakeSecHead(object):
        def __init__(self, fp):
            self.fp = fp
            self.sechead = '[_dummy]\n'

        def readline(self):
            if self.sechead:
                try:
                    return self.sechead
                finally:
                    self.sechead = None
            else:
                return self.fp.readline()

    def __init__(self, fp):
        self.options = {}
        self.fp = None
        self.open(fp)

    def set_option(self, key, value):
        if key in self.multioptions():
            if key in self.options:
                self.options[key].add(value)
            else:
                self.options[key] = {value}
        else:
            self.options[key] = value

    def get_option(self, key):
        if key not in self.options:
            return None
        return self.options[key]

    def dump(self):
        self.fp.seek(0)
        for key, value in self.options.items():
            if key in self.multioptions():
                for v in value:
                    self.fp.writelines('{0}={1}\n'.format(key, v))
            else:
                self.fp.writelines('{0}={1}\n'.format(key, value))
        self.reset()

    def reset(self):
        self.options = {}
        self.fp = None

    def open(self, fp):
        config = configparser.configparser()
        config.readfp(self._FakeSecHead(fp))
        for key in config.options('_dummy'):
            value = config.get('_dummy', key)
            self.set_option(key, value)
        self.fp = fp

    @staticmethod
    def multioptions():
        return ['addnode']


def set_default(dic, key, default):
    if key not in dic:
        dic[key] = default


class Sandbox:
    def __init__(self, bindir, targetdir, config_file, port_base=42000):
        self.targetdir = os.path.expanduser(targetdir)
        self.bindir = '' if bindir is None else os.path.expanduser(bindir)
        self.network = parse_json(config_file)
        self.port_base = port_base

        port = self.port_base
        for name, node in self.network['nodes'].items():
            set_default(node, 'generate', False)
            set_default(node, 'addnodes', [])
            set_default(node, 'masternodes', [])
            set_default(node, 'mnconfig', {})

            node['masternodes'] = [{"node": mn} for mn in node['masternodes']]

            port += 1
            node['port'] = port

            self.read_mnconfig(name)

    def read_mnconfig(self, node):
        filename = self.mnconfig_filename(node)
        if not os.path.exists(filename):
            return
        config = parse_nodeconfig(open(filename))
        self.network['nodes'][node]['mnconfig'] = config

    def write_mnconfig(self, node):
        filename = self.mnconfig_filename(node)
        write_nodeconfig(open(filename, "w+"), self.network['nodes'][node]['mnconfig'])

    def mnconfig_filename(self, node):
        filename = 'devnet-{0}/masternode.conf'.format(self.network['devnet']['name'])
        return os.path.join(self.data_directory(node), filename)

    def prepare(self):
        delete_dir(self.targetdir)
        create_dir(self.targetdir)

        for name, node in self.network['nodes'].items():
            create_dir(os.path.join(self.targetdir, name))
            self.write_config(name)

    def start_nodes(self, nodes=None, binary='crownd'):
        if nodes is None:
            nodes = []
        nodes = nodes if nodes != [] else self.network['nodes'].iterkeys()
        for name in nodes:
            self.start_node(name, binary)

    def start_node(self, node, binary='crownd'):
        execute = os.path.join(self.bindir, binary)
        return self.unchecked_call(
            [execute, '-datadir=' + self.data_directory(node), '-daemon']
        )

    @staticmethod
    def check_call(arguments):
        p = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        retcode = p.returncode
        if retcode == 1:
            cmd = arguments[0]
            raise subprocess.CalledProcessError(retcode, cmd, err)
        return out, err

    @staticmethod
    def unchecked_call(*args):
        return subprocess.call(*args)

    def write_config(self, node):
        config = Config(open(self.config_filename(node), "w+"))
        for key, value in self.config_for_node(node):
            config.set_option(key, value)
        config.dump()

    def config_for_node(self, name):
        config = set()

        node = self.network['nodes'][name]

        if 'mnprivkey' in node:
            config.add(('masternode', 1))
            config.add(('masternodeprivkey', node['mnprivkey']))
            config.add(('externalip',self.node_ip(name)))

        config.add(('port', self.node_port(name)))
        config.add(('rpcport', self.node_rpc_port(name)))
        config.add(('devnet', self.network['devnet']['name']))

        if node['generate']:
            config.add(('gen', ''))
            config.add(('genproclimit', 1))

        for peer in node['addnodes']:
            config.add(('addnode', self.node_ip(peer)))

        for seed_name in self.network['nodes']:
            if seed_name != name:
                config.add(('addnode', self.node_ip(seed_name)))

        config.add(('rpcpassword', 'bogus'))

        return config

    def node_port(self, name):
        return self.network['nodes'][name]['port']

    def node_ip(self, peer):
        return '127.0.0.1:' + str(self.node_port(peer))

    def config_filename(self, node):
        return os.path.join(self.data_directory(node), 'crown.conf')

    def data_directory(self, node):
        if node not in self.network['nodes']:
            raise RuntimeError("No such node: {0}".format(node))

        return os.path.join(self.targetdir, node)

    def node_rpc_port(self, name):
        return self.node_port(name) + 1000

    def masternodes(self, node):
        all_nodes = [x for x in self.network['nodes'].iterkeys()]
        mnlist = self.network['nodes'][node]['masternodes']
        mnnames = [mn['node'] for mn in mnlist]

        return [node for node in mnnames if node in all_nodes]

    def check_balance(self, node, binary='crown-cli'):
        out, err = self.client_command(node, binary, 'getbalance')
        if len(err) != 0:
            return 0

        return float(out)

    def gen_address(self, node, binary='crown-cli'):
        out, err = self.client_command(node, binary, 'getnewaddress')
        assert (len(err) == 0)

        return out

    def client_command(self, node, binary, *args):
        execute = os.path.join(self.bindir, binary)
        try:
            return self.check_call(
                [execute, '-datadir=' + self.data_directory(node)] + list(args)
            )
        except:
            print(node, ": ", list(args))
            raise

    def send_all(self, node_from, node_to):
        balance = self.check_balance(node_from)
        if balance > 0:
            self.client_command(node_from, 'crown-cli', 'settxfee', str(0))
            self.send(node_from, self.gen_address(node_to), balance)

    def send(self, node, addr, amount, binary='crown-cli'):
        out, err = self.client_command(node, binary, 'sendtoaddress', addr, str(amount))
        if len(err) != 0:
            print(err)
        assert (len(err) == 0)
        return out.strip()

    def get_transaction(self, node, txhash, binary='crown-cli'):

        """
        Retrieve the transaction details for a given transaction hash.

        Args:
            node (str): The node from which to get the transaction.
            txhash (str): The transaction hash.
            binary (str): The binary to use for the command (default: 'crown-cli').

        Returns:
            dict: The transaction details in JSON format.

        Raises:
            AssertionError: If there is an error in retrieving the transaction.
        """
        tx, err = self.client_command(node, binary, 'getrawtransaction', txhash, '1')
        if len(err) != 0:
            print(err)
        assert (len(err) == 0)
        return json.loads(tx)

    def create_key(self, node, binary='crown-cli'):
        """
        Create a new key for a masternode.

        Args:
            node (str): The node for which to create the key.
            binary (str): The binary to use for the command (default: 'crown-cli').

        Returns:
            str: The newly created key.

        Raises:
            AssertionError: If there is an error in creating the key.
        """
        out, err = self.client_command(node, binary, 'node', 'genkey')
        assert (len(err) == 0)
        return out.strip()

    def next_masternode_to_setup(self):
        """
        Determine the next masternode to set up.

        Returns:
            tuple: The masternode and its controller, or (None, None) if all masternodes are set up.
        """
        def is_setup(masternode, name):
            if 'mnconfig' not in self.network['nodes'][name]:
                return False

            for alias, nodecfg in self.network['nodes'][name]['mnconfig'].items():
                if nodecfg['ip'] == self.node_ip(masternode):
                    return True
            return False

        mnodes = [(mn, controller)
                  for controller in self.masternode_controllers()
                  for mn in self.masternodes(controller)
                  if not is_setup(mn, controller)
                  ]
        if mnodes:
            return mnodes[0]
        else:
            return None, None

    def setup_masternode(self, control_node, masternode):
        """
        Set up a masternode by generating a new key, sending the collateral transaction, 
        waiting for confirmations, and then starting the masternode.

        Args:
            control_node (str): The node that controls the masternode setup.
            masternode (str): The masternode to be set up.

        Raises:
            RuntimeError: If any step in the process fails.
        """
        try:
            # Generate a new private key for the masternode
            prvkey = self.create_key(control_node)
            
            # Send the collateral transaction and get the transaction hash
            txhash = self.send(control_node, self.gen_address(control_node), 10000)
            colltx = self.get_transaction(control_node, txhash)
            
            # Find the collateral output
            claddr = tx_find_output(colltx, 10000)

            print(f'colltx hash: {txhash}')

            # Store the masternode configuration
            self.network['nodes'][control_node]['mnconfig'][masternode] = {
                'ip': self.node_ip(masternode),
                'key': prvkey,
                'tx': (txhash, claddr)
            }
            self.network['nodes'][masternode]['mnprivkey'] = prvkey

            # Wait for the transaction to get enough confirmations
            while 'confirmations' not in colltx or colltx['confirmations'] < 15:
                print(f"{colltx['confirmations'] if 'confirmations' in colltx else 0} confirmations, waiting")
                time.sleep(2)
                colltx = self.get_transaction(control_node, txhash)

            print(f"{colltx['confirmations']} confirmations, done")

            # Stop the control node and write the masternode configuration
            self.stop_node(control_node)
            time.sleep(1)
            self.write_mnconfig(control_node)
            self.start_node(control_node)

            # Stop the masternode and write its configuration
            self.stop_node(masternode)
            time.sleep(1)
            self.write_config(masternode)
            self.start_node(masternode)

            # Give the nodes some time to start
            time.sleep(1)
            
            # Start the masternode and capture the output and error
            out, err = self.start_masternode(control_node, masternode)
            print(err)
            print(out)

        except Exception as e:
            print(f"Error setting up masternode: {e}")
            raise RuntimeError(f"Failed to set up masternode {masternode} controlled by {control_node}")

    def stop_nodes(self, nodes=None):
        """
        Stops the specified nodes or all nodes if none are specified.

        Args:
            nodes (list, optional): List of node names to stop. If None, stops all nodes.

        Raises:
            RuntimeError: If there is an error stopping a node.
            Exception: If an unexpected error occurs.
        """
        if nodes is None:
            nodes = []

        # If nodes list is empty, stop all nodes
        nodes = nodes if nodes != [] else list(self.network['nodes'].keys())

        for name in nodes:
            try:
                self.stop_node(name)
                print(f"Successfully stopped node {name}")
            except RuntimeError as e:
                print(f"Error stopping node {name}: {e}")
            except Exception as e:
                print(f"Unexpected error stopping node {name}: {e}")

    def stop_node(self, node):
        """
        Stops a specific node using the crown-cli stop command.

        Args:
            node (str): The name of the node to stop.

        Returns:
            str: The output from the crown-cli stop command.

        Raises:
            RuntimeError: If the crown-cli stop command fails.
            Exception: If an unexpected error occurs.
        """
        try:
            # Attempt to stop the node using crown-cli stop command
            return self.client_command(node, 'crown-cli', 'stop')
        except subprocess.CalledProcessError as e:
            # Handle known error during command execution
            raise RuntimeError(f"Failed to stop node {node}: {e.output}")
        except Exception as e:
            # Handle any unexpected error
            raise RuntimeError(f"Unexpected error stopping node {node}: {e}")

    def miners(self):
        """
        Retrieve the list of nodes that are miners.

        Returns:
            list: A list of node names that are miners.
        """
        return [k for k, v in self.network['nodes'].items() if v['generate']]

    def masternode_controllers(self):
        """
        Retrieve the list of nodes that control masternodes.

        Returns:
            list: A list of node names that control masternodes.
        """
        return [k for k, v in self.network['nodes'].items() if v['masternodes'] != []]

    def start_masternode(self, control_node, masternode):
        """
        Start a masternode using the crown-cli command.

        Args:
            control_node (str): The node that controls the masternode setup.
            masternode (str): The masternode to be started.

        Returns:
            str: The output from the crown-cli command to start the masternode.
        """
        return self.client_command(control_node, 'crown-cli', 'masternode', 'start-alias', masternode)

    def gen_or_reuse_address(self, node):
        """
        Generate a new address or reuse an existing one for a given node.

        Args:
            node (str): The node for which to generate or reuse an address.

        Returns:
            str: The generated or reused address.
        """
        if 'receive_with' in self.network['nodes'][node]:
            return self.network['nodes'][node]['receive_with']

        self.network['nodes'][node]['receive_with'] = self.gen_address(node)
        return self.network['nodes'][node]['receive_with']

    def get_block_height(self, node):
        """
        Get the current block height of a given node.

        Args:
            node (str): The node from which to get the block height.

        Returns:
            int: The current block height.
        """
        try:
            out, err = self.client_command(node, 'crown-cli', 'getinfo')
            info = json.loads(out)
            return int(info['blocks'])
        except ValueError:
            return 0


def prepare(json_desc_file, target_dir, bin_dir):
    """
    Prepares the sandbox environment by reading the JSON description file and setting up directories.

    Args:
        json_desc_file (str): Path to the JSON description file.
        target_dir (str): Target directory for the simulation.
        bin_dir (str): Directory containing the binaries.
    """
    sb = Sandbox(bin_dir, target_dir, open(json_desc_file))
    sb.prepare()


def start(json_desc_file, target_dir, bin_dir, nodes):
    """
    Starts the specified nodes in the sandbox environment.

    Args:
        json_desc_file (str): Path to the JSON description file.
        target_dir (str): Target directory for the simulation.
        bin_dir (str): Directory containing the binaries.
        nodes (list): List of nodes to start.
    """
    sb = Sandbox(bin_dir, target_dir, open(json_desc_file))
    sb.start_nodes(nodes)


def stop(json_desc_file, target_dir, bin_dir, nodes):
    """
    Stops the specified nodes in the sandbox environment.

    Args:
        json_desc_file (str): Path to the JSON description file.
        target_dir (str): Target directory for the simulation.
        bin_dir (str): Directory containing the binaries.
        nodes (list): List of nodes to stop.
    """
    sb = Sandbox(bin_dir, target_dir, open(json_desc_file))
    sb.stop_nodes(nodes)


def command(json_desc_file, target_dir, bin_dir, node, *args):
    """
    Executes a command on a specified node or on all nodes in the sandbox environment.

    Args:
        json_desc_file (str): Path to the JSON description file.
        target_dir (str): Target directory for the simulation.
        bin_dir (str): Directory containing the binaries.
        node (str): Node on which to execute the command.
        *args: Additional command arguments.
    """
    sb = Sandbox(bin_dir, target_dir, open(json_desc_file))
    if node == '_':
        for node in sb.network['nodes']:
            try:
                sb.client_command(node, 'crown-cli', *args)
            except subprocess.CalledProcessError as ex:
                print(ex.output)
                print('error running on ', node, ': ', ex)
            except Exception as ex:
                print('error running on ', node, ': ', ex)
    else:
        out, err = sb.client_command(node, 'crown-cli', *args)
        print(out)
        if len(err.strip()) > 0:
            print(err)


def run_simulation(json_desc_file, target_dir, bin_dir):
    """
    Runs a simulation for setting up and managing masternodes based on the given JSON description file.

    Args:
        json_desc_file (str): Path to the JSON description file.
        target_dir (str): Target directory for the simulation.
        bin_dir (str): Directory containing the binaries.

    Raises:
        RuntimeError: If any step in the process fails.
    """
    sb = Sandbox(bin_dir, target_dir, open(json_desc_file))

    while True:
        try:
            # Iterate through all miner nodes to distribute funds
            for node in sb.miners():
                if 'send_to' not in sb.network['nodes'][node]:
                    continue
                balance = sb.check_balance(node)
                if balance > 1000:
                    # Sending almost all the balance to the target address to avoid tx fee issues
                    to = sb.network['nodes'][node]['send_to']
                    amount = int(math.floor(balance / 1000.0)) * 1000
                    print(f'Sending {amount} to {to}')

                    try:
                        sb.send(node, sb.gen_or_reuse_address(to), amount)
                        time.sleep(1)
                        print(f'{to} balance: {sb.check_balance(to)}')

                    except subprocess.CalledProcessError as ex:
                        print(f'Error while sending from node {node} to {to}: {ex.output}')

            # Setup the next masternode
            mn, node = sb.next_masternode_to_setup()
            if mn is not None:
                balance = sb.check_balance(node)
                if balance < 10001:
                    continue

                print(f'Setting up masternode {mn}')
                sb.setup_masternode(node, mn)

                # Wait for the blockchain to process blocks and get confirmations
                blockheight = sb.get_block_height(node)
                while blockheight == 0:
                    print('Cannot get block height. Retrying...')
                    time.sleep(2)
                    blockheight = sb.get_block_height(node)

                while True:
                    time.sleep(2)
                    if sb.get_block_height(node) > blockheight + 15:
                        break

                # Start the masternode and handle any errors
                try:
                    out, err = sb.start_masternode(node, mn)
                    print(err)
                    print(out)
                    print(f'Next masternode is {sb.next_masternode_to_setup()[0]}')
                except Exception as e:
                    print(f'Error starting masternode {mn} on node {node}: {e}')

        except RuntimeError as e:
            print(f'Runtime error: {e}')
            pass

        # Sleep for 2 seconds before the next iteration
        time.sleep(2)

if __name__ == '__main__':
    try:
        # Setup argument parser
        ap = argparse.ArgumentParser(description='Crown Sandbox control script')
        ap.add_argument(
            'command',
            nargs='+',
            action='store',
            help='Command to execute: ( prepare | start [NODES...] | cmd NODE [ARGUMENTS...] | sim)'
        )
        ap.add_argument('-b', '--bin-directory', action='store', help='Binaries custom directory')
        ap.add_argument('-d', '--directory', action='store', help='Root data directory for all nodes in the sandbox',
                        required=True)
        ap.add_argument('-f', '--file', action='store', help='Sandbox description file (json format)', required=True)
        parsed = ap.parse_args()

        # Determine which command to execute based on the parsed arguments
        if parsed.command[0] == 'prepare':
            prepare(parsed.file, parsed.directory, parsed.bin_directory)
        elif parsed.command[0] == 'start':
            start(parsed.file, parsed.directory, parsed.bin_directory, parsed.command[1:])
        elif parsed.command[0] == 'stop':
            stop(parsed.file, parsed.directory, parsed.bin_directory, parsed.command[1:])
        elif parsed.command[0] == 'cmd':
            command(parsed.file, parsed.directory, parsed.bin_directory, parsed.command[1], *parsed.command[2:])
        elif parsed.command[0] == 'sim':
            run_simulation(parsed.file, parsed.directory, parsed.bin_directory)
        else:
            ap.print_help()
    except subprocess.CalledProcessError as ex:
        # Handle errors from subprocess calls
        print("Subprocess error output:", ex.output)
        print("Subprocess error:", ex)
    except RuntimeError as ex:
        # Handle runtime errors
        print("Runtime error:", ex)
    except Exception as ex:
        # Handle any other exceptions
        print("An unexpected error occurred:", ex)
