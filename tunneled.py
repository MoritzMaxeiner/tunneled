#!/usr/bin/env python3.4

import os, json, subprocess, enum, sys, pwd, time, argparse;

import FileLock;

def drop_sudo_to_suid():
	try:
		pwdEntry = pwd.getpwnam(os.environ['SUDO_USER']);
	except KeyError:
		sys.exit('Sudo user not found in password database');
	# Drop real, effective, and saved group id
	os.setresgid(pwdEntry.pw_gid, pwdEntry.pw_gid, pwdEntry.pw_gid);
	if os.getresgid() != (pwdEntry.pw_gid, pwdEntry.pw_gid, pwdEntry.pw_gid):
		sys.exit('Could not properly drop group id');
	# Drop real, keep effective, and ensure saved equals effective group id
	(_, euid, _) = os.getresuid();
	os.setresuid(pwdEntry.pw_uid, euid, euid);
	if os.getresuid() != (pwdEntry.pw_uid, euid, euid):
		sys.exit('Could not properly drop user id');

# Drop from full root (precondition) down to what would be the permissions
# if interpreter had been executed as uid:gid with "set user ID upon execution"
# access rights flag set and had been owned by root.
ConnectionState = enum.Enum('ConnectionState', 'Up Down')

def _OpenRC_isState(vpn, state):
	return subprocess.call(["/sbin/rc-service", vpn, "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == (0 if state == ConnectionState.Up else 3);

def _OpenRC_changeState(vpn, newState, blocking = False):
	if subprocess.call(['/sbin/rc-service', vpn, ('start' if newState == ConnectionState.Up else 'stop')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != (1 if newState == ConnectionState.Up else 0):
		raise Exception('Could not change VPN status');
	while blocking:
		time.sleep(0.1);
		if _OpenRC_isState(vpn, newState):
			break;

_OpenRC = {'isState' : _OpenRC_isState,
           'changeState' : _OpenRC_changeState};

VPNControllers = {'OpenRC': _OpenRC}

class VPNConnection:
	def __init__(self, name, controller = _OpenRC):
		self.name = name;
		self.controller = controller;

	def __enter__(self):
		self.acquire();
		return True;

	def __exit__(self, exception_type, exception_val, trace):
		self.release();
		return True;

	def acquire(self, blocking = True):
		self.__acquireOrRelease(True, blocking, controller = self.controller);

	def release(self, blocking = True):
		self.__acquireOrRelease(False, blocking, controller = self.controller);

	def __acquireOrRelease(self, acquire, blocking, controller):
		with FileLock.FileLock('/tmp/.tunneled-lock'):
			(ruid, euid, suid) = os.getresuid();

			try:
				with open('/tmp/.tunneled-state', 'r') as stateFile:
					state = json.load(stateFile);
			except FileNotFoundError:
				state = {self.name: {'useCount': 0}};

			# Drop effective user id to have the state file belong to real UID
			os.setresuid(ruid, ruid, suid);

			state[self.name]['useCount'] += (1 if acquire else -1);
			with open('/tmp/.tunneled-state', 'w') as stateFile:
				json.dump(state, stateFile);

			# Restore effective user id
			os.setresuid(ruid, euid, suid);

			# Elevate real to effective user id
			# Seems to be required for direct VPN actions
			os.setresuid(euid, euid, suid);

			# Start VPN if needed
			if acquire and controller['isState'](self.name, ConnectionState.Down):
				controller['changeState'](self.name, ConnectionState.Up, blocking);
			elif not acquire and controller['isState'](self.name, ConnectionState.Up) and state[self.name]['useCount'] <= 0:
				controller['changeState'](self.name, ConnectionState.Down, blocking);

			# Restore real, effective, and saved user id
			os.setresuid(ruid, euid, suid);

			# Lose state before releasing lock
			state = None;

def main():
	if "SUDO_USER" in os.environ.keys():
		drop_sudo_to_suid();

	try:
		argument_split = sys.argv.index('--');
		app_argv = sys.argv[argument_split + 1 :];
		sys.argv = sys.argv[: argument_split];
	except ValueError:
		app_argv = [];

	parser = argparse.ArgumentParser(description = "Tunnel a program's network traffic over VPN", usage="%(prog)s [options] program vpn-controller vpn [-- [program options]]");
	parser.add_argument('program', help='program to tunnel');
	parser.add_argument('vpn_controller', help="subsystem in control of VPN, e.g. 'OpenRC'");
	parser.add_argument('vpn', help='vpn connection to tunnel over');

	args = parser.parse_args();

	with VPNConnection(args.vpn, controller = VPNControllers[args.vpn_controller]):
		# Create child process to be turned into chromium
		pid = os.fork();

		if(pid != 0):
			# Sleep until child-turned-chromium exits
			os.waitid(os.P_PID, pid, os.WEXITED);
		else:
			# Drop effective and saved to real user id
			# (Permanently drop all privileges)
			os.setuid(os.getuid());

			# Force Application into VPN-only control group
			with open('/sys/fs/cgroup/net_cls/' + args.vpn + '/tasks', 'w') as tasks:
				tasks.write(str(os.getpid()));

			os.execvp(args.program, [args.program] + app_argv);

if __name__ == '__main__':
	main();
