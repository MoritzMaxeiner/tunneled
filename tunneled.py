#!/usr/bin/env python3.4

import os, json, subprocess, enum, sys, pwd, time, argparse, signal;

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

class OpenVPNConnection:
	def __init__(self, name, state='/tmp/.tunneled-state', lock='/tmp/.tunneled-lock'):
		self.name = name;
		self.state = state;
		self.lock = lock;

	def __enter__(self):
		self.acquire();
		return True;

	def __exit__(self, exception_type, exception_val, trace):
		self.release();
		return True;

	def acquire(self):
		self.__acquireOrRelease(True);

	def release(self):
		self.__acquireOrRelease(False);

	def __acquireOrRelease(self, acquire):
		with FileLock.FileLock(self.lock):
			(ruid, euid, suid) = os.getresuid();

			try:
				with open(self.state, 'r') as state_file:
					state = json.load(state_file);
			except FileNotFoundError:
				state = {self.name: {'pid': None, 'use_count': 0}};

			# Elevate real to stored effective user id
			# Seems to be required for direct VPN actions
			os.setresuid(euid, euid, suid);

			# Start/Stop OpenVPN
			if acquire and not state[self.name]['pid']:
				openvpn_process = subprocess.Popen(['/usr/sbin/openvpn', os.environ['HOME'] + '/.tunneled/' + self.name.replace('.', '/', 1) + '.conf'],
					stdout=subprocess.DEVNULL,
					stderr=subprocess.DEVNULL,
					start_new_session=True
#					preexec_fn=os.setpgrp
					);
				state[self.name]['pid'] = openvpn_process.pid;
			elif not acquire and state[self.name]['pid'] and state[self.name]['use_count'] == 1:
				os.kill(state[self.name]['pid'], signal.SIGTERM);
				state[self.name]['pid'] = None;

			# Drop real and effective to stored real user id
			os.setresuid(ruid, ruid, suid);

			state[self.name]['use_count'] += (1 if acquire else -1);
			with open(self.state, 'w') as state_file:
				json.dump(state, state_file);

			# Restore real, effective, and saved user id to stored values
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

	parser = argparse.ArgumentParser(description = "Tunnel a program's network traffic over VPN", usage="%(prog)s [options] program vpn [-- [program options]]");
	parser.add_argument('program', help='program to tunnel');
	parser.add_argument('vpn', help='vpn connection to tunnel over');

	args = parser.parse_args();

	# Create child process to be turned into designated programm
	pid = os.fork();

	if(pid != 0):
		with OpenVPNConnection(args.vpn):
			# Sleep until child exits
			os.waitid(os.P_PID, pid, os.WEXITED);
	else:
		# Drop effective and saved to real user id
		# (Permanently drop all privileges)
		os.setuid(os.getuid());

		# Force Application into VPN-only control group
		with open('/sys/fs/cgroup/net_cls/tunneled/' + args.vpn + '/tasks', 'w') as tasks:
			tasks.write(str(os.getpid()));

		os.execvp(args.program, [args.program] + app_argv);

if __name__ == '__main__':
	main();
