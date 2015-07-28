#!/usr/bin/env python3.4

import os, json, subprocess, enum, sys, pwd, time, argparse, signal;

import butter.inotify as inotify;

class FileLock:

	def acquire(self, blocking=True, timeout=-1):
		if timeout < -1:
			raise ValueError('timeout value must be strictly positive');
		timeout = int(timeout);
		while True:
			try:
				self.atomic_file = open(self.filename, 'x');
				return True;
			except FileExistsError:
				if not blocking or timeout == 0:
					self.atomic_file = None;
					return False;
				time_before_wait = time.time();
				inotify = inotify.Inotify();
				try:
					wd = inotify.watch(self.filename, inotify.IN_DELETE_SELF);
					inotify.wait(timeout=(timeout if timeout >= 0 else None));
				except TimeoutError:
					pass;
				finally:
					inotify.close();
				if timeout > 0:
					timeout = int(max(0, timeout - abs(time.time() - time_before_wait)));

	def release(self):
		try:
			if self.atomic_file:
				self.atomic_file.close();
			os.remove(self.filename);
			self.atomic_file = None;
		except OSError:
			tb = sys.exc_info()[2];
			raise RuntimeError('Could not release FileLock "' + self.filename + '"').with_traceback(tb);

	def __init__(self, filename):
		self.filename = filename;
		self.atomic_file = None;

	def __del__(self):
		try:
			if self.atomic_file:
				self.atomic_file.close();
			os.remove(self.filename);
			self.atomic_file = None;
		except FileNotFoundError:
			return;
		except OSError:
			tb = sys.exc_info()[2];
			raise RuntimeError('Could not release FileLock "' + self.filename + '"').with_traceback(tb);

	def __enter__(self):
		return self.acquire();

	def __exit__(self, exception_type, exception_val, trace):
		self.release();
		return True;

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
		with FileLock(self.lock):
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

