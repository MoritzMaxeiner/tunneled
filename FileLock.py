#!/usr/bin/env python3.4

import os, subprocess, time, sys;

class FileLock:

	def acquire(self, blocking=True, timeout=-1):
		if timeout < -1:
			raise ValueError('timeout value must be strictly positive');
		timeout = int(timeout);
		while True:
			try:
				self.atomicFile = open(self.fileName, 'x');
				return True;
			except FileExistsError:
				if not blocking or timeout == 0:
					self.atomicFile = None;
					return False;
				timeBeforeWait = time.time();
				subprocess.call(['inotifywait', '--event', 'delete_self', '--quiet', '--quiet', '--timeout', str(timeout), self.fileName]);
				if timeout > 0:
					timeout = int(max(0, timeout - abs(time.time() - timeBeforeWait)));

	def release(self):
		try:
			if self.atomicFile:
				self.atomicFile.close();
			os.remove(self.fileName);
			self.atomicFile = None;
		except OSError:
			tb = sys.exc_info()[2];
			raise RuntimeError('Could not release FileLock "' + self.fileName + '"').with_traceback(tb);

	def __init__(self, fileName):
		self.fileName = fileName;
		self.atomicFile = None;

	def __del__(self):
		try:
			if self.atomicFile:
				self.atomicFile.close();
			os.remove(self.fileName);
			self.atomicFile = None;
		except FileNotFoundError:
			return;
		except OSError:
			tb = sys.exc_info()[2];
			raise RuntimeError('Could not release FileLock "' + self.fileName + '"').with_traceback(tb);

	def __enter__(self):
		return self.acquire();

	def __exit__(self, exception_type, exception_val, trace):
		self.release();
		return True;
