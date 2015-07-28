#!/usr/bin/env python3.4

import os, subprocess, time, sys;

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
