
#define SHARED_NAME "/org.ucworks.tunneled"

#define _GNU_SOURCE

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <semaphore.h>
#include <sys/mman.h>

#include <stdio.h>
#include <string.h>

#include <sys/wait.h>

typedef struct
{
	pid_t process;
	uint8_t use_count;
} OpenVPNConnectionState;

typedef struct
{
	char* name;
	// State of the connection, shared between processes
	// by residing in shared memory
	OpenVPNConnectionState* state;
	// Semaphore providing mutual exclusion for accessing
	// the shared state
	sem_t* lock;
} OpenVPNConnection;

OpenVPNConnection* ovpn_new(char const * name)
{
	OpenVPNConnection* connection = (OpenVPNConnection*) calloc(1, sizeof(OpenVPNConnection));

	char* shared_name = NULL;
	asprintf(&shared_name, "%s.%s", SHARED_NAME, name);

	connection -> lock = sem_open(shared_name, O_CREAT, 0664, 1);
	if (connection -> lock == SEM_FAILED)
	{
		perror("Could not open named semaphore");
		free(shared_name);
		free(connection);
		return NULL;
	}

	// Ensure mutual exclusion before accessing shared memory
	sem_wait(connection -> lock);

	int shared_state = shm_open(shared_name, O_CREAT | O_RDWR, 0644);
	if (shared_state == -1)
	{
		perror("Could not open shared memory");
		sem_post(connection -> lock);
		sem_close(connection -> lock);
		free(shared_name);
		free(connection);
		return NULL;
	}

	struct stat shared_state_stat;
	if (fstat(shared_state, &shared_state_stat) == -1)
	{
		perror("Could not get file status of shared memory");
		close(shared_state);
		sem_post(connection -> lock);
		sem_close(connection -> lock);
		free(shared_name);
		free(connection);
		return NULL;
	}

	// Check whether the shared memory has yet to be grown to the required size
	if (shared_state_stat.st_size != sizeof(OpenVPNConnectionState))
	{
		// If not, try to grow it
		if (ftruncate(shared_state, sizeof(OpenVPNConnectionState)) == -1)
		{
			perror("Could not grow shared memory");
			close(shared_state);
			sem_post(connection -> lock);
			sem_close(connection -> lock);
			free(shared_name);
			free(connection);
			return NULL;
		}
	}

	connection -> state = mmap(NULL, sizeof(OpenVPNConnectionState), PROT_READ | PROT_WRITE, MAP_SHARED, shared_state, 0);
	if (connection -> state == MAP_FAILED)
	{
		perror("Could not map shared memory into process' virtual memory");
		close(shared_state);
		sem_post(connection -> lock);
		sem_close(connection -> lock);
		free(shared_name);
		free(connection);
		return NULL;
	}

	// File descriptor for share memory not needed after setting it up
	close(shared_state);

	// Finished initialising access to shared memory, relinquish mutual exclusion
	sem_post(connection -> lock);

	asprintf(&(connection -> name), "%s", name);
	return connection;
}

void ovpn_free(OpenVPNConnection** connection)
{
	sem_post((*connection) -> lock);
	if ((*connection) -> state -> use_count == 0)
	{
		char* shared_name = NULL;
		asprintf(&shared_name, "%s.%s", SHARED_NAME, (*connection) -> name);
		shm_unlink(shared_name);
		free(shared_name);
	}
	munmap((*connection) -> state, sizeof(OpenVPNConnectionState));
	sem_close((*connection) -> lock);
	free((*connection) -> name);
	free((*connection));

	(*connection) = NULL;
}

bool ovpn_acquire(OpenVPNConnection* connection)
{
	sem_wait(connection -> lock);

	connection -> state -> use_count += 1;

	printf("PID: %d, Use count: %d\n", connection -> state -> process, connection -> state -> use_count);

	// TODO: Implement starting of OpenVPN

	sem_post(connection -> lock);

	return true;
}

bool ovpn_release(OpenVPNConnection* connection)
{
	sem_wait(connection -> lock);

	if (connection -> state -> use_count > 0) connection -> state -> use_count -= 1;

	printf("PID: %d, Use count: %d\n", connection -> state -> process, connection -> state -> use_count);

	// TODO: Implement stopping of OpenVPN

	sem_post(connection -> lock);

	return true;
}

void drop_sudo_to_suid()
{
	
}

int main(int argc, char* argv[])
{
	if (getenv("SUDO_USER") != NULL) drop_sudo_to_suid();

	uid_t ruid, euid, suid;
	getresuid(&ruid, &euid, &suid);
	if (!(euid == 0 && suid == 0))
	{
		fprintf(stderr, "tunneled must be run as root\n");
		return 1;
	}

	int program_argc = 1;
	if (argc >= 4 && strcmp(argv[3], "--") == 0) program_argc += argc - 4;

	char** program_argv = (char**) calloc(program_argc + 1, sizeof(char*));
	program_argv[0] = argv[1];
	if (program_argc > 1) memcpy(&program_argv[1], &argv[4], (program_argc - 1) * sizeof(char*));

	OpenVPNConnection* connection = ovpn_new(argv[2]);
	ovpn_acquire(connection);

	// Create child process to exec the designated program
	pid_t pid = fork();

	if(pid != 0)
	{
		// Sleep until child exits
		siginfo_t child_info;
		waitid(P_PID, pid, &child_info, WEXITED);

		ovpn_release(connection);
		ovpn_free(&connection);
	}
	else
	{
		// Drop effective and saved to real user id
		// (Permanently drop all privileged)
		setuid(ruid);

		// Force application into VPN-only control group
		char* task_file_name;
		asprintf(&task_file_name, "/sys/fs/cgroup/net_cls/tunneled/%s/tasks", argv[2]);

		FILE* task_file = fopen(task_file_name, "a");
		fprintf(task_file, "%d\n", getpid());
		fclose(task_file);

		free(task_file_name);

		// Execute application
		execvp(program_argv[0], program_argv);
	}

	return 0;
}
