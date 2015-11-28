
#define SHARED_NAME "/org.ucworks.tunneled"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <semaphore.h>
#include <sys/mman.h>

#include <stdio.h>

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

	sem_post(connection -> lock);

	return true;
}

bool ovpn_release(OpenVPNConnection* connection)
{
	sem_wait(connection -> lock);

	if (connection -> state -> use_count > 0) connection -> state -> use_count -= 1;

	printf("PID: %d, Use count: %d\n", connection -> state -> process, connection -> state -> use_count);

	sem_post(connection -> lock);

	return true;
}

int main(int argc, char* argv[])
{
	OpenVPNConnection* connection = ovpn_new("openvpn.us-east@hide.me");

	ovpn_acquire(connection); usleep(2 * 1000 * 1000); ovpn_release(connection);
	ovpn_acquire(connection); usleep(2 * 1000 * 1000); ovpn_release(connection);
	ovpn_acquire(connection); usleep(2 * 1000 * 1000); ovpn_release(connection);

	ovpn_free(&connection);

	return 0;
}
