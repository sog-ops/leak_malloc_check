#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <execinfo.h>
#include <pthread.h>

typedef void *(*malloc_t)(size_t size);
typedef void (*free_t)(void *ptr);
#define MEM_DIR "./mem"

static malloc_t malloc_f;
static free_t free_f;

// malloc 和 free 不同时检测
static pthread_mutex_t malloc_mutex;
static pthread_mutex_t free_mutex;
static pthread_t malloc_tid = 0;
static pthread_t free_tid = 0;

static inline void print_stacktrace(int fd)
{
	void *array[10];
	size_t size;

	size = backtrace(array, 10);
	backtrace_symbols_fd(array, size, fd);
}

void init_mem_hook()
{
	if (malloc_f == NULL)
	{
		malloc_f = (malloc_t)dlsym(RTLD_NEXT, "malloc");
	}

	if (free_f == NULL)
	{
		free_f = (free_t)dlsym(RTLD_NEXT, "free");
	}
	if (access(MEM_DIR, F_OK) != 0)
	{
		mkdir(MEM_DIR, 0775);
	}

	malloc_tid = 0;
	free_tid = 0;

	pthread_mutex_init(&malloc_mutex, NULL);
	pthread_mutex_init(&free_mutex, NULL);
}

void *malloc(size_t size)
{
	static int mallac_enable_hook = 1;
	char fileName[32] = {0};
	char buf[128] = {0};
	pthread_t tid = pthread_self();
	void *ptr = malloc_f(size);

	if (free_tid == 0 && (malloc_tid == 0 || malloc_tid != tid)) // 多线程，不同线程可以，需要记录
	{
		pthread_mutex_lock(&malloc_mutex);
		malloc_tid = tid;

		/* blow */
		sprintf(fileName, MEM_DIR "/%p.mem", ptr);
		int fd = open(fileName, O_CREAT | O_RDWR, 0664);
		void *caller = __builtin_return_address(0);
		sprintf(buf, "[caller %p] --> addr %p,szie %ld\n\n", caller, ptr, size);
		write(fd, buf, strlen(buf));
		print_stacktrace(fd);
		fsync(fd);
		close(fd);
		//printf("create %p\n", ptr);

		malloc_tid = 0;
		pthread_mutex_unlock(&malloc_mutex);
	}

	return ptr;
}

void free(void *ptr)
{
	static int free_enable_hook = 1;
	char fileName[32] = {0};
	free_f(ptr);
	pthread_t tid = pthread_self();

	if (malloc_tid == 0 && (free_tid == 0 || free_tid != tid))
	{
		pthread_mutex_lock(&free_mutex);
		free_tid = tid;

		/* blow */
		sprintf(fileName, MEM_DIR "/%p.mem", ptr);
		if (unlink(fileName) < 0)
		{
			void *caller = __builtin_return_address(0);
			printf("double free, caller %p addr -> %p\n", caller, ptr);
			print_stacktrace(STDOUT_FILENO);
		}


		free_tid = 0;
		pthread_mutex_unlock(&free_mutex);
	}
}

int main()
{
	init_mem_hook();

	void *p1 = malloc(10);
	printf("p1 %p\n", p1);
	void *p2 = malloc(20);
	printf("p2 %p\n", p2);
	void *p3 = malloc(30);
	printf("p3 %p\n", p3);

	free(p1);
	free(p2);
	free(p3);
	return 0;
}